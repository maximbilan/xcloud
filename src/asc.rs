use std::{
    env,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use crate::util::{is_branch_git_ref, resource_id};

#[derive(Debug, Clone)]
pub struct Config {
    pub issuer_id: String,
    pub key_id: String,
    pub p8_private_key_pem: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let issuer_id = env::var("XCLOUD_ISSUER")
            .context("Missing env XCLOUD_ISSUER (App Store Connect Issuer ID)")?;
        let key_id = env::var("XCLOUD_KEY_ID")
            .context("Missing env XCLOUD_KEY_ID (App Store Connect API Key ID)")?;
        let p8_private_key_pem =
            env::var("XCLOUD_P8").context("Missing env XCLOUD_P8 (contents of .p8 private key)")?;

        Ok(Self {
            issuer_id,
            key_id,
            p8_private_key_pem,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    exp: usize,
    aud: String,
    iat: usize,
}

pub struct AppStoreConnectClient {
    http: Client,
    base_url: Url,
    config: Config,
    cached_token: tokio::sync::Mutex<Option<(String, SystemTime)>>,
    static_token: Option<String>,
    verbose: bool,
}

impl AppStoreConnectClient {
    pub fn new(config: Config, verbose: bool) -> Result<Self> {
        let http = Client::builder()
            .user_agent("xcloud/0.1")
            .use_rustls_tls()
            .build()?;
        let base_url = Url::parse("https://api.appstoreconnect.apple.com/")?;
        Ok(Self {
            http,
            base_url,
            config,
            cached_token: tokio::sync::Mutex::new(None),
            static_token: None,
            verbose,
        })
    }

    pub fn with_static_token(mut self, token: impl Into<String>) -> Self {
        self.static_token = Some(token.into());
        self
    }

    /// Overrides the base URL for API requests. Useful for tests with a mock server.
    pub fn with_base_url(mut self, base_url: Url) -> Self {
        self.base_url = base_url;
        self
    }

    pub async fn bearer(&self) -> Result<String> {
        if let Some(tok) = &self.static_token {
            return Ok(tok.clone());
        }
        {
            let guard = self.cached_token.lock().await;
            if let Some((token, exp_time)) = &*guard
                && SystemTime::now() + Duration::from_secs(60) < *exp_time
            {
                return Ok(token.clone());
            }
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as usize;
        // Apple recommends short-lived tokens (max 20m). Use 10 minutes.
        let exp = now + (10 * 60);
        let claims = Claims {
            iss: self.config.issuer_id.clone(),
            exp,
            aud: "appstoreconnect-v1".to_string(),
            iat: now,
        };
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.config.key_id.clone());

        // Ensure PEM header lines are present
        let pem = if self.config.p8_private_key_pem.contains("BEGIN PRIVATE KEY") {
            self.config.p8_private_key_pem.clone()
        } else {
            // If user provided base64 only, wrap into PEM
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                self.config.p8_private_key_pem.trim()
            )
        };

        let key = EncodingKey::from_ec_pem(pem.as_bytes())
            .context("Failed to parse XCLOUD_P8 as an EC PKCS#8 private key")?;
        let token = encode(&header, &claims, &key)?;
        {
            let mut guard = self.cached_token.lock().await;
            guard.replace((token.clone(), UNIX_EPOCH + Duration::from_secs(exp as u64)));
        }
        Ok(token)
    }

    pub async fn get(&self, path_or_url: &str) -> Result<Value> {
        let url = if path_or_url.starts_with("http") {
            Url::parse(path_or_url)?
        } else {
            self.base_url.join(path_or_url)?
        };
        let bearer = self.bearer().await?;
        let req = self
            .http
            .get(url)
            .header("Authorization", format!("Bearer {}", bearer));
        let res = req.send().await?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            return Err(anyhow!("GET failed {}: {}", status, text));
        }
        let v: Value = serde_json::from_str(&text).context("Failed to parse JSON response")?;
        if self.verbose {
            eprintln!("GET ok: {} bytes", text.len());
        }
        Ok(v)
    }

    pub async fn post(&self, path: &str, body: Value) -> Result<Value> {
        let url = self.base_url.join(path)?;
        let bearer = self.bearer().await?;
        let req = self
            .http
            .post(url)
            .header("Authorization", format!("Bearer {}", bearer))
            .header("Content-Type", "application/json")
            .json(&body);
        let res = req.send().await?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            return Err(anyhow!("POST failed {}: {}", status, text));
        }
        let v: Value = serde_json::from_str(&text).context("Failed to parse JSON response")?;
        if self.verbose {
            eprintln!("POST ok: {} bytes", text.len());
        }
        Ok(v)
    }

    pub async fn list_all(&self, initial_path: &str) -> Result<Vec<Value>> {
        let mut items: Vec<Value> = Vec::new();
        let mut next_url: Option<String> = Some(initial_path.to_string());
        while let Some(url) = next_url.take() {
            let v = self.get(&url).await?;
            if let Some(data) = v.get("data").and_then(|d| d.as_array()) {
                items.extend(data.iter().cloned());
            }
            next_url = v
                .get("links")
                .and_then(|l| l.get("next"))
                .and_then(|n| n.as_str())
                .map(|s| s.to_string());
        }
        Ok(items)
    }

    pub async fn list_ci_products(&self) -> Result<Vec<Value>> {
        self.list_all("v1/ciProducts?limit=200").await
    }

    pub async fn list_workflows_for_product(&self, product_id: &str) -> Result<Vec<Value>> {
        let path = format!("v1/ciProducts/{}/workflows?limit=200", product_id);
        self.list_all(&path).await
    }

    pub async fn list_repositories_for_product(&self, product_id: &str) -> Result<Vec<Value>> {
        let path = format!("v1/ciProducts/{}/scmRepositories?limit=200", product_id);
        self.list_all(&path).await
    }

    pub async fn get_primary_repository_for_product(
        &self,
        product_id: &str,
    ) -> Result<Option<Value>> {
        let path = format!("v1/ciProducts/{}/primaryRepository", product_id);
        match self.get(&path).await {
            Ok(v) => {
                let data = v.get("data");
                if let Some(d) = data {
                    if d.is_null() {
                        return Ok(None);
                    }
                    return Ok(Some(d.clone()));
                }
                Ok(None)
            }
            Err(e) => {
                if self.verbose {
                    eprintln!("primaryRepository lookup failed, will fallback: {}", e);
                }
                Ok(None)
            }
        }
    }

    pub async fn resolve_repository_id_for_product(
        &self,
        product_id: &str,
    ) -> Result<Option<String>> {
        if let Some(primary) = self.get_primary_repository_for_product(product_id).await?
            && let Some(id) = primary.get("id").and_then(|s| s.as_str())
        {
            return Ok(Some(id.to_string()));
        }
        // Try singular 'repository' relationship
        let singular_repo = self
            .get(&format!("v1/ciProducts/{}/repository", product_id))
            .await;
        if let Ok(v) = singular_repo
            && let Some(id) = v
                .get("data")
                .and_then(|d| d.get("id"))
                .and_then(|s| s.as_str())
        {
            return Ok(Some(id.to_string()));
        }
        // Fallback to plural relationship if available
        match self.list_repositories_for_product(product_id).await {
            Ok(list) => Ok(list
                .first()
                .and_then(|v| v.get("id"))
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())),
            Err(e) => {
                if self.verbose {
                    eprintln!("scmRepositories lookup failed: {}", e);
                }
                Ok(None)
            }
        }
    }

    pub async fn resolve_repository_id_for_workflow(
        &self,
        workflow_id: &str,
    ) -> Result<Option<String>> {
        // Try direct relationship endpoint first (singular 'repository')
        let direct = self
            .get(&format!("v1/ciWorkflows/{}/repository", workflow_id))
            .await;
        if let Ok(v) = direct
            && let Some(id) = v
                .get("data")
                .and_then(|d| d.get("id"))
                .and_then(|s| s.as_str())
        {
            return Ok(Some(id.to_string()));
        }

        // Fetch workflow and inspect relationships
        let wf = self.get(&format!("v1/ciWorkflows/{}", workflow_id)).await;
        if let Ok(v) = wf {
            if let Some(rel) = v
                .get("data")
                .and_then(|d| d.get("relationships"))
                .and_then(|r| r.get("repository"))
            {
                if let Some(id) = rel
                    .get("data")
                    .and_then(|d| d.get("id"))
                    .and_then(|s| s.as_str())
                {
                    return Ok(Some(id.to_string()));
                }
                if let Some(related_url) = rel
                    .get("links")
                    .and_then(|l| l.get("related"))
                    .and_then(|s| s.as_str())
                    && let Ok(v2) = self.get(related_url).await
                    && let Some(id) = v2
                        .get("data")
                        .and_then(|d| d.get("id"))
                        .and_then(|s| s.as_str())
                {
                    return Ok(Some(id.to_string()));
                }
            }
            // As a last resort, resolve via product
            if let Some(prod_id) = v
                .get("data")
                .and_then(|d| d.get("relationships"))
                .and_then(|r| r.get("product"))
                .and_then(|p| p.get("data"))
                .and_then(|d| d.get("id"))
                .and_then(|s| s.as_str())
            {
                return self.resolve_repository_id_for_product(prod_id).await;
            }
        }

        Ok(None)
    }

    pub async fn list_branches_for_repository(&self, repo_id: &str) -> Result<Vec<Value>> {
        let all = self
            .list_all(&format!(
                "v1/scmRepositories/{}/gitReferences?limit=200",
                repo_id
            ))
            .await?;
        let mut branches = Vec::new();
        for r in all {
            if is_branch_git_ref(&r) {
                branches.push(r);
            }
        }
        Ok(branches)
    }

    pub async fn list_build_runs_for_workflow(&self, workflow_id: &str) -> Result<Vec<Value>> {
        let path = format!("v1/ciWorkflows/{}/buildRuns?limit=50", workflow_id);
        self.list_all(&path).await
    }

    pub async fn start_build_run(&self, workflow_id: &str, scm_git_ref_id: &str) -> Result<Value> {
        let body = json!({
            "data": {
                "type": "ciBuildRuns",
                "relationships": {
                    "workflow": {"data": {"type": "ciWorkflows", "id": workflow_id}},
                    "sourceBranchOrTag": {"data": {"type": "scmGitReferences", "id": scm_git_ref_id}}
                }
            }
        });
        self.post("v1/ciBuildRuns", body).await
    }

    pub async fn get_build_run(&self, run_id: &str) -> Result<Value> {
        let path = format!("v1/ciBuildRuns/{}", run_id);
        self.get(&path).await
    }

    pub async fn list_actions_for_run(&self, run_id: &str) -> Result<Vec<Value>> {
        self.list_all(&format!("v1/ciBuildRuns/{}/actions?limit=200", run_id))
            .await
    }

    pub async fn list_artifacts_for_action(&self, action_id: &str) -> Result<Vec<Value>> {
        self.list_all(&format!(
            "v1/ciBuildActions/{}/artifacts?limit=200",
            action_id
        ))
        .await
    }

    pub async fn get_artifact(&self, artifact_id: &str) -> Result<Value> {
        self.get(&format!("v1/ciArtifacts/{}", artifact_id)).await
    }

    pub async fn download_artifact(&self, artifact_id: &str, dest_path: &PathBuf) -> Result<()> {
        let detail = self.get_artifact(artifact_id).await?;
        let url_opt = detail
            .get("data")
            .and_then(|d| d.get("attributes"))
            .and_then(|a| a.get("fileUrl").or_else(|| a.get("downloadUrl")))
            .and_then(|s| s.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                detail
                    .get("links")
                    .and_then(|l| l.get("download"))
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string())
            });
        let Some(url) = url_opt else {
            return Err(anyhow!("Artifact does not expose a download URL"));
        };

        let bearer = self.bearer().await?;
        let mut resp = self
            .http
            .get(url)
            .header("Authorization", format!("Bearer {}", bearer))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Download failed: {}", resp.status()));
        }
        let mut file = BufWriter::new(File::create(dest_path)?);
        while let Some(chunk) = resp.chunk().await? {
            file.write_all(&chunk)?;
        }
        file.flush()?;
        Ok(())
    }

    pub async fn list_test_results_for_run(&self, run_id: &str) -> Result<Vec<Value>> {
        let actions = self.list_actions_for_run(run_id).await?;
        let mut results: Vec<Value> = Vec::new();
        for act in actions {
            let aid = resource_id(&act);
            if let Ok(list) = self
                .list_all(&format!("v1/ciBuildActions/{}/testResults?limit=200", aid))
                .await
            {
                results.extend(list);
            }
        }
        Ok(results)
    }
}
