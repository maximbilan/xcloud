use std::{env, time::{Duration, SystemTime, UNIX_EPOCH}};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use dialoguer::{theme::ColorfulTheme, Select};
use indicatif::{ProgressBar, ProgressStyle};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::cmp::Ordering;

#[derive(Parser, Debug)]
#[command(name = "xcloud", version, about = "Xcode Cloud CLI in Rust", long_about = None)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Interactive browser for products, workflows, branches, and actions
    Browse,
    /// List Xcode Cloud products
    Products,
    /// List workflows for a product
    Workflows {
        /// CI Product ID
        #[arg(short, long)]
        product: String,
    },
    /// List branches for a product's primary repository
    Branches {
        /// CI Product ID (used to resolve repository)
        #[arg(short, long)]
        product: String,
    },
    /// Start a build run for workflow and branch
    BuildStart {
        /// CI Workflow ID
        #[arg(short, long)]
        workflow: String,
        /// SCM Branch ID
        #[arg(short, long)]
        branch: String,
    },
    /// Print a short-lived App Store Connect bearer token
    Token,
    /// Show raw product JSON
    ProductInfo {
        /// CI Product ID
        #[arg(short, long)]
        product: String,
    },
    /// Show raw workflow JSON
    WorkflowInfo {
        /// CI Workflow ID
        #[arg(short, long)]
        workflow: String,
    },
    /// List recent build runs for a workflow
    Runs {
        /// CI Workflow ID
        #[arg(short, long)]
        workflow: String,
    },
    /// Show details for a build run
    RunInfo {
        /// CI Build Run ID
        #[arg(short = 'r', long = "run")]
        run_id: String,
    },
    /// List artifacts for a build run
    Artifacts {
        /// CI Build Run ID
        #[arg(short = 'r', long = "run")]
        run_id: String,
    },
    /// List test results for a build run
    TestResults {
        /// CI Build Run ID
        #[arg(short = 'r', long = "run")]
        run_id: String,
    },
}

#[derive(Debug, Clone)]
struct Config {
    issuer_id: String,
    key_id: String,
    p8_private_key_pem: String,
}

impl Config {
    fn from_env() -> Result<Self> {
        let issuer_id = env::var("XCLOUD_ISSUER")
            .context("Missing env XCLOUD_ISSUER (App Store Connect Issuer ID)")?;
        let key_id = env::var("XCLOUD_KEY_ID")
            .context("Missing env XCLOUD_KEY_ID (App Store Connect API Key ID)")?;
        let p8_private_key_pem = env::var("XCLOUD_P8")
            .context("Missing env XCLOUD_P8 (contents of .p8 private key)")?;

        Ok(Self { issuer_id, key_id, p8_private_key_pem })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    exp: usize,
    aud: String,
    iat: usize,
}

struct AppStoreConnectClient {
    http: Client,
    base_url: Url,
    config: Config,
    cached_token: tokio::sync::Mutex<Option<(String, SystemTime)>>,
    verbose: bool,
}

impl AppStoreConnectClient {
    fn new(config: Config, verbose: bool) -> Result<Self> {
        let http = Client::builder()
            .user_agent("xcloud/0.1")
            .use_rustls_tls()
            .build()?;
        let base_url = Url::parse("https://api.appstoreconnect.apple.com/")?;
        Ok(Self { http, base_url, config, cached_token: tokio::sync::Mutex::new(None), verbose })
    }

    async fn bearer(&self) -> Result<String> {
        {
            let guard = self.cached_token.lock().await;
            if let Some((token, exp_time)) = &*guard {
                if SystemTime::now() + Duration::from_secs(60) < *exp_time {
                    return Ok(token.clone());
                }
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

    async fn get(&self, path_or_url: &str) -> Result<Value> {
        let url = if path_or_url.starts_with("http") {
            Url::parse(path_or_url)?
        } else {
            self.base_url.join(path_or_url)?
        };
        let bearer = self.bearer().await?;
        let req = self.http.get(url).header("Authorization", format!("Bearer {}", bearer));
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

    async fn post(&self, path: &str, body: Value) -> Result<Value> {
        let url = self.base_url.join(path)?;
        let bearer = self.bearer().await?;
        let req = self.http
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

    async fn list_all(&self, initial_path: &str) -> Result<Vec<Value>> {
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

    async fn list_ci_products(&self) -> Result<Vec<Value>> {
        // The API supports pagination; request a generous page size
        self.list_all("v1/ciProducts?limit=200").await
    }

    async fn list_workflows_for_product(&self, product_id: &str) -> Result<Vec<Value>> {
        let path = format!("v1/ciProducts/{}/workflows?limit=200", product_id);
        self.list_all(&path).await
    }

    async fn list_repositories_for_product(&self, product_id: &str) -> Result<Vec<Value>> {
        let path = format!("v1/ciProducts/{}/scmRepositories?limit=200", product_id);
        self.list_all(&path).await
    }

    async fn get_primary_repository_for_product(&self, product_id: &str) -> Result<Option<Value>> {
        let path = format!("v1/ciProducts/{}/primaryRepository", product_id);
        match self.get(&path).await {
            Ok(v) => {
                let data = v.get("data");
                if let Some(d) = data {
                    if d.is_null() { return Ok(None); }
                    return Ok(Some(d.clone()));
                }
                Ok(None)
            }
            Err(e) => {
                if self.verbose { eprintln!("primaryRepository lookup failed, will fallback: {}", e); }
                Ok(None)
            }
        }
    }

    async fn resolve_repository_id_for_product(&self, product_id: &str) -> Result<Option<String>> {
        if let Some(primary) = self.get_primary_repository_for_product(product_id).await? {
            if let Some(id) = primary.get("id").and_then(|s| s.as_str()) { return Ok(Some(id.to_string())); }
        }
        // Try singular 'repository' relationship
        let singular_repo = self.get(&format!("v1/ciProducts/{}/repository", product_id)).await;
        if let Ok(v) = singular_repo {
            if let Some(id) = v.get("data").and_then(|d| d.get("id")).and_then(|s| s.as_str()) {
                return Ok(Some(id.to_string()));
            }
        }
        // Fallback to plural relationship if available
        match self.list_repositories_for_product(product_id).await {
            Ok(list) => Ok(list.first().and_then(|v| v.get("id")).and_then(|s| s.as_str()).map(|s| s.to_string())),
            Err(e) => {
                if self.verbose { eprintln!("scmRepositories lookup failed: {}", e); }
                Ok(None)
            }
        }
    }

    async fn resolve_repository_id_for_workflow(&self, workflow_id: &str) -> Result<Option<String>> {
        // Try direct relationship endpoint first (singular 'repository')
        let direct = self.get(&format!("v1/ciWorkflows/{}/repository", workflow_id)).await;
        if let Ok(v) = direct {
            if let Some(id) = v.get("data").and_then(|d| d.get("id")).and_then(|s| s.as_str()) {
                return Ok(Some(id.to_string()));
            }
        }

        // Fetch workflow and inspect relationships
        let wf = self.get(&format!("v1/ciWorkflows/{}", workflow_id)).await;
        if let Ok(v) = wf {
            if let Some(rel) = v.get("data").and_then(|d| d.get("relationships")).and_then(|r| r.get("repository")) {
                if let Some(id) = rel.get("data").and_then(|d| d.get("id")).and_then(|s| s.as_str()) {
                    return Ok(Some(id.to_string()));
                }
                if let Some(related_url) = rel.get("links").and_then(|l| l.get("related")).and_then(|s| s.as_str()) {
                    if let Ok(v2) = self.get(related_url).await {
                        if let Some(id) = v2.get("data").and_then(|d| d.get("id")).and_then(|s| s.as_str()) {
                            return Ok(Some(id.to_string()));
                        }
                    }
                }
            }
            // As a last resort, resolve via product
            if let Some(prod_id) = v.get("data")
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
    async fn list_branches_for_repository(&self, repo_id: &str) -> Result<Vec<Value>> {
        // Fetch all git references and filter locally to branches
        let all = self
            .list_all(&format!("v1/scmRepositories/{}/gitReferences?limit=200", repo_id))
            .await?;
        let mut branches = Vec::new();
        for r in all {
            let is_branch = r
                .get("attributes")
                .and_then(|a| a.get("canonicalName"))
                .and_then(|s| s.as_str())
                .map(|s| s.starts_with("refs/heads/") || s.starts_with("heads/") || s.contains("/heads/"))
                .unwrap_or(false);
            if is_branch {
                branches.push(r);
            }
        }
        Ok(branches)
    }

    async fn list_build_runs_for_workflow(&self, workflow_id: &str) -> Result<Vec<Value>> {
        let path = format!("v1/ciWorkflows/{}/buildRuns?limit=50", workflow_id);
        self.list_all(&path).await
    }

    async fn start_build_run(&self, workflow_id: &str, scm_git_ref_id: &str) -> Result<Value> {
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

    async fn get_build_run(&self, run_id: &str) -> Result<Value> {
        let path = format!("v1/ciBuildRuns/{}", run_id);
        self.get(&path).await
    }

    async fn list_actions_for_run(&self, run_id: &str) -> Result<Vec<Value>> {
        // Build run -> actions
        self.list_all(&format!("v1/ciBuildRuns/{}/actions?limit=200", run_id)).await
    }

    async fn list_artifacts_for_action(&self, action_id: &str) -> Result<Vec<Value>> {
        // Per docs: GET /v1/ciBuildActions/{id}/artifacts
        self.list_all(&format!("v1/ciBuildActions/{}/artifacts?limit=200", action_id)).await
    }

    async fn get_artifact(&self, artifact_id: &str) -> Result<Value> {
        // Per docs: GET /v1/ciArtifacts/{id}
        self.get(&format!("v1/ciArtifacts/{}", artifact_id)).await
    }

    async fn list_test_results_for_run(&self, run_id: &str) -> Result<Vec<Value>> {
        // Build run -> actions -> testResults relationship on actions
        // First try the documented endpoint on actions via include
        // Fallback approach: request actions and for each action, follow its testResults link
        let actions = self.list_actions_for_run(run_id).await?;
        let mut results: Vec<Value> = Vec::new();
        for act in actions {
            let aid = resource_id(&act);
            // GET /v1/ciBuildActions/{id}/testResults
            if let Ok(list) = self.list_all(&format!("v1/ciBuildActions/{}/testResults?limit=200", aid)).await {
                results.extend(list);
            }
        }
        Ok(results)
    }
}

fn resource_name(resource: &Value) -> String {
    if let Some(attrs) = resource.get("attributes") {
        if let Some(s) = attrs.get("name").and_then(|n| n.as_str()) {
            return s.to_string();
        }
        if let Some(s) = attrs.get("canonicalName").and_then(|n| n.as_str()) {
            return s.to_string();
        }
        if let Some(s) = attrs.get("title").and_then(|n| n.as_str()) {
            return s.to_string();
        }
    }
    resource
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or("<unknown>")
        .to_string()
}

fn resource_id(resource: &Value) -> String {
    resource
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or("")
        .to_string()
}

fn pretty_run_status(run: &Value) -> String {
    let a = run.get("attributes");
    let status = a
        .and_then(|a| a.get("buildResult")).and_then(|s| s.as_str())
        .or_else(|| a.and_then(|a| a.get("executionProgress")).and_then(|s| s.as_str()))
        .or_else(|| a.and_then(|a| a.get("completionStatus")).and_then(|s| s.as_str()))
        .or_else(|| a.and_then(|a| a.get("status")).and_then(|s| s.as_str()))
        .unwrap_or("UNKNOWN");
    status.to_string()
}

fn compare_runs_desc(a: &Value, b: &Value) -> Ordering {
    let ca = a.get("attributes").and_then(|x| x.get("createdDate")).and_then(|s| s.as_str());
    let cb = b.get("attributes").and_then(|x| x.get("createdDate")).and_then(|s| s.as_str());
    match (ca, cb) {
        (Some(a), Some(b)) => b.cmp(a), // newer first
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        _ => resource_id(b).cmp(&resource_id(a)),
    }
}

fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(Duration::from_millis(80));
    pb.set_style(ProgressStyle::with_template("{spinner} {msg}").unwrap());
    pb.set_message(msg.to_string());
    pb
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config::from_env()?;
    let client = AppStoreConnectClient::new(cfg, cli.verbose)?;

    match cli.command.unwrap_or(Commands::Browse) {
        Commands::Browse => browse_flow(&client).await?,
        Commands::Products => list_products_cmd(&client).await?,
        Commands::Workflows { product } => list_workflows_cmd(&client, &product).await?,
        Commands::Branches { product } => list_branches_cmd(&client, &product).await?,
        Commands::BuildStart { workflow, branch } => start_build_cmd(&client, &workflow, &branch).await?,
        Commands::Token => print_token_cmd(&client).await?,
        Commands::ProductInfo { product } => product_info_cmd(&client, &product).await?,
        Commands::WorkflowInfo { workflow } => workflow_info_cmd(&client, &workflow).await?,
        Commands::Runs { workflow } => list_runs_cmd(&client, &workflow).await?,
        Commands::RunInfo { run_id } => run_info_cmd(&client, &run_id).await?,
        Commands::Artifacts { run_id } => run_artifacts_cmd(&client, &run_id).await?,
        Commands::TestResults { run_id } => run_test_results_cmd(&client, &run_id).await?,
    }

    Ok(())
}

async fn list_products_cmd(client: &AppStoreConnectClient) -> Result<()> {
    let pb = spinner("Loading products...");
    let products = client.list_ci_products().await?;
    pb.finish_and_clear();

    if products.is_empty() {
        println!("No Xcode Cloud products found");
        return Ok(());
    }

    for p in products {
        let id = resource_id(&p);
        let name = resource_name(&p);
        println!("{}\t{}", id, name);
    }
    Ok(())
}

async fn list_workflows_cmd(client: &AppStoreConnectClient, product_id: &str) -> Result<()> {
    let pb = spinner("Loading workflows...");
    let workflows = client.list_workflows_for_product(product_id).await?;
    pb.finish_and_clear();

    if workflows.is_empty() { println!("No workflows found"); return Ok(()); }

    for w in workflows {
        println!("{}\t{}", resource_id(&w), resource_name(&w));
    }
    Ok(())
}

async fn list_branches_cmd(client: &AppStoreConnectClient, product_id: &str) -> Result<()> {
    // Try both product and each workflow because repository can be attached at workflow level
    let mut repo_id_opt = {
        let pb = spinner("Resolving repository from product...");
        let r = client.resolve_repository_id_for_product(product_id).await?;
        pb.finish_and_clear();
        r
    };
    if repo_id_opt.is_none() {
        // Try via a workflow of this product
        let workflows = client.list_workflows_for_product(product_id).await?;
        for w in workflows {
            let wid = resource_id(&w);
            if let Some(rid) = client.resolve_repository_id_for_workflow(&wid).await? {
                repo_id_opt = Some(rid);
                break;
            }
        }
    }
    let Some(repo_id) = repo_id_opt else { println!("No repositories attached to this product"); return Ok(()); };

    let pb = spinner("Loading branches...");
    let branches = client.list_branches_for_repository(&repo_id).await?;
    pb.finish_and_clear();
    if branches.is_empty() { println!("No branches found"); return Ok(()); }

    for b in branches { println!("{}\t{}", resource_id(&b), resource_name(&b)); }
    Ok(())
}

async fn start_build_cmd(client: &AppStoreConnectClient, workflow_id: &str, branch_id: &str) -> Result<()> {
    let pb = spinner("Starting build run...");
    let res = client.start_build_run(workflow_id, branch_id).await?;
    pb.finish_and_clear();

    let id = res.get("data").and_then(|d| d.get("id")).and_then(|s| s.as_str()).unwrap_or("<unknown>");
    println!("Build run created: {}", id);

    Ok(())
}

async fn print_token_cmd(client: &AppStoreConnectClient) -> Result<()> {
    let token = client.bearer().await?;
    println!("{}", token);
    Ok(())
}

async fn product_info_cmd(client: &AppStoreConnectClient, product_id: &str) -> Result<()> {
    let v = client.get(&format!("v1/ciProducts/{}", product_id)).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    // Try to show primary repo linkage too
    match client.get(&format!("v1/ciProducts/{}/primaryRepository", product_id)).await {
        Ok(pr) => {
            println!("\nPrimary Repository:\n{}", serde_json::to_string_pretty(&pr)?);
        }
        Err(e) => eprintln!("primaryRepository lookup failed: {}", e),
    }
    Ok(())
}

async fn workflow_info_cmd(client: &AppStoreConnectClient, workflow_id: &str) -> Result<()> {
    let v = client.get(&format!("v1/ciWorkflows/{}", workflow_id)).await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    // Try scmRepository relation
    match client.get(&format!("v1/ciWorkflows/{}/scmRepository", workflow_id)).await {
        Ok(rep) => println!("\nscmRepository:\n{}", serde_json::to_string_pretty(&rep)?),
        Err(e) => eprintln!("scmRepository relation lookup failed: {}", e),
    }
    Ok(())
}

async fn list_runs_cmd(client: &AppStoreConnectClient, workflow_id: &str) -> Result<()> {
    let pb = spinner("Loading runs...");
    let mut runs = client.list_build_runs_for_workflow(workflow_id).await?;
    pb.finish_and_clear();
    if runs.is_empty() { println!("No runs found"); return Ok(()); }
    // Sort by createdDate desc if present, else by id desc
    runs.sort_by(|a, b| compare_runs_desc(a, b));
    for r in runs {
        let rid = resource_id(&r);
        let status = pretty_run_status(&r);
        println!("{}\t{}", rid, status);
    }
    Ok(())
}

async fn run_info_cmd(client: &AppStoreConnectClient, run_id: &str) -> Result<()> {
    let pb = spinner("Loading run info...");
    let v = client.get_build_run(run_id).await?;
    pb.finish_and_clear();
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

// removed cancel run action per API constraints

fn extract_url_fields(v: &Value) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(attrs) = v.get("attributes") {
        for key in ["url", "downloadUrl", "fileUrl", "logUrl", "artifactUrl", "browserDownloadUrl"] {
            if let Some(s) = attrs.get(key).and_then(|x| x.as_str()) {
                out.push((key.to_string(), s.to_string()));
            }
        }
        if let Some(name) = attrs.get("name").and_then(|x| x.as_str()) {
            if !out.is_empty() { out.insert(0, ("name".into(), name.to_string())); }
        }
        if let Some(filename) = attrs.get("fileName").and_then(|x| x.as_str()) {
            if !out.is_empty() { out.insert(0, ("fileName".into(), filename.to_string())); }
        }
    }
    if let Some(links) = v.get("links") {
        for key in ["download", "self", "related", "web"] {
            if let Some(s) = links.get(key).and_then(|x| x.as_str()) {
                out.push((format!("links.{}", key), s.to_string()));
            }
        }
    }
    out
}

async fn run_artifacts_cmd(client: &AppStoreConnectClient, run_id: &str) -> Result<()> {
    let pb = spinner("Loading actions...");
    let acts = client.list_actions_for_run(run_id).await;
    pb.finish_and_clear();
    match acts {
        Ok(actions) => {
            if actions.is_empty() { println!("No actions found"); return Ok(()); }
            for act in actions {
                let aid = resource_id(&act);
                let aname = resource_name(&act);
                println!("Action {}\t{}", aid, aname);
                let pb = spinner("  Loading artifacts...");
                let arts = client.list_artifacts_for_action(&aid).await;
                pb.finish_and_clear();
                match arts {
                    Ok(list) => {
                        if list.is_empty() { println!("  (no artifacts)"); }
                        for a in list {
                            let id = resource_id(&a);
                            let name = resource_name(&a);
                            println!("  {}\t{}", id, name);
                            // Fetch artifact details to get any URL or metadata
                            if let Ok(details) = client.get_artifact(&id).await {
                                if let Some(attrs) = details.get("data").and_then(|d| d.get("attributes")) {
                                    if let Some(size) = attrs.get("fileSize").and_then(|x| x.as_i64()) {
                                        println!("    size: {} bytes", size);
                                    }
                                    if let Some(state) = attrs.get("state").and_then(|x| x.as_str()) {
                                        println!("    state: {}", state);
                                    }
                                }
                                let urls = extract_url_fields(&details);
                                for (k, u) in urls { println!("    {}: {}", k, u); }
                            }
                        }
                    }
                    Err(e) => eprintln!("  Failed to list artifacts: {}", e),
                }
            }
        }
        Err(e) => eprintln!("Failed to load actions: {}", e),
    }
    Ok(())
}

async fn run_test_results_cmd(client: &AppStoreConnectClient, run_id: &str) -> Result<()> {
    let pb = spinner("Loading test results...");
    let trs = client.list_test_results_for_run(run_id).await;
    pb.finish_and_clear();
    match trs {
        Ok(list) => {
            if list.is_empty() { println!("No test results found"); return Ok(()); }
            for t in list {
                let id = resource_id(&t);
                let name = resource_name(&t);
                println!("{}\t{}", id, name);
            }
        }
        Err(e) => eprintln!("Failed to list test results: {}", e),
    }
    Ok(())
}

async fn browse_flow(client: &AppStoreConnectClient) -> Result<()> {
    let theme = ColorfulTheme::default();

    // Level 1: Products (with Back/Exit not needed at root)
    let products = {
        let pb = spinner("Loading products...");
        let p = client.list_ci_products().await?;
        pb.finish_and_clear();
        p
    };
    if products.is_empty() {
        println!("No products available");
        return Ok(());
    }

    let mut product_idx: Option<usize> = None;
    loop {
        // Pick product
        if product_idx.is_none() {
            let mut items: Vec<String> = products.iter().map(resource_name).collect();
            items.push("Exit".into());
            let idx = Select::with_theme(&theme)
                .with_prompt("Select a product")
                .default(0)
                .items(&items)
                .interact()?;
            if idx == items.len() - 1 { return Ok(()); }
            product_idx = Some(idx);
        }
        let product = &products[product_idx.unwrap()];
        let product_id = resource_id(product);

        // Level 2: Workflows
        let workflows = {
            let pb = spinner("Loading workflows...");
            let w = client.list_workflows_for_product(&product_id).await?;
            pb.finish_and_clear();
            w
        };
        if workflows.is_empty() {
            println!("No workflows for this product");
            product_idx = None; // force reselect product
            continue;
        }
        let mut workflow_idx: Option<usize> = None;
        loop {
            if workflow_idx.is_none() {
                let mut items: Vec<String> = workflows.iter().map(resource_name).collect();
                items.push("Back".into());
                items.push("Exit".into());
                let idx = Select::with_theme(&theme)
                    .with_prompt("Select a workflow")
                    .default(0)
                    .items(&items)
                    .interact()?;
                if idx == items.len() - 1 { return Ok(()); }
                if idx == items.len() - 2 { product_idx = None; break; }
                workflow_idx = Some(idx);
            }
            let workflow = &workflows[workflow_idx.unwrap()];
            let workflow_id = resource_id(workflow);

            // Level 3: Branches (resolve repo via workflow first, then product)
            let repo_id_opt = {
                let pb = spinner("Resolving repository...");
                let via_wf = client.resolve_repository_id_for_workflow(&workflow_id).await?;
                let r = if via_wf.is_some() { via_wf } else { client.resolve_repository_id_for_product(&product_id).await? };
                pb.finish_and_clear();
                r
            };
            let Some(repo_id) = repo_id_opt else {
                println!("No repositories attached to this product");
                workflow_idx = None; // back to workflow selection
                continue;
            };
            let branches = {
                let pb = spinner("Loading branches...");
                let b = client.list_branches_for_repository(&repo_id).await?;
                pb.finish_and_clear();
                b
            };
            if branches.is_empty() {
                println!("No branches found");
                workflow_idx = None;
                continue;
            }

            let mut branch_idx: Option<usize> = None;
            loop {
                if branch_idx.is_none() {
                    let mut items: Vec<String> = branches.iter().map(resource_name).collect();
                    items.push("Back".into());
                    items.push("Exit".into());
                    let idx = Select::with_theme(&theme)
                        .with_prompt("Select a branch")
                        .default(0)
                        .items(&items)
                        .interact()?;
                    if idx == items.len() - 1 { return Ok(()); }
                    if idx == items.len() - 2 { break; }
                    branch_idx = Some(idx);
                }

                let branch = &branches[branch_idx.unwrap()];
                let branch_id = resource_id(branch);

                // Action menu for selected (product, workflow, branch)
                let actions = vec![
                    "Start build run",
                    "Show recent runs",
                    "Back",
                    "Exit",
                ];
                let idx = Select::with_theme(&theme)
                    .with_prompt("Choose action")
                    .items(&actions)
                    .default(0)
                    .interact()?;
                match idx {
                    0 => {
                        let pb = spinner("Starting build run...");
                        let res = client.start_build_run(&workflow_id, &branch_id).await;
                        pb.finish_and_clear();
                        match res {
                            Ok(v) => {
                                let id = v.get("data").and_then(|d| d.get("id")).and_then(|s| s.as_str()).unwrap_or("<unknown>");
                                println!("Build run created: {}", id);
                            }
                            Err(e) => eprintln!("Failed to start build: {}", e),
                        }
                    }
                    1 => {
                        // Runs submenu
                        runs_submenu(client, &theme, &workflow_id).await?;
                    }
                    2 => { branch_idx = None; continue; }
                    _ => return Ok(()),
                }
            }
        }
    }
}

async fn runs_submenu(client: &AppStoreConnectClient, theme: &ColorfulTheme, workflow_id: &str) -> Result<()> {
    loop {
        let mut runs = {
            let pb = spinner("Loading runs...");
            let r = client.list_build_runs_for_workflow(workflow_id).await;
            pb.finish_and_clear();
            r
        }?;
        if runs.is_empty() { println!("No runs found"); return Ok(()); }
        runs.sort_by(|a, b| compare_runs_desc(a, b));

        let mut items: Vec<String> = runs.iter().map(|r| {
            let rid = resource_id(r);
            let status = pretty_run_status(r);
            let when = r.get("attributes").and_then(|a| a.get("createdDate")).and_then(|s| s.as_str()).unwrap_or("");
            if when.is_empty() { format!("{} - {}", rid, status) } else { format!("{} - {} - {}", rid, status, when) }
        }).collect();
        items.push("Back".into());
        items.push("Exit".into());
        let idx = Select::with_theme(theme)
            .with_prompt("Select a run")
            .default(0)
            .items(&items)
            .interact()?;
        if idx == items.len() - 1 { return Ok(()); }
        if idx == items.len() - 2 { break; }
        let run = &runs[idx];
        let run_id = resource_id(run);

        // Actions for run
        let actions = vec![
            "View details",
            "List artifacts",
            "Test results",
            "Back",
            "Exit",
        ];
        let aidx = Select::with_theme(theme)
            .with_prompt("Run actions")
            .default(0)
            .items(&actions)
            .interact()?;
        match aidx {
            0 => { run_info_cmd(client, &run_id).await?; }
            1 => { run_artifacts_cmd(client, &run_id).await?; }
            2 => { run_test_results_cmd(client, &run_id).await?; }
            3 => continue, // back
            _ => return Ok(()),
        }
    }
    Ok(())
}
