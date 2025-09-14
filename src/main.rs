use std::{env, time::{Duration, SystemTime, UNIX_EPOCH}};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use dialoguer::{theme::ColorfulTheme, Select};
use indicatif::{ProgressBar, ProgressStyle};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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
    /// Cancel a build run (best-effort)
    RunCancel {
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
    /// List logs for a build run
    Logs {
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

    async fn list_branches_for_repository(&self, repo_id: &str) -> Result<Vec<Value>> {
        let path = format!("v1/scmRepositories/{}/scmBranches?limit=200", repo_id);
        self.list_all(&path).await
    }

    async fn list_build_runs_for_workflow(&self, workflow_id: &str) -> Result<Vec<Value>> {
        let path = format!("v1/ciWorkflows/{}/buildRuns?limit=50", workflow_id);
        self.list_all(&path).await
    }

    async fn start_build_run(&self, workflow_id: &str, scm_branch_id: &str) -> Result<Value> {
        let body = json!({
            "data": {
                "type": "ciBuildRuns",
                "relationships": {
                    "workflow": {"data": {"type": "ciWorkflows", "id": workflow_id}},
                    "scmBranch": {"data": {"type": "scmBranches", "id": scm_branch_id}}
                }
            }
        });
        self.post("v1/ciBuildRuns", body).await
    }

    async fn get_build_run(&self, run_id: &str) -> Result<Value> {
        let path = format!("v1/ciBuildRuns/{}", run_id);
        self.get(&path).await
    }

    async fn cancel_build_run(&self, run_id: &str) -> Result<()> {
        // Apple actions often use the actions namespace
        let path = format!("v1/ciBuildRuns/{}/actions/cancel", run_id);
        let _ = self.post(&path, json!({})).await?;
        Ok(())
    }

    async fn list_artifacts_for_run(&self, run_id: &str) -> Result<Vec<Value>> {
        let path = format!("v1/ciBuildRuns/{}/artifacts?limit=200", run_id);
        self.list_all(&path).await
    }

    async fn list_logs_for_run(&self, run_id: &str) -> Result<Vec<Value>> {
        let path = format!("v1/ciBuildRuns/{}/logs?limit=200", run_id);
        self.list_all(&path).await
    }
}

fn resource_name(resource: &Value) -> String {
    resource
        .get("attributes")
        .and_then(|a| a.get("name"))
        .and_then(|n| n.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| resource.get("id").and_then(|i| i.as_str()).unwrap_or("<unknown>").to_string())
}

fn resource_id(resource: &Value) -> String {
    resource
        .get("id")
        .and_then(|i| i.as_str())
        .unwrap_or("")
        .to_string()
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
        Commands::Runs { workflow } => list_runs_cmd(&client, &workflow).await?,
        Commands::RunInfo { run_id } => run_info_cmd(&client, &run_id).await?,
        Commands::RunCancel { run_id } => run_cancel_cmd(&client, &run_id).await?,
        Commands::Artifacts { run_id } => run_artifacts_cmd(&client, &run_id).await?,
        Commands::Logs { run_id } => run_logs_cmd(&client, &run_id).await?,
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
    let pb = spinner("Resolving repository...");
    let repos = client.list_repositories_for_product(product_id).await?;
    pb.finish_and_clear();
    if repos.is_empty() { println!("No repositories attached to product"); return Ok(()); }
    // For now, use the first repo
    let repo = &repos[0];
    let repo_id = resource_id(repo);

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

async fn list_runs_cmd(client: &AppStoreConnectClient, workflow_id: &str) -> Result<()> {
    let pb = spinner("Loading runs...");
    let runs = client.list_build_runs_for_workflow(workflow_id).await?;
    pb.finish_and_clear();
    if runs.is_empty() { println!("No runs found"); return Ok(()); }
    for r in runs {
        let rid = resource_id(&r);
        let status = r
            .get("attributes").and_then(|a| a.get("buildResult")).and_then(|s| s.as_str())
            .or_else(|| r.get("attributes").and_then(|a| a.get("status")).and_then(|s| s.as_str()))
            .unwrap_or("<unknown>");
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

async fn run_cancel_cmd(client: &AppStoreConnectClient, run_id: &str) -> Result<()> {
    let pb = spinner("Cancelling run...");
    let res = client.cancel_build_run(run_id).await;
    pb.finish_and_clear();
    match res {
        Ok(_) => println!("Run {} cancellation requested", run_id),
        Err(e) => eprintln!("Failed to cancel run: {}", e),
    }
    Ok(())
}

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
    let pb = spinner("Loading artifacts...");
    let arts = client.list_artifacts_for_run(run_id).await;
    pb.finish_and_clear();
    match arts {
        Ok(list) => {
            if list.is_empty() { println!("No artifacts found"); return Ok(()); }
            for a in list {
                let id = resource_id(&a);
                let name = resource_name(&a);
                println!("{}\t{}", id, name);
                let urls = extract_url_fields(&a);
                for (k, u) in urls { println!("  {}: {}", k, u); }
            }
        }
        Err(e) => eprintln!("Failed to list artifacts: {}", e),
    }
    Ok(())
}

async fn run_logs_cmd(client: &AppStoreConnectClient, run_id: &str) -> Result<()> {
    let pb = spinner("Loading logs...");
    let logs = client.list_logs_for_run(run_id).await;
    pb.finish_and_clear();
    match logs {
        Ok(list) => {
            if list.is_empty() { println!("No logs found"); return Ok(()); }
            for l in list {
                let id = resource_id(&l);
                let name = resource_name(&l);
                println!("{}\t{}", id, name);
                let urls = extract_url_fields(&l);
                for (k, u) in urls { println!("  {}: {}", k, u); }
            }
        }
        Err(e) => eprintln!("Failed to list logs: {}", e),
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
                if idx == items.len() - 2 { workflow_idx = None; product_idx = None; break; }
                workflow_idx = Some(idx);
            }
            let workflow = &workflows[workflow_idx.unwrap()];
            let workflow_id = resource_id(workflow);

            // Level 3: Branches
            let repos = {
                let pb = spinner("Resolving repository...");
                let r = client.list_repositories_for_product(&product_id).await?;
                pb.finish_and_clear();
                r
            };
            if repos.is_empty() {
                println!("No repositories attached to this product");
                workflow_idx = None; // back to workflow selection
                continue;
            }
            let repo_id = resource_id(&repos[0]);
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
                    if idx == items.len() - 2 { branch_idx = None; break; }
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
        let runs = {
            let pb = spinner("Loading runs...");
            let r = client.list_build_runs_for_workflow(workflow_id).await;
            pb.finish_and_clear();
            r
        }?;
        if runs.is_empty() { println!("No runs found"); return Ok(()); }

        let mut items: Vec<String> = runs.iter().map(|r| {
            let rid = resource_id(r);
            let status = r
                .get("attributes").and_then(|a| a.get("buildResult")).and_then(|s| s.as_str())
                .or_else(|| r.get("attributes").and_then(|a| a.get("status")).and_then(|s| s.as_str()))
                .unwrap_or("<unknown>");
            format!("{} - {}", rid, status)
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
            "Cancel run",
            "List artifacts",
            "List logs",
            "Open first artifact URL",
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
            1 => { run_cancel_cmd(client, &run_id).await?; }
            2 => { run_artifacts_cmd(client, &run_id).await?; }
            3 => { run_logs_cmd(client, &run_id).await?; }
            4 => {
                // Best-effort: try to open a URL from artifacts
                let arts = client.list_artifacts_for_run(&run_id).await;
                match arts {
                    Ok(list) => {
                        if let Some(first) = list.first() {
                            if let Some((_, url)) = extract_url_fields(first).into_iter().find(|(k, _)| k.contains("url")) {
                                let _ = open::that(url);
                            } else {
                                println!("No URL available on first artifact");
                            }
                        } else {
                            println!("No artifacts found");
                        }
                    }
                    Err(e) => eprintln!("Failed to load artifacts: {}", e),
                }
            }
            5 => continue, // back to runs list
            _ => return Ok(()),
        }
    }
    Ok(())
}
