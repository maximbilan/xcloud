use anyhow::Result;
use clap::{Parser, Subcommand};
use dialoguer::{Select, theme::ColorfulTheme};
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;

use crate::{
    asc::{AppStoreConnectClient, Config},
    util::{compare_runs_desc, pretty_run_status, resource_id, resource_name},
};

#[derive(Parser, Debug)]
#[command(name = "xcloud", version, about = "Xcode Cloud CLI in Rust", long_about = None)]
pub struct Cli {
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

pub async fn run_cli() -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config::from_env()?;
    let client = AppStoreConnectClient::new(cfg, cli.verbose)?;

    match cli.command.unwrap_or(Commands::Browse) {
        Commands::Browse => browse_flow(&client).await?,
        Commands::Products => list_products_cmd(&client).await?,
        Commands::Workflows { product } => list_workflows_cmd(&client, &product).await?,
        Commands::Branches { product } => list_branches_cmd(&client, &product).await?,
        Commands::BuildStart { workflow, branch } => {
            start_build_cmd(&client, &workflow, &branch).await?
        }
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

fn spinner(msg: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(std::time::Duration::from_millis(80));
    pb.set_style(ProgressStyle::with_template("{spinner} {msg}").unwrap());
    pb.set_message(msg.to_string());
    pb
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

    if workflows.is_empty() {
        println!("No workflows found");
        return Ok(());
    }

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
    let Some(repo_id) = repo_id_opt else {
        println!("No repositories attached to this product");
        return Ok(());
    };

    let pb = spinner("Loading branches...");
    let branches = client.list_branches_for_repository(&repo_id).await?;
    pb.finish_and_clear();
    if branches.is_empty() {
        println!("No branches found");
        return Ok(());
    }

    for b in branches {
        println!("{}\t{}", resource_id(&b), resource_name(&b));
    }
    Ok(())
}

async fn start_build_cmd(
    client: &AppStoreConnectClient,
    workflow_id: &str,
    branch_id: &str,
) -> Result<()> {
    let pb = spinner("Starting build run...");
    let res = client.start_build_run(workflow_id, branch_id).await?;
    pb.finish_and_clear();

    let id = res
        .get("data")
        .and_then(|d| d.get("id"))
        .and_then(|s| s.as_str())
        .unwrap_or("<unknown>");
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
    match client
        .get(&format!("v1/ciProducts/{}/primaryRepository", product_id))
        .await
    {
        Ok(pr) => {
            println!(
                "\nPrimary Repository:\n{}",
                serde_json::to_string_pretty(&pr)?
            );
        }
        Err(e) => eprintln!("primaryRepository lookup failed: {}", e),
    }
    Ok(())
}

async fn workflow_info_cmd(client: &AppStoreConnectClient, workflow_id: &str) -> Result<()> {
    let v = client
        .get(&format!("v1/ciWorkflows/{}", workflow_id))
        .await?;
    println!("{}", serde_json::to_string_pretty(&v)?);
    // Try scmRepository relation
    match client
        .get(&format!("v1/ciWorkflows/{}/scmRepository", workflow_id))
        .await
    {
        Ok(rep) => println!("\nscmRepository:\n{}", serde_json::to_string_pretty(&rep)?),
        Err(e) => eprintln!("scmRepository relation lookup failed: {}", e),
    }
    Ok(())
}

async fn list_runs_cmd(client: &AppStoreConnectClient, workflow_id: &str) -> Result<()> {
    let pb = spinner("Loading runs...");
    let mut runs = client.list_build_runs_for_workflow(workflow_id).await?;
    pb.finish_and_clear();
    if runs.is_empty() {
        println!("No runs found");
        return Ok(());
    }
    // Sort by createdDate desc if present, else by id desc
    runs.sort_by(compare_runs_desc);
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

async fn run_artifacts_cmd(client: &AppStoreConnectClient, run_id: &str) -> Result<()> {
    loop {
        let pb = spinner("Loading actions...");
        let actions = client.list_actions_for_run(run_id).await;
        pb.finish_and_clear();
        let actions = match actions {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Failed to load actions: {}", e);
                return Ok(());
            }
        };
        if actions.is_empty() {
            println!("No actions found");
            return Ok(());
        }

        let theme = ColorfulTheme::default();
        let mut action_items: Vec<String> = actions.iter().map(resource_name).collect();
        action_items.push("Back".into());
        action_items.push("Exit".into());
        let aidx = Select::with_theme(&theme)
            .with_prompt("Select an action")
            .default(0)
            .items(&action_items)
            .interact()?;
        if aidx == action_items.len() - 1 {
            std::process::exit(0);
        }
        if aidx == action_items.len() - 2 {
            break;
        }
        let action = &actions[aidx];
        let action_id = resource_id(action);

        // List artifacts for selected action
        let pb = spinner("Loading artifacts...");
        let arts = client.list_artifacts_for_action(&action_id).await;
        pb.finish_and_clear();
        let arts = match arts {
            Ok(x) => x,
            Err(e) => {
                eprintln!("Failed to list artifacts: {}", e);
                continue;
            }
        };
        if arts.is_empty() {
            println!("(no artifacts)");
            continue;
        }

        let mut art_items: Vec<String> = arts.iter().map(resource_name).collect();
        art_items.push("Back".into());
        art_items.push("Exit".into());
        let aridx = Select::with_theme(&theme)
            .with_prompt("Select an artifact")
            .default(0)
            .items(&art_items)
            .interact()?;
        if aridx == art_items.len() - 1 {
            std::process::exit(0);
        }
        if aridx == art_items.len() - 2 {
            continue;
        }
        let art = &arts[aridx];
        let art_id = resource_id(art);

        // Show artifact details
        let pb = spinner("Loading artifact details...");
        let details = client.get_artifact(&art_id).await;
        pb.finish_and_clear();
        match details {
            Ok(v) => {
                println!("{}", serde_json::to_string_pretty(&v)?);
                // Offer to download
                let choices = vec!["Download", "Back", "Exit"];
                let cidx = Select::with_theme(&theme)
                    .with_prompt("Artifact action")
                    .default(0)
                    .items(&choices)
                    .interact()?;
                if cidx == 2 {
                    std::process::exit(0);
                }
                if cidx == 0 {
                    let fallback = format!("{}.bin", art_id);
                    let filename_owned = v
                        .get("data")
                        .and_then(|d| d.get("attributes"))
                        .and_then(|a| a.get("fileName"))
                        .and_then(|s| s.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or(fallback);
                    let mut dest = PathBuf::from(&filename_owned);
                    // if file exists, append suffix
                    let mut counter = 1;
                    while dest.exists() {
                        let alt = format!(
                            "{}({}).{}",
                            dest.file_stem()
                                .and_then(|s| s.to_str())
                                .unwrap_or("artifact"),
                            counter,
                            dest.extension().and_then(|s| s.to_str()).unwrap_or("bin")
                        );
                        dest = PathBuf::from(alt);
                        counter += 1;
                    }
                    let pb = spinner(&format!("Downloading to {:?}...", dest));
                    let r = client.download_artifact(&art_id, &dest).await;
                    pb.finish_and_clear();
                    match r {
                        Ok(_) => println!("Saved to {:?}", dest),
                        Err(e) => eprintln!("Download failed: {}", e),
                    }
                }
            }
            Err(e) => eprintln!("Failed to load artifact details: {}", e),
        }
    }
    Ok(())
}

async fn run_test_results_cmd(client: &AppStoreConnectClient, run_id: &str) -> Result<()> {
    let pb = spinner("Loading test results...");
    let trs = client.list_test_results_for_run(run_id).await;
    pb.finish_and_clear();
    match trs {
        Ok(list) => {
            if list.is_empty() {
                println!("No test results found");
                return Ok(());
            }
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
            if idx == items.len() - 1 {
                std::process::exit(0);
            }
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
                if idx == items.len() - 1 {
                    std::process::exit(0);
                }
                if idx == items.len() - 2 {
                    product_idx = None;
                    break;
                }
                workflow_idx = Some(idx);
            }
            let workflow = &workflows[workflow_idx.unwrap()];
            let workflow_id = resource_id(workflow);

            // Level 3: Branches (resolve repo via workflow first, then product)
            let repo_id_opt = {
                let pb = spinner("Resolving repository...");
                let via_wf = client
                    .resolve_repository_id_for_workflow(&workflow_id)
                    .await?;
                let r = if via_wf.is_some() {
                    via_wf
                } else {
                    client
                        .resolve_repository_id_for_product(&product_id)
                        .await?
                };
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
            let mut back_to_workflows = false;
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
                    if idx == items.len() - 1 {
                        std::process::exit(0);
                    }
                    if idx == items.len() - 2 {
                        back_to_workflows = true;
                    }
                    if back_to_workflows {
                        break;
                    }
                    branch_idx = Some(idx);
                }

                let branch = &branches[branch_idx.unwrap()];
                let branch_id = resource_id(branch);

                // Action menu for selected (product, workflow, branch)
                let actions = vec!["Start build run", "Show recent runs", "Back", "Exit"];
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
                                let id = v
                                    .get("data")
                                    .and_then(|d| d.get("id"))
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("<unknown>");
                                println!("Build run created: {}", id);
                            }
                            Err(e) => eprintln!("Failed to start build: {}", e),
                        }
                    }
                    1 => {
                        // Runs submenu
                        runs_submenu(client, &theme, &workflow_id).await?;
                    }
                    2 => {
                        branch_idx = None;
                        continue;
                    }
                    _ => return Ok(()),
                }
            }
            if back_to_workflows {
                workflow_idx = None;
                continue;
            }
        }
    }
}

async fn runs_submenu(
    client: &AppStoreConnectClient,
    theme: &ColorfulTheme,
    workflow_id: &str,
) -> Result<()> {
    loop {
        let mut runs = {
            let pb = spinner("Loading runs...");
            let r = client.list_build_runs_for_workflow(workflow_id).await;
            pb.finish_and_clear();
            r
        }?;
        if runs.is_empty() {
            println!("No runs found");
            return Ok(());
        }
        runs.sort_by(compare_runs_desc);

        let mut items: Vec<String> = runs
            .iter()
            .map(|r| {
                let rid = resource_id(r);
                let status = pretty_run_status(r);
                let when = r
                    .get("attributes")
                    .and_then(|a| a.get("createdDate"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                if when.is_empty() {
                    format!("{} - {}", rid, status)
                } else {
                    format!("{} - {} - {}", rid, status, when)
                }
            })
            .collect();
        items.push("Back".into());
        items.push("Exit".into());
        let idx = Select::with_theme(theme)
            .with_prompt("Select a run")
            .default(0)
            .items(&items)
            .interact()?;
        if idx == items.len() - 1 {
            std::process::exit(0);
        }
        if idx == items.len() - 2 {
            break;
        }
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
            0 => {
                run_info_cmd(client, &run_id).await?;
            }
            1 => {
                run_artifacts_cmd(client, &run_id).await?;
            }
            2 => {
                run_test_results_cmd(client, &run_id).await?;
            }
            3 => continue, // back
            _ => return Ok(()),
        }
    }
    Ok(())
}
