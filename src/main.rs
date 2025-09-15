use anyhow::Result;
use xcloud::cli::run_cli;

#[tokio::main]
async fn main() -> Result<()> {
    run_cli().await
}
