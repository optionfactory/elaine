use anyhow::{Context, Result};
use clap::Parser;
use elaine::cli::{Cli, Commands};
use elaine::commands::Elaine;
use elaine::server::Config;
use std::fs;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config: Config = fs::read("elaine.conf.json")
        .context("Failed to read 'elaine.conf.json'")
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
        .context("Failed to parse 'elaine.conf.json'.")?;

    let app = Elaine::new(config)?;

    match cli.command {
        Commands::Serve { dev } => app.serve(dev).await?,
        Commands::Sync { force } => app.sync(force).await?,
        Commands::Scan => app.scan().await?,
        Commands::CleanRepositories => app.clean_repositories()?,
        Commands::CleanStats => app.clean_stats()?,
    }

    Ok(())
}
