use anyhow::{Context, Result};
use clap::Parser;
use repospect::cli::{Cli, Commands};
use repospect::commands::Repospect;
use repospect::server::Config;
use std::fs;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config: Config = fs::read("repospect.json")
        .context("Failed to read 'repospect.json'")
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
        .context("Failed to parse 'repospect.json'.")?;

    let app = Repospect::new(config)?;

    match cli.command {
        Commands::Serve { dev } => app.serve(dev).await?,
        Commands::Sync { force } => app.sync(force).await?,
        Commands::Scan => app.scan().await?,
        Commands::CleanRepositories => app.clean_repositories()?,
        Commands::CleanStats => app.clean_stats()?,
    }

    Ok(())
}
