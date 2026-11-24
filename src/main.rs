use anyhow::{Context, Result};
use clap::Parser;
use elaine::app::Elaine;
use elaine::cli::{Cli, Commands};
use elaine::config::Config;
use std::fs;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Commands::Init = cli.command {
        return Elaine::init();
    }

    // it holds the push token, the login secret and the GitHub token: the group may read it, nobody else
    let mode = std::os::unix::fs::PermissionsExt::mode(&fs::metadata("elaine.conf.json").context("Failed to read 'elaine.conf.json'")?.permissions());
    if mode & 0o007 != 0 {
        anyhow::bail!(
            "'elaine.conf.json' can be read by every user of this machine (mode {:o}): chmod o-rwx elaine.conf.json",
            mode & 0o777
        );
    }
    let config: Config = fs::read("elaine.conf.json")
        .context("Failed to read 'elaine.conf.json'")
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
        .context("Failed to parse 'elaine.conf.json'.")?;

    let app = Elaine::new(config)?;

    match cli.command {
        Commands::Bootstrap { dev } => app.bootstrap(dev).await?,
        Commands::Serve { dev } => app.serve(dev).await?,
        Commands::Sync { force } => app.sync(force).await?,
        Commands::Scan => app.scan().await?,
        Commands::Push => app.push().await?,
        Commands::CleanRepositories => app.clean_repositories()?,
        Commands::CleanStats => app.clean_stats()?,
        Commands::Init => unreachable!(),
    }

    Ok(())
}
