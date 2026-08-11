use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "repospect",
    version,
    about = "Multi-ecosystem repository, archive, and DevSecOps SBOM inspector",
    infer_subcommands = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Serve the dashboard and stats data over HTTP")]
    Serve {
        #[arg(short, long, default_value_t = 8000, help = "Port to serve the dashboard on")]
        port: u16,
        #[arg(long, help = "Serve frontend assets from the local filesystem instead of embedded binary")]
        dev: bool,
    },
    #[command(about = "Fetch repository metadata and cache .tar.gz archives from GitHub")]
    Sync {
        #[arg(long = "force", help = "Force re-downloading archives even if pushed_at timestamps match")]
        force: bool,
    },
    #[command(about = "Audit cached organization repositories for DevSecOps metadata & SBOMs")]
    Scan,
    #[command(about = "Remove the stats archives for a specific organization or wipe the entire data directory")]
    CleanStats,

    #[command(about = "Remove cached archives for a specific organization or wipe the entire cache")]
    CleanRepositories,
}
