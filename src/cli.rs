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

        #[arg(
            long,
            help = "Serve frontend assets from the local filesystem instead of embedded binary"
        )]
        dev: bool,
    },
    #[command(about = "Manage the local tarball and metadata cache")]
    Repositories {
        #[command(subcommand)]
        command: RepoCommands,
    },
    #[command(about = "Manage the local stats data")]
    Stats {
        #[command(subcommand)]
        command: StatsCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum RepoCommands {
    #[command(about = "Fetch repository metadata and cache .tar.gz archives from GitHub")]
    Sync {
        #[arg(
            long = "force",
            help = "Force re-downloading archives even if pushed_at timestamps match"
        )]
        force: bool,
    },
    #[command(about = "Remove cached archives for a specific organization or wipe the entire cache")]
    Clean,
    #[command(about = "List cached repositories and size usage")]
    List,
    #[command(about = "Inspect a single local filesystem directory or .tar.gz archive directly")]
    Inspect {
        #[arg(short = 'r', long = "repository", help = "Repository name to inspect")]
        repository: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum StatsCommands {
    #[command(about = "Remove the stats archives for a specific organization or wipe the entire data directory")]
    Clean,
    #[command(about = "List data repositories and size usage")]
    List,
    #[command(about = "Audit cached organization repositories for DevSecOps metadata & SBOMs")]
    Scan,
    #[command(about = "Aggregate individual project scans into a unified latest.json")]
    Aggregate,
}
