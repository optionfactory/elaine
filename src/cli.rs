use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "repospect",
    version,
    about = "Multi-ecosystem repository, archive, and DevSecOps SBOM inspector",
    infer_subcommands = true
)]
pub struct Cli {
    #[arg(
        short = 'o',
        long = "organization",
        default_value = "optionfactory",
        global = true,
        help = "GitHub organization name"
    )]
    pub organization: String,

    #[arg(
        short = 'c',
        long = "cache-dir",
        default_value = "cache",
        global = true,
        help = "Directory to store cached repository tarballs and metadata"
    )]
    pub cache_dir: PathBuf,

    #[arg(
        short = 'd',
        long = "data-dir",
        default_value = "data",
        global = true,
        help = "Directory to store stats data"
    )]
    pub data_dir: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Fetch repository metadata and cache .tar.gz archives from GitHub")]
    Sync {
        #[arg(
            long = "force",
            help = "Force re-downloading archives even if pushed_at timestamps match"
        )]
        force: bool,
    },
    #[command(about = "Audit cached organization repositories for DevSecOps metadata & SBOMs")]
    Scan,
    #[command(about = "Aggregate individual project scans into a unified latest.json")]
    Aggregate,
    #[command(about = "Serve the dashboard and stats data over HTTP")]
    Serve {
        #[arg(short, long, default_value_t = 8000, help = "Port to serve the dashboard on")]
        port: u16,
    },
    #[command(about = "Inspect a single local filesystem directory or .tar.gz archive directly")]
    Inspect {
        #[arg(short = 'r', long = "repository", help = "Repository name to inspect")]
        repository: String,
    },
    #[command(about = "Manage the local tarball and metadata cache")]
    Cache {
        #[command(subcommand)]
        command: CacheCommands,
    },
    #[command(about = "Manage the local stats data")]
    Data {
        #[command(subcommand)]
        command: DataCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum CacheCommands {
    #[command(about = "Remove cached archives for a specific organization or wipe the entire cache")]
    Clean,
    #[command(about = "List cached repositories and size usage")]
    List,
}

#[derive(Subcommand, Debug)]
pub enum DataCommands {
    #[command(about = "Remove the stats archives for a specific organization or wipe the entire data directory")]
    Clean,
    #[command(about = "List data repositories and size usage")]
    List,
}
