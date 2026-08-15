use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "elaine",
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
    #[command(about = "Sync repositories, scan them, then serve the dashboard")]
    Bootstrap {
        #[arg(long, help = "Serve frontend assets from the local filesystem instead of embedded binary")]
        dev: bool,
    },
    #[command(about = "Serve the dashboard and stats data over HTTP")]
    Serve {
        #[arg(long, help = "Serve frontend assets from the local filesystem instead of embedded binary")]
        dev: bool,
    },
    #[command(about = "Fetch repository metadata and cache .tar.gz archives from GitHub")]
    Sync {
        #[arg(
            long = "force",
            help = "Force re-downloading archives even if updated_at and pushed_at timestamps match"
        )]
        force: bool,
    },
    #[command(about = "Audit cached organization repositories for DevSecOps metadata & SBOMs")]
    Scan,
    #[command(about = "Remove cached per-repository scan data and the aggregated stats file")]
    CleanStats,

    #[command(about = "Remove cached repository metadata and .tar.gz archives")]
    CleanRepositories,

    #[command(about = "Create a stub elaine.yaml manifest in the current folder if it does not exist")]
    Init,
}
