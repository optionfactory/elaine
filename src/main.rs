use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use repospect::cache::RepositoryCache;
use repospect::cli::{CacheCommands, Cli, Commands, DataCommands};
use repospect::data::DataStore;
use repospect::github::GithubClient;
use std::fs;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Sync { force } => {
            let cache = Arc::new(RepositoryCache::new(&cli.cache_dir, &cli.organization)?);
            let client = Arc::new(GithubClient::new()?);

            eprintln!("Fetching repository list for organization '{}'...", cli.organization);
            let repos = client.fetch_org_repos(&cli.organization).await?;
            let total = repos.len() as u64;

            let progress = make_progress(total, "Downloading repository archives...".to_string());
            let sem = Arc::new(Semaphore::new(2));
            let mut tasks = Vec::new();

            for repo in repos {
                let client = Arc::clone(&client);
                let cache = Arc::clone(&cache);
                let sem = Arc::clone(&sem);
                let pb = Arc::clone(&progress);
                let org = cli.organization.clone();

                tasks.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    let res = cache.sync_repo(&client, &org, &repo, force).await;

                    match res {
                        Ok(_status) => {
                            pb.inc(1);
                            Ok(())
                        }
                        Err(e) => {
                            pb.println(format!("[ERROR] {}: {}", repo.name, e));
                            pb.inc(1);
                            Err(e)
                        }
                    }
                }));
            }

            for t in tasks {
                let _ = t.await?;
            }

            progress.finish_with_message("Sync complete!");
        }

        Commands::Scan => {
            let cache = Arc::new(RepositoryCache::new(&cli.cache_dir, &cli.organization)?);
            let repos = cache.load_all_metadata()?;
            let total = repos.len() as u64;
            let worker_count = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
            let sem = Arc::new(Semaphore::new(worker_count.max(1)));
            let progress = make_progress(
                total,
                format!("Scanning repositories using {} workers...", worker_count),
            );
            let mut tasks = Vec::new();
            for (_name, repo) in repos {
                let cache = Arc::clone(&cache);
                let sem = Arc::clone(&sem);
                let pb = Arc::clone(&progress);
                tasks.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    let repo_name = repo.name.clone();
                    let tar_path = cache.tarball_path(&repo_name);
                    let result = if tar_path.exists() {
                        tokio::task::spawn_blocking(move || repospect::scanners::scan_repository(&repo, &tar_path))
                            .await
                            .unwrap()
                    } else {
                        Err(anyhow::anyhow!("Tarball missing for repo: {}", repo_name))
                    };
                    pb.inc(1);
                    match result {
                        Ok(stat) => Some(stat),
                        Err(e) => {
                            pb.println(format!("Warning: failed to inspect {}: {}", repo_name, e));
                            None
                        }
                    }
                }));
            }
            let mut stats_list = Vec::with_capacity(total as usize);
            for task in tasks {
                if let Ok(Some(stat)) = task.await {
                    stats_list.push(stat);
                }
            }
            stats_list.sort_by(|a, b| a.name.cmp(&b.name));
            progress.finish_and_clear();

            let data_store = DataStore::new(&cli.data_dir, &cli.organization)?;
            let saved_path = data_store.save_scan(&stats_list)?;
            eprintln!("Saved scan snapshot to {:?}", saved_path);

            println!("{}", serde_json::to_string_pretty(&stats_list)?);
        }

        Commands::Inspect { repository } => {
            let cache = RepositoryCache::new(&cli.cache_dir, &cli.organization)?;
            let tar_path = cache.tarball_path(&repository);
            let meta_path = cache.metadata_path(&repository);

            if !tar_path.exists() {
                anyhow::bail!(
                    "Cached archive for repository '{}/{}' not found at {:?}",
                    cli.organization,
                    repository,
                    tar_path
                );
            }

            let repo_meta = if meta_path.exists() {
                let data = fs::read_to_string(&meta_path)?;
                serde_json::from_str::<repospect::github::GithubRepository>(&data)?
            } else {
                repospect::github::GithubRepository {
                    name: repository.clone(),
                    default_branch: "main".to_string(),
                    created_at: String::new(),
                    updated_at: String::new(),
                    pushed_at: String::new(),
                    archived: false,
                    fork: false,
                    disabled: false,
                    private: true,
                    description: Some(format!("{}/{}", cli.organization, repository)),
                }
            };

            let report =
                tokio::task::spawn_blocking(move || repospect::scanners::scan_repository(&repo_meta, &tar_path))
                    .await??;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }

        Commands::Cache { command } => match command {
            CacheCommands::Clean => {
                let target_dir = cli.cache_dir.join(cli.organization);
                if target_dir.exists() {
                    fs::remove_dir_all(&target_dir).with_context(|| format!("Failed to remove {:?}", target_dir))?;
                    eprintln!("Cleaned cache directory: {:?}", target_dir);
                } else {
                    eprintln!("Cache directory {:?} is already clean.", target_dir);
                }
            }
            CacheCommands::List => {
                let cache = RepositoryCache::new(&cli.cache_dir, &cli.organization)?;
                let repos = cache.load_all_metadata()?;
                eprintln!("Cached repositories for '{}': {}", cli.organization, repos.len());
                for (name, _) in repos {
                    eprintln!("  - {}", name);
                }
            }
        },

        Commands::Data { command } => match command {
            DataCommands::Clean => {
                let target_dir = cli.data_dir.join(&cli.organization);
                if target_dir.exists() {
                    fs::remove_dir_all(&target_dir).with_context(|| format!("Failed to remove {:?}", target_dir))?;
                    eprintln!("Cleaned data directory: {:?}", target_dir);
                } else {
                    eprintln!("Data directory {:?} is already clean.", target_dir);
                }
            }
            DataCommands::List => {
                let data_store = DataStore::new(&cli.data_dir, &cli.organization)?;
                let scans = data_store.list_scans()?;
                eprintln!("Data files for '{}': {}", cli.organization, scans.len());
                for (name, size) in scans {
                    eprintln!("  - {} ({} bytes)", name, size);
                }
            }
        },
    }

    Ok(())
}

fn make_progress(total: u64, message: String) -> Arc<ProgressBar> {
    let pb = Arc::new(ProgressBar::new(total));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .expect("Invalid progress bar template")
            .progress_chars("=>-"),
    );
    pb.set_message(message);
    pb
}
