use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use repospect::cli::{Cli, Commands, RepoCommands, StatsCommands};
use repospect::github::GithubClient;
use repospect::repositories::RepositoryStore;
use repospect::stats::StatsStore;
use rust_embed::RustEmbed;
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Semaphore;
use warp::Filter;
use warp::Reply;

#[derive(Deserialize)]
struct Config {
    github_token: Option<String>,
    organization: String,
    data_dir: PathBuf,
}

#[derive(RustEmbed)]
#[folder = "src/frontend/"]
struct FrontendAssets;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let worker_count = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let download_worker_count = worker_count.min(8);
    let config_data =
        fs::read_to_string("repospect.json").context("Failed to read 'repospect.json' in the current directory")?;
    let config: Config = serde_json::from_str(&config_data)
        .context("Failed to parse 'repospect.json'. Ensure it has github_token, organization, and data_dir fields.")?;

    match cli.command {
        Commands::Serve { port, dev } => {
            let data_dir = config.data_dir.clone();
            if !data_dir.exists() {
                anyhow::bail!("Data directory {:?} does not exist. Run a scan first.", data_dir);
            }
            let url = format!("http://localhost:{}", port);
            eprintln!("Serving dashboard from {:?} at {}", data_dir, url);
            if dev {
                eprintln!("Development mode enabled: Serving frontend assets from ./frontend/");
            } else {
                eprintln!("Serving embedded frontend assets.");
            }
            eprintln!("Press Ctrl+C to stop.");
            let data_route = warp::fs::dir(data_dir);
            if dev {
                let frontend_route = warp::fs::dir("src/frontend");
                let route = frontend_route.or(data_route);
                warp::serve(route).run(([127, 0, 0, 1], port)).await;
            } else {
                let embedded_frontend = warp::path::tail().and_then(|tail: warp::path::Tail| async move {
                    let path = if tail.as_str().is_empty() {
                        "index.html"
                    } else {
                        tail.as_str()
                    };
                    match FrontendAssets::get(path) {
                        Some(content) => {
                            let mime = mime_guess::from_path(path).first_or_octet_stream();
                            Ok(
                                warp::reply::with_header(content.data.into_owned(), "content-type", mime.as_ref())
                                    .into_response(),
                            )
                        }
                        None => Err(warp::reject::not_found()),
                    }
                });
                let route = embedded_frontend.or(data_route);
                warp::serve(route).run(([127, 0, 0, 1], port)).await;
            }
        }
        Commands::Repositories { command } => match command {
            RepoCommands::Sync { force } => {
                let repositories = Arc::new(RepositoryStore::new(&config.data_dir)?);
                let client = Arc::new(GithubClient::new(config.github_token, config.organization)?);
                
                eprintln!("Fetching repository list...");
                let repos = client.fetch_org_repos().await?;
                
                eprintln!("Checking for deleted repositories to remove from cache...");
                let current_repo_names: HashSet<&str> = repos.iter().map(|r| r.name.as_str()).collect();
                repositories.clean_orphans(&current_repo_names)?;

                let total = repos.len() as u64;
                let m = MultiProgress::new();

                let main_pb = m.add(ProgressBar::new(total));
                main_pb.set_style(
                    ProgressStyle::default_bar()
                        .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                        .expect("Invalid progress bar template")
                        .progress_chars("=>-"),
                );
                main_pb.set_message(format!("Downloading archives with {} workers...", download_worker_count));

                let sem = Arc::new(Semaphore::new(download_worker_count));
                let mut tasks = Vec::new();
                
                for repo in repos {
                    let client = Arc::clone(&client);
                    let cache = Arc::clone(&repositories);
                    let sem = Arc::clone(&sem);
                    let m_clone = m.clone();
                    let main_pb_clone = main_pb.clone();
                    
                    tasks.push(tokio::spawn(async move {
                        let _permit = sem.acquire().await.unwrap();
                        let task_pb = m_clone.add(ProgressBar::new_spinner());
                        task_pb.set_style(
                            ProgressStyle::default_spinner()
                                .template("{spinner:.blue} {msg}")
                                .unwrap(),
                        );
                        task_pb.enable_steady_tick(std::time::Duration::from_millis(100));
                        task_pb.set_message(format!("Syncing {}...", repo.name));
                        
                        let res = cache.sync_repo(&client, &repo, force).await;
                        m_clone.remove(&task_pb);

                        match res {
                            Ok(_) => {
                                main_pb_clone.inc(1);
                                Ok(())
                            }
                            Err(e) => {
                                main_pb_clone.println(format!("  [ERROR] {}: {}", repo.name, e));
                                main_pb_clone.inc(1);
                                Err(e)
                            }
                        }
                    }));
                }
                
                for t in tasks {
                    let _ = t.await?;
                }
                
                main_pb.finish_with_message("Sync complete!");
            }
            RepoCommands::Inspect { repository } => {
                let repositories = RepositoryStore::new(&config.data_dir)?;
                let tar_path = repositories.tarball_path(&repository);
                let meta_path = repositories.metadata_path(&repository);
                
                if !tar_path.exists() {
                    anyhow::bail!(
                        "Cached archive for repository '{}' not found at {:?}",
                        repository,
                        tar_path
                    );
                }
                
                let repo_meta = if meta_path.exists() {
                    let data = fs::read_to_string(&meta_path)?;
                    serde_json::from_str::<repospect::github::GithubRepository>(&data)?
                } else {
                    anyhow::bail!(
                        "Metadata file for repository '{}' not found at {:?}. Please run a sync first to fetch the repository metadata.",
                        repository,
                        meta_path
                    );
                };
                
                let report = tokio::task::spawn_blocking(move || {
                    repospect::scanners::scan_repository(&repo_meta, &tar_path, None)
                })
                .await??;
                
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            RepoCommands::Clean => {
                let repositories = RepositoryStore::new(&config.data_dir)?;
                repositories.clean_all().context("Failed to clean cache directory")?;
                eprintln!("Cleaned cache directory.");
            }
            RepoCommands::List => {
                let repositories = RepositoryStore::new(&config.data_dir)?;
                let repos = repositories.load_all_metadata()?;
                eprintln!("Cached repositories: {}", repos.len());
                for (name, _) in repos {
                    eprintln!("  - {}", name);
                }
            }
        },
        Commands::Stats { command } => match command {
            StatsCommands::Scan => {
                let repositories = Arc::new(RepositoryStore::new(&config.data_dir)?);
                let stats = Arc::new(StatsStore::new(&config.data_dir)?);
                let repos = repositories.load_all_metadata()?;
                let total = repos.len() as u64;
                let sem = Arc::new(Semaphore::new(worker_count.max(1)));
                let m = MultiProgress::new();
                
                // Add the bar FIRST to prevent double-rendering artifacts
                let main_pb = m.add(ProgressBar::new(total));
                main_pb.set_style(
                    ProgressStyle::default_bar()
                        .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                        .expect("Invalid progress bar template")
                        .progress_chars("=>-"),
                );
                main_pb.set_message(format!("Scanning with {} workers...", worker_count));
                
                let mut tasks = Vec::new();
                
                for (_name, repo) in repos {
                    let cache = Arc::clone(&repositories);
                    let data_store = Arc::clone(&stats);
                    let sem = Arc::clone(&sem);
                    let main_pb_clone = main_pb.clone();
                    let m_clone = m.clone();
                    
                    tasks.push(tokio::spawn(async move {
                        let _permit = sem.acquire().await.unwrap();
                        let repo_name = repo.name.clone();
                        
                        if data_store.is_scan_fresh(&repo_name, &repo.pushed_at) {
                            main_pb_clone.inc(1);
                            return Ok(());
                        }
                        
                        let task_pb = m_clone.add(ProgressBar::new_spinner());
                        task_pb.set_style(
                            ProgressStyle::default_spinner()
                                .template("{spinner:.magenta} {msg}")
                                .unwrap(),
                        );
                        task_pb.enable_steady_tick(std::time::Duration::from_millis(100));
                        task_pb.set_message(format!("[{}] Starting...", repo_name));
                        
                        let tar_path = cache.tarball_path(&repo_name);
                        
                        let result = if tar_path.exists() {
                            let pb_clone = task_pb.clone();
                            tokio::task::spawn_blocking(move || {
                                repospect::scanners::scan_repository(&repo, &tar_path, Some(pb_clone))
                            })
                            .await
                            .unwrap()
                        } else {
                            Err(anyhow::anyhow!("Tarball missing"))
                        };
                        
                        // Remove the spinner to prevent ghost lines from shifting the terminal
                        m_clone.remove(&task_pb);
                        main_pb_clone.inc(1);
                        
                        match result {
                            Ok(stat) => {
                                if let Err(e) = data_store.save_project_scan(&stat) {
                                    main_pb_clone.println(format!("  Failed to save scan for {}: {}", repo_name, e));
                                }
                                Ok(())
                            }
                            Err(e) => {
                                main_pb_clone.println(format!("  Failed to inspect {}: {}", repo_name, e));
                                Err(e)
                            }
                        }
                    }));
                }
                
                for task in tasks {
                    let _ = task.await?;
                }
                
                main_pb.finish_and_clear();
                eprintln!("Scan complete! Run `repospect stats aggregate` to generate the dashboard data.");
            }
            StatsCommands::Aggregate => {
                let stats_store = StatsStore::new(&config.data_dir)?;
                eprintln!("Aggregating project scans...");
                let latest_path = stats_store.aggregate_scans()?;
                eprintln!("Successfully created aggregated data at {:?}", latest_path);
            }
            StatsCommands::Clean => {
                let stats_store = StatsStore::new(&config.data_dir)?;
                stats_store.clean_all().context("Failed to clean stats directory")?;
                eprintln!("Cleaned stats directory.");
            }
            StatsCommands::List => {
                let data_store = StatsStore::new(&config.data_dir)?;
                let scans = data_store.list_scans()?;
                eprintln!("Data files: {}", scans.len());
                for (name, size) in scans {
                    eprintln!("  - {} ({} bytes)", name, size);
                }
            }
        },
    }
    Ok(())
}