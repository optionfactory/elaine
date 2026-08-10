use anyhow::{Context, Result};
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use repospect::cache::RepositoryCache;
use repospect::cli::{CacheCommands, Cli, Commands, DataCommands};
use repospect::data::DataStore;
use repospect::github::GithubClient;
use rust_embed::RustEmbed;
use std::collections::HashSet;
use std::fs;
use std::sync::Arc;
use tokio::sync::Semaphore;
use warp::Filter;
use warp::Reply;

#[derive(RustEmbed)]
#[folder = "frontend/"]
struct FrontendAssets;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Sync { force } => {
            let cache = Arc::new(RepositoryCache::new(&cli.cache_dir, &cli.organization)?);
            let client = Arc::new(GithubClient::new()?);
            eprintln!("Fetching repository list for organization '{}'...", cli.organization);
            let repos = client.fetch_org_repos(&cli.organization).await?;
            eprintln!("Checking for deleted repositories to remove from cache...");
            let current_repo_names: HashSet<&str> = repos.iter().map(|r| r.name.as_str()).collect();
            if let Ok(entries) = fs::read_dir(&cache.dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                        let repo_name = if file_name.ends_with(".json") {
                            file_name.strip_suffix(".json")
                        } else if file_name.ends_with(".tar.gz") {
                            file_name.strip_suffix(".tar.gz")
                        } else {
                            None
                        };
                        if let Some(name) = repo_name {
                            if !current_repo_names.contains(name) {
                                eprintln!("  🗑️ Removing orphaned cache file: {}", file_name);
                                let _ = fs::remove_file(&path);
                            }
                        }
                    }
                }
            }
            let total = repos.len() as u64;
            let m = MultiProgress::new();
            let main_pb = m.add(make_main_progress(total, "Downloading archives...".to_string()));
            let sem = Arc::new(Semaphore::new(2));
            let mut tasks = Vec::new();
            for repo in repos {
                let client = Arc::clone(&client);
                let cache = Arc::clone(&cache);
                let sem = Arc::clone(&sem);
                let org = cli.organization.clone();
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
                    let res = cache.sync_repo(&client, &org, &repo, force).await;
                    match res {
                        Ok(_) => {
                            task_pb.finish_and_clear();
                            main_pb_clone.inc(1);
                            Ok(())
                        }
                        Err(e) => {
                            task_pb.finish_and_clear();
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
        Commands::Scan => {
            let cache = Arc::new(RepositoryCache::new(&cli.cache_dir, &cli.organization)?);
            let data_store = Arc::new(DataStore::new(&cli.data_dir, &cli.organization)?);
            let repos = cache.load_all_metadata()?;
            let total = repos.len() as u64;
            let worker_count = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
            let sem = Arc::new(Semaphore::new(worker_count.max(1)));
            let m = MultiProgress::new();
            let main_pb = m.add(make_main_progress(
                total,
                format!("Scanning with {} workers...", worker_count),
            ));
            let mut tasks = Vec::new();
            for (_name, repo) in repos {
                let cache = Arc::clone(&cache);
                let data_store = Arc::clone(&data_store);
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
                    task_pb.finish_and_clear();
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
            eprintln!("Scan complete! Run `repospect aggregate` to generate the latest.json dashboard data.");
        }
        Commands::Aggregate => {
            let data_store = DataStore::new(&cli.data_dir, &cli.organization)?;
            eprintln!("Aggregating project scans for organization '{}'...", cli.organization);
            let latest_path = data_store.aggregate_scans()?;
            eprintln!("Successfully created aggregated data at {:?}", latest_path);
        }
        Commands::Serve { port, dev } => {
            let data_dir = cli.data_dir.clone();
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
                let frontend_route = warp::fs::dir("frontend");
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
                tokio::task::spawn_blocking(move || repospect::scanners::scan_repository(&repo_meta, &tar_path, None))
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

fn make_main_progress(total: u64, message: String) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
            .expect("Invalid progress bar template")
            .progress_chars("=>-"),
    );
    pb.set_message(message);
    pb
}
