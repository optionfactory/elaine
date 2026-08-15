use crate::config::Config;
use crate::github::{GithubClient, GithubRepository};
use crate::repo_cache::RepositoryStore;
use crate::server::{AppState, CacheData, DashboardStats};
use crate::stats::StatsStore;
use anyhow::{Context, Result};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::fs;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};

pub struct Elaine {
    config: Config,
    repositories: Arc<RepositoryStore>,
    stats: Arc<StatsStore>,
}

impl Elaine {
    pub fn new(config: Config) -> Result<Self> {
        let repositories = Arc::new(RepositoryStore::new(&config.data_dir)?);
        let stats = Arc::new(StatsStore::new(&config.data_dir)?);

        Ok(Self { config, repositories, stats })
    }

    pub async fn bootstrap(&self, dev: bool) -> Result<()> {
        eprintln!("[Bootstrap] Syncing repositories...");
        self.sync(false).await?;
        eprintln!("[Bootstrap] Scanning repositories...");
        self.scan().await?;
        eprintln!("[Bootstrap] Starting server...");
        self.serve(dev).await
    }

    pub async fn serve(&self, dev: bool) -> Result<()> {
        let address = self.config.address.as_deref().unwrap_or("127.0.0.1");
        let port = self.config.port.unwrap_or(8000);
        let stats_file = self.config.data_dir.join("stats.json");
        if !stats_file.exists() {
            anyhow::bail!("Stats file {:?} does not exist. Run 'elaine scan' first.", stats_file);
        }

        let jwks = if self.config.google_auth.is_some() {
            eprintln!("Fetching Google public keys...");
            let keys = crate::server::auth::fetch_jwks(&reqwest::Client::new())
                .await
                .context("Failed to fetch Google JWKS")?;
            eprintln!("Successfully loaded Google keys.");
            Some(Arc::new(crate::server::auth::JwksCache::new(keys)))
        } else {
            None
        };

        let initial_data = fs::read_to_string(&stats_file).unwrap_or_else(|_| "[]".to_string());
        let initial_projects: Vec<crate::scanners::RepoStats> = serde_json::from_str(&initial_data).unwrap_or_default();
        let initial_stats = DashboardStats::calculate(&initial_projects);

        let projects_cache = Arc::new(RwLock::new(CacheData {
            projects: initial_projects,
            stats: initial_stats,
        }));

        let bg_projects_cache = Arc::clone(&projects_cache);

        tokio::spawn(async move {
            let mut last_mtime = tokio::fs::metadata(&stats_file)
                .await
                .and_then(|m| m.modified())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));

            loop {
                interval.tick().await;
                if let Ok(meta) = tokio::fs::metadata(&stats_file).await
                    && let Ok(mtime) = meta.modified()
                    && mtime != last_mtime
                    && let Ok(data) = tokio::fs::read_to_string(&stats_file).await
                    && let Ok(parsed) = serde_json::from_str::<Vec<crate::scanners::RepoStats>>(&data)
                {
                    let new_stats = DashboardStats::calculate(&parsed);
                    let mut w = bg_projects_cache.write().await;
                    w.projects = parsed;
                    w.stats = new_stats;
                    last_mtime = mtime;
                    eprintln!("[Background] Detected stats.json change. Recalculated stats and reloaded memory.");
                }
            }
        });

        let app_state = Arc::new(AppState {
            config: self.config.clone(),
            http_client: reqwest::Client::new(),
            jwks,
            cache: projects_cache,
        });

        let app = crate::server::routes::create_router(app_state, dev);

        let url = format!("http://localhost:{}", port);
        eprintln!("Serving dashboard from {:?} at {}", self.config.data_dir, url);
        if dev {
            eprintln!("Development mode enabled: Serving frontend assets from ./src/frontend/");
        } else {
            eprintln!("Serving embedded frontend assets.");
        }
        let listener = tokio::net::TcpListener::bind((address, port)).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }

    pub async fn sync(&self, force: bool) -> Result<()> {
        let download_worker_count = get_worker_count().min(8);
        let client = Arc::new(GithubClient::new(self.config.github_token.clone(), self.config.organization.clone())?);

        let multiprogress = MultiProgress::new();
        let pb = multiprogress.add(ProgressBar::new(1));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                .expect("Invalid progress bar template")
                .progress_chars("=>-"),
        );
        pb.set_message("Fetching repository list...");

        let repos = self.fetch_all_repos(&client, &pb).await?;

        pb.set_message("Checking for renamed repositories...");
        let cached_by_id: std::collections::HashMap<u64, String> = self
            .repositories
            .load_all_metadata()?
            .into_values()
            .filter(|r| r.id != 0)
            .map(|r| (r.id, r.name))
            .collect();
        for repo in &repos {
            if let Some(old_name) = cached_by_id.get(&repo.id)
                && *old_name != repo.name
            {
                pb.println(format!("[{}] 🔁 Repository renamed from '{}'; removing stale scan data.", repo.name, old_name));
                if let Err(e) = self.stats.remove_project_scan(old_name) {
                    pb.println(format!("[{}] 🔥 Failed to remove scan for '{}': {}", repo.name, old_name, e));
                }
            }
        }

        pb.set_message("Checking for deleted repositories to remove from cache...");
        let current_repo_names: HashSet<&str> = repos.iter().map(|r| r.name.as_str()).collect();
        self.repositories.clean_orphans(&current_repo_names)?;

        let total = repos.len() as u64;
        pb.reset();
        pb.set_length(total);
        pb.set_message(format!("Downloading archives with {} workers...", download_worker_count));

        let sem = Arc::new(Semaphore::new(download_worker_count));
        let mut tasks = Vec::new();

        for repo in repos {
            let client = Arc::clone(&client);
            let cache = Arc::clone(&self.repositories);
            let sem = Arc::clone(&sem);
            let m_clone = multiprogress.clone();
            let main_pb = pb.clone();

            tasks.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore closed");
                let task_pb = m_clone.add(ProgressBar::new_spinner());
                task_pb.set_style(
                    ProgressStyle::default_spinner()
                        .template("{spinner:.blue} {msg}")
                        .expect("invalid spinner template"),
                );
                task_pb.enable_steady_tick(std::time::Duration::from_millis(100));
                task_pb.set_message(format!("Syncing {}...", repo.name));

                let res = cache.sync_repo(&client, &repo, force).await;

                m_clone.remove(&task_pb);

                match res {
                    Ok(_) => {
                        main_pb.inc(1);
                        Ok(())
                    }
                    Err(e) => {
                        main_pb.println(format!("[{}] 🔥 Sync failed: {}", repo.name, e));
                        main_pb.inc(1);
                        Err(e)
                    }
                }
            }));
        }

        let mut failures = 0;
        for t in tasks {
            if !matches!(t.await, Ok(Ok(()))) {
                failures += 1;
            }
        }

        if failures > 0 {
            pb.println(format!("🔥 {failures} repo(s) failed during sync (see errors above)."));
        }
        pb.finish_with_message("Sync complete!");
        if failures > 0 {
            anyhow::bail!("sync completed with failures");
        }
        Ok(())
    }

    async fn fetch_all_repos(&self, client: &GithubClient, pb: &ProgressBar) -> Result<Vec<GithubRepository>> {
        use futures::stream::{self, StreamExt};

        const PER_PAGE: usize = 100;
        let max_concurrent = get_worker_count().min(8);

        let mut all_repos = Vec::new();
        let mut next_page = 1;

        loop {
            let batch_size = match all_repos.is_empty() {
                true => max_concurrent,
                false => 1,
            };
            let pages: Vec<usize> = (next_page..next_page + batch_size).collect();
            next_page += batch_size;

            pb.set_message(format!("Fetching pages {}-{}...", pages.first().unwrap_or(&1), pages.last().unwrap_or(&1)));

            let results: Vec<anyhow::Result<Vec<GithubRepository>>> = stream::iter(pages)
                .map(|page| async move { client.fetch_org_repos_page(page).await })
                .buffered(max_concurrent)
                .collect()
                .await;

            let mut short_page = false;
            for result in results {
                let repos = result?;
                if repos.len() < PER_PAGE {
                    short_page = true;
                }
                pb.inc(repos.len() as u64);
                all_repos.extend(repos);
            }
            pb.set_message(format!("{} repositories found so far...", all_repos.len()));

            if short_page {
                break;
            }
        }

        Ok(all_repos)
    }

    pub async fn scan(&self) -> Result<()> {
        let worker_count = get_worker_count();
        let repos = self.repositories.load_all_metadata()?;
        let current_repo_names: HashSet<&str> = repos.keys().map(|s| s.as_str()).collect();
        self.stats.clean_orphans(&current_repo_names)?;
        let total = repos.len() as u64;

        let sem = Arc::new(Semaphore::new(worker_count.max(1)));
        let multiprogress = MultiProgress::new();
        let pb = multiprogress.add(ProgressBar::new(total));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                .expect("Invalid progress bar template")
                .progress_chars("=>-"),
        );
        pb.set_message(format!("Scanning with {} workers...", worker_count));

        let mut tasks = Vec::new();

        for (_name, repo) in repos {
            let cache = Arc::clone(&self.repositories);
            let data_store = Arc::clone(&self.stats);
            let sem = Arc::clone(&sem);
            let multiprogress = multiprogress.clone();
            let pb = pb.clone();

            tasks.push(tokio::spawn(async move {
                let _permit = sem.acquire().await.expect("semaphore closed");
                let repo_name = repo.name.clone();

                if data_store.is_scan_fresh(&repo_name, &repo.updated_at, &repo.pushed_at) {
                    pb.inc(1);
                    return Ok(());
                }

                let task_pb = multiprogress.add(ProgressBar::new_spinner());
                task_pb.set_style(
                    ProgressStyle::default_spinner()
                        .template("{spinner:.magenta} {msg}")
                        .expect("invalid spinner template"),
                );
                task_pb.enable_steady_tick(std::time::Duration::from_millis(100));
                task_pb.set_message(format!("[{}] Starting...", repo_name));

                let tar_path = cache.tarball_path(&repo_name);

                let result: anyhow::Result<crate::scanners::RepoStats> = if tar_path.exists() {
                    let pb_clone = task_pb.clone();
                    let logs_dir = data_store.repo_logs_dir(&repo_name);
                    tokio::task::spawn_blocking(move || crate::scanners::scan_repository(&repo, &tar_path, Some(pb_clone), Some(&logs_dir)))
                        .await
                        .context("scanner task failed")?
                } else {
                    Err(anyhow::anyhow!("Tarball missing"))
                };

                multiprogress.remove(&task_pb);
                pb.inc(1);

                match result {
                    Ok(stat) => {
                        if let Err(e) = data_store.save_project_scan(&stat) {
                            pb.println(format!("[{}] 🔥 Failed to save scan: {}", repo_name, e));
                        }
                        Ok(())
                    }
                    Err(e) => {
                        pb.println(format!("[{}] 🔥 Failed to inspect: {}", repo_name, e));
                        Err(e)
                    }
                }
            }));
        }

        let mut failures = 0;
        for task in tasks {
            if !matches!(task.await, Ok(Ok(()))) {
                failures += 1;
            }
        }

        if failures > 0 {
            pb.println(format!("🔥 {failures} repo(s) failed during scan (see errors above)."));
        }
        let latest_path = self.stats.aggregate_scans()?;
        pb.println(format!("Successfully created aggregated data at {:?}", latest_path));
        pb.finish_and_clear();
        if failures > 0 {
            anyhow::bail!("scan completed with failures");
        }
        Ok(())
    }

    pub fn clean_repositories(&self) -> Result<()> {
        self.repositories.clean_all().context("Failed to clean cache directory")?;
        eprintln!("Cleaned cache directory.");
        Ok(())
    }

    pub fn clean_stats(&self) -> Result<()> {
        self.stats.clean_all().context("Failed to clean stats directory")?;
        eprintln!("Cleaned stats directory.");
        Ok(())
    }

    pub fn init() -> Result<()> {
        let path = std::path::Path::new("elaine.yaml");
        if path.exists() {
            anyhow::bail!("elaine.yaml already exists in the current folder");
        }
        let name = std::env::current_dir()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "my-project".to_string());
        let manifest = include_str!("elaine.prototype.yaml").replace("{name}", &name);
        std::fs::write(path, manifest).context("Failed to write elaine.yaml")?;
        eprintln!("Created elaine.yaml stub in the current folder.");
        Ok(())
    }
}

fn get_worker_count() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
}
