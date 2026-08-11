use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{FromRef, FromRequestParts, Query, State},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
    routing::get,
};
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use repospect::cli::{Cli, Commands};
use repospect::github::GithubClient;
use repospect::repositories::RepositoryStore;
use repospect::stats::StatsStore;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GoogleAuthConfig {
    pub client_id: String,
    pub hosted_domain: Option<String>,
}

#[derive(Deserialize, Clone)]
struct Config {
    github_token: Option<String>,
    organization: String,
    data_dir: PathBuf,
    google_auth: Option<GoogleAuthConfig>,
}

#[derive(Deserialize)]
struct ApiQuery {
    search: Option<String>,
    filters: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct DashboardStats {
    pub all: usize,
    pub live: usize,
    pub live_audited: usize,
    pub live_unaudited: usize,
    pub public: usize,
    pub live_public: usize,
    pub live_public_audited: usize,
    pub live_public_unaudited: usize,
    pub private: usize,
    pub live_private: usize,
    pub live_private_audited: usize,
    pub live_private_unaudited: usize,
    pub public_vulns: usize,
    pub public_audited_vulns: usize,
    pub public_unaudited_vulns: usize,
    pub private_vulns: usize,
    pub private_audited_vulns: usize,
    pub private_unaudited_vulns: usize,
}

impl DashboardStats {
    pub fn calculate(projects: &[repospect::scanners::RepoStats]) -> Self {
        let mut s = Self::default();

        for r in projects {
            s.all += 1;

            let (tot, live, aud, unaud, vul, aud_v, unaud_v) = match r.private {
                true => (
                    &mut s.private,
                    &mut s.live_private,
                    &mut s.live_private_audited,
                    &mut s.live_private_unaudited,
                    &mut s.private_vulns,
                    &mut s.private_audited_vulns,
                    &mut s.private_unaudited_vulns,
                ),
                false => (
                    &mut s.public,
                    &mut s.live_public,
                    &mut s.live_public_audited,
                    &mut s.live_public_unaudited,
                    &mut s.public_vulns,
                    &mut s.public_audited_vulns,
                    &mut s.public_unaudited_vulns,
                ),
            };

            *tot += 1;
            if r.archived {
                continue;
            }

            s.live += 1;
            *live += 1;

            let audited = r.audit.is_some();
            let has_vulns = r.vulnerabilities.as_ref().is_some_and(|v| !v.is_empty());

            if audited {
                s.live_audited += 1;
                *aud += 1;
            } else {
                s.live_unaudited += 1;
                *unaud += 1;
            }
            if has_vulns {
                *vul += 1;
                if audited {
                    *aud_v += 1;
                } else {
                    *unaud_v += 1;
                }
            }
        }

        s
    }
}

struct CacheData {
    projects: Vec<repospect::scanners::RepoStats>,
    stats: DashboardStats,
}

struct AppState {
    config: Config,
    jwks: Option<jsonwebtoken::jwk::JwkSet>,
    cache: Arc<RwLock<CacheData>>,
}

#[derive(RustEmbed)]
#[folder = "src/frontend/"]
struct FrontendAssets;

// --- Authentication Extractor ---

#[derive(Debug)]
struct AuthError(String);

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, self.0).into_response()
    }
}

struct ValidatedUser;

#[axum::async_trait]
impl<S> FromRequestParts<S> for ValidatedUser
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = Arc::<AppState>::from_ref(state);

        let google_auth = match &app_state.config.google_auth {
            Some(g) => g,
            None => return Ok(ValidatedUser),
        };

        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "));

        let token = match auth_header {
            Some(t) => t,
            None => return Err(AuthError("Missing Bearer token".into())),
        };

        let jwks = match app_state.jwks.as_ref() {
            Some(j) => j,
            None => return Err(AuthError("Google JWKS not loaded on server".into())),
        };

        let header = jsonwebtoken::decode_header(token).map_err(|_| AuthError("Invalid token header".into()))?;

        let kid = header.kid.ok_or_else(|| AuthError("Missing 'kid' in token header".into()))?;

        let jwk = jwks.find(&kid).ok_or_else(|| AuthError("Unknown 'kid'".into()))?;

        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk).map_err(|_| AuthError("Invalid JWK formatting".into()))?;

        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.set_audience(&[&google_auth.client_id]);
        validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);

        #[derive(Deserialize)]
        struct Claims {
            hd: Option<String>,
        }

        let token_data =
            jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation).map_err(|e| AuthError(format!("Invalid token: {}", e)))?;

        if let Some(expected_hd) = &google_auth.hosted_domain
            && token_data.claims.hd.as_deref() != Some(expected_hd.as_str())
        {
            return Err(AuthError(format!("Invalid organization domain. Expected {}", expected_hd)));
        }

        Ok(ValidatedUser)
    }
}


async fn api_config_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "google_auth": state.config.google_auth
    }))
}

async fn api_stats_handler(State(state): State<Arc<AppState>>, _auth: ValidatedUser) -> impl IntoResponse {
    let cache = state.cache.read().await;
    Json(cache.stats.clone()).into_response()
}

async fn api_projects_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ApiQuery>,
    _auth: ValidatedUser,
) -> impl IntoResponse {
    let cache = state.cache.read().await;

    let term = query.search.as_deref().map(|s| s.to_lowercase());
    let filters: Vec<&str> = query.filters.as_deref().unwrap_or("all").split(',').collect();

    let mut filtered: Vec<&repospect::scanners::RepoStats> = cache
        .projects
        .iter()
        .filter(|p| {
            if let Some(t) = &term
                && !p.name.to_lowercase().contains(t)
                && !p.description.to_lowercase().contains(t)
            {
                return false;
            }

            if filters.contains(&"all") {
                return true;
            }

            let live = !p.archived;
            let audited = p.audit.is_some();
            let public = !p.private;
            let has_vulns = p.vulnerabilities.as_ref().map(|v| !v.is_empty()).unwrap_or(false);

            if filters.contains(&"live") && !live {
                return false;
            }
            if filters.contains(&"audited") && !audited {
                return false;
            }
            if filters.contains(&"unaudited") && audited {
                return false;
            }
            if filters.contains(&"public") && !public {
                return false;
            }
            if filters.contains(&"private") && public {
                return false;
            }
            if filters.contains(&"vulns") && !has_vulns {
                return false;
            }

            true
        })
        .collect();

    if filters.contains(&"roulette") && !filtered.is_empty() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as usize)
            .unwrap_or(0);
        let pick_index = nanos % filtered.len();
        filtered = vec![filtered[pick_index]];
    }

    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(5);

    let paginated: Vec<&repospect::scanners::RepoStats> = filtered.into_iter().skip(offset).take(limit).collect();

    Json(paginated).into_response()
}

async fn embedded_assets_handler(uri: axum::http::Uri) -> impl IntoResponse {
    let mut path = uri.path().trim_start_matches('/');
    if path.is_empty() {
        path = "index.html";
    }

    match FrontendAssets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            ([(axum::http::header::CONTENT_TYPE, mime.as_ref())], content.data).into_response()
        }
        None => (StatusCode::NOT_FOUND, "404 Not Found").into_response(),
    }
}


#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let worker_count = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let download_worker_count = worker_count.min(8);

    let config_data = fs::read_to_string("repospect.json").context("Failed to read 'repospect.json' in the current directory")?;
    let config: Config = serde_json::from_str(&config_data)
        .context("Failed to parse 'repospect.json'. Ensure it has github_token, organization, and data_dir fields.")?;

    match cli.command {
        Commands::Serve { port, dev } => {
            let data_dir = config.data_dir.clone();
            if !data_dir.exists() {
                anyhow::bail!("Data directory {:?} does not exist. Run a scan first.", data_dir);
            }

            let mut jwks = None;
            if config.google_auth.is_some() {
                eprintln!("Fetching Google public keys...");
                match reqwest::get("https://www.googleapis.com/oauth2/v3/certs").await {
                    Ok(resp) => {
                        if let Ok(keys) = resp.json::<jsonwebtoken::jwk::JwkSet>().await {
                            eprintln!("Successfully loaded Google keys.");
                            jwks = Some(keys);
                        } else {
                            eprintln!("Failed to parse JWKS from Google.");
                        }
                    }
                    Err(e) => eprintln!("Failed to reach Google: {}", e),
                }
            }

            let stats_file = data_dir.join("stats.json");
            let initial_data = fs::read_to_string(&stats_file).unwrap_or_else(|_| "[]".to_string());
            let initial_projects: Vec<repospect::scanners::RepoStats> = serde_json::from_str(&initial_data).unwrap_or_default();

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
                        && let Ok(parsed) = serde_json::from_str::<Vec<repospect::scanners::RepoStats>>(&data)
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
                config: config.clone(),
                jwks,
                cache: projects_cache,
            });

            let mut app = Router::new()
                .route("/api/config", get(api_config_handler))
                .route("/api/stats", get(api_stats_handler))
                .route("/api/projects", get(api_projects_handler))
                .with_state(app_state);

            if dev {
                app = app.fallback_service(tower_http::services::ServeDir::new("src/frontend"));
            } else {
                app = app.fallback(get(embedded_assets_handler));
            }

            let url = format!("http://localhost:{}", port);
            eprintln!("Serving dashboard from {:?} at {}", data_dir, url);
            if dev {
                eprintln!("Development mode enabled: Serving frontend assets from ./src/frontend/");
            } else {
                eprintln!("Serving embedded frontend assets.");
            }
            eprintln!("Press Ctrl+C to stop.");

            let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
            axum::serve(listener, app).await?;
        }
        Commands::Sync { force } => {
            let repositories = Arc::new(RepositoryStore::new(&config.data_dir)?);
            let client = Arc::new(GithubClient::new(config.github_token, config.organization)?);

            let multiprogress = MultiProgress::new();
            let pb = multiprogress.add(ProgressBar::new(1));
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                    .expect("Invalid progress bar template")
                    .progress_chars("=>-"),
            );
            pb.set_message("Fetching repository list...");

            let repos = client.fetch_org_repos(&pb).await?;

            pb.set_message("Checking for deleted repositories to remove from cache...");
            let current_repo_names: HashSet<&str> = repos.iter().map(|r| r.name.as_str()).collect();
            repositories.clean_orphans(&current_repo_names)?;

            let total = repos.len() as u64;
            pb.reset();
            pb.set_length(total);
            pb.set_message(format!("Downloading archives with {} workers...", download_worker_count));

            let sem = Arc::new(Semaphore::new(download_worker_count));
            let mut tasks = Vec::new();

            for repo in repos {
                let client = Arc::clone(&client);
                let cache = Arc::clone(&repositories);
                let sem = Arc::clone(&sem);
                let m_clone = multiprogress.clone();
                let main_pb = pb.clone();

                tasks.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    let task_pb = m_clone.add(ProgressBar::new_spinner());
                    task_pb.set_style(ProgressStyle::default_spinner().template("{spinner:.blue} {msg}").unwrap());
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
                            main_pb.println(format!("  [ERROR] {}: {}", repo.name, e));
                            main_pb.inc(1);
                            Err(e)
                        }
                    }
                }));
            }

            for t in tasks {
                let _ = t.await?;
            }

            pb.finish_with_message("Sync complete!");
        }
        Commands::Scan => {
            let repositories = Arc::new(RepositoryStore::new(&config.data_dir)?);
            let stats = Arc::new(StatsStore::new(&config.data_dir)?);
            let repos = repositories.load_all_metadata()?;
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
                let cache = Arc::clone(&repositories);
                let data_store = Arc::clone(&stats);
                let sem = Arc::clone(&sem);
                let multiprogress = multiprogress.clone();
                let pb = pb.clone();

                tasks.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    let repo_name = repo.name.clone();

                    if data_store.is_scan_fresh(&repo_name, &repo.pushed_at) {
                        pb.inc(1);
                        return Ok(());
                    }

                    let task_pb = multiprogress.add(ProgressBar::new_spinner());
                    task_pb.set_style(ProgressStyle::default_spinner().template("{spinner:.magenta} {msg}").unwrap());
                    task_pb.enable_steady_tick(std::time::Duration::from_millis(100));
                    task_pb.set_message(format!("[{}] Starting...", repo_name));

                    let tar_path = cache.tarball_path(&repo_name);

                    let result = if tar_path.exists() {
                        let pb_clone = task_pb.clone();
                        tokio::task::spawn_blocking(move || repospect::scanners::scan_repository(&repo, &tar_path, Some(pb_clone)))
                            .await
                            .unwrap()
                    } else {
                        Err(anyhow::anyhow!("Tarball missing"))
                    };

                    multiprogress.remove(&task_pb);
                    pb.inc(1);

                    match result {
                        Ok(stat) => {
                            if let Err(e) = data_store.save_project_scan(&stat) {
                                pb.println(format!("  Failed to save scan for {}: {}", repo_name, e));
                            }
                            Ok(())
                        }
                        Err(e) => {
                            pb.println(format!("  Failed to inspect {}: {}", repo_name, e));
                            Err(e)
                        }
                    }
                }));
            }

            for task in tasks {
                let _ = task.await?;
            }

            pb.finish_and_clear();

            let latest_path = stats.aggregate_scans()?;
            eprintln!("Successfully created aggregated data at {:?}", latest_path);
        }
        Commands::CleanRepositories => {
            let repositories = RepositoryStore::new(&config.data_dir)?;
            repositories.clean_all().context("Failed to clean cache directory")?;
            eprintln!("Cleaned cache directory.");
        }
        Commands::CleanStats => {
            let stats = StatsStore::new(&config.data_dir)?;
            stats.clean_all().context("Failed to clean stats directory")?;
            eprintln!("Cleaned stats directory.");
        }
    }
    Ok(())
}
