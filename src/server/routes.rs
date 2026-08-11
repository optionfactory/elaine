use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use serde::Deserialize;
use std::sync::Arc;

use super::{AppState, FrontendAssets, ValidatedUser};

#[derive(Deserialize)]
pub struct ApiQuery {
    pub search: Option<String>,
    pub filters: Option<String>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

pub async fn api_config_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "google_auth": state.config.google_auth,
        "organization": state.config.organization,
    }))
}

pub async fn api_stats_handler(State(state): State<Arc<AppState>>, _auth: ValidatedUser) -> impl IntoResponse {
    let cache = state.cache.read().await;
    Json(cache.stats.clone()).into_response()
}

pub async fn api_projects_handler(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ApiQuery>,
    _auth: ValidatedUser,
) -> impl IntoResponse {
    let cache = state.cache.read().await;
    let term = query.search.as_deref().map(|s| s.to_lowercase());
    let filters: Vec<&str> = query.filters.as_deref().unwrap_or("all").split(',').collect();

    let mut filtered: Vec<&crate::scanners::RepoStats> = cache
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
    let paginated: Vec<&crate::scanners::RepoStats> = filtered.into_iter().skip(offset).take(limit).collect();
    Json(paginated).into_response()
}

pub async fn embedded_assets_handler(uri: axum::http::Uri) -> impl IntoResponse {
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

pub fn create_router(app_state: Arc<AppState>, dev: bool) -> Router {
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

    app
}