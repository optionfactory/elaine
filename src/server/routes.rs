use crate::schema::{AdsResponsibility, AiActClass, CraClass, DoraCriticality, ExposureType, GdprRole, LifecycleType, Nis2Category, ProjectType, ServiceTier};
use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use axum_extra::extract::Query;
use serde::Deserialize;
use std::sync::Arc;

use super::auth::ValidatedUser;
use super::{AppState, FrontendAssets};

#[derive(Deserialize)]
pub struct ApiQuery {
    pub search: Option<String>,
    pub filter: Option<Vec<String>>,
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

pub async fn api_projects_handler(State(state): State<Arc<AppState>>, Query(query): Query<ApiQuery>, _auth: ValidatedUser) -> impl IntoResponse {
    let cache = state.cache.read().await;
    let term = query.search.as_deref().map(|s| s.to_lowercase());
    let filter_values = query.filter.unwrap_or_default();
    let filters: Vec<&str> = filter_values.iter().map(|s| s.as_str()).collect();

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
            matches_filters(p, &filters)
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

#[derive(Deserialize)]
pub struct LogQuery {
    pub repo: String,
    pub scanner: String,
}

/// Serves saved scanner failure logs from <data_dir>/stats/logs/<repo>/<scanner>.log.
/// Repo/scanner names are validated (no separators) to prevent path traversal.
pub async fn api_logs_handler(State(state): State<Arc<AppState>>, Query(query): Query<LogQuery>, _auth: ValidatedUser) -> impl IntoResponse {
    let is_safe = |s: &str| !s.is_empty() && !s.contains('/') && !s.contains('\\') && !s.contains("..");
    if !is_safe(&query.repo) || !is_safe(&query.scanner) {
        return (StatusCode::BAD_REQUEST, "Invalid repo or scanner").into_response();
    }
    let path = state
        .config
        .data_dir
        .join("stats")
        .join("logs")
        .join(&query.repo)
        .join(format!("{}.log", query.scanner));
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => ([(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], content).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Log not found").into_response(),
    }
}

pub fn create_router(app_state: Arc<AppState>, dev: bool) -> Router {
    let mut app = Router::new()
        .route("/api/config", get(api_config_handler))
        .route("/api/stats", get(api_stats_handler))
        .route("/api/projects", get(api_projects_handler))
        .route("/api/logs", get(api_logs_handler))
        .with_state(app_state);

    if dev {
        app = app.fallback_service(tower_http::services::ServeDir::new("src/frontend"));
    } else {
        app = app.fallback(get(embedded_assets_handler));
    }

    app
}

fn matches_filters(p: &crate::scanners::RepoStats, filters: &[&str]) -> bool {
    let live = !p.archived;
    let manifest = p.manifest.is_some();
    let public = !p.private;
    let has_vulns = p.vulnerabilities.as_ref().map(|v| !v.is_empty()).unwrap_or(false);
    let has_outdated = p.outdated_dependencies.as_ref().map(|v| !v.is_empty()).unwrap_or(false);

    if filters.contains(&"live") && !live {
        return false;
    }
    if filters.contains(&"archived") && live {
        return false;
    }
    if filters.contains(&"forked") && !p.fork {
        return false;
    }
    if filters.contains(&"disabled") && !p.disabled {
        return false;
    }
    if filters.contains(&"public") && !public {
        return false;
    }
    if filters.contains(&"private") && public {
        return false;
    }
    if filters.contains(&"manifest") && !manifest {
        return false;
    }
    if filters.contains(&"nomanifest") && manifest {
        return false;
    }
    if filters.contains(&"vulns") && !has_vulns {
        return false;
    }
    if filters.contains(&"no-vulns") && has_vulns {
        return false;
    }
    if filters.contains(&"outdated") && !has_outdated {
        return false;
    }
    if filters.contains(&"no-outdated") && has_outdated {
        return false;
    }

    if filters.contains(&"tier1") && !p.manifest.as_ref().is_some_and(|a| a.tier == Some(ServiceTier::Tier1)) {
        return false;
    }
    if filters.contains(&"tier2") && !p.manifest.as_ref().is_some_and(|a| a.tier == Some(ServiceTier::Tier2)) {
        return false;
    }
    if filters.contains(&"tier3") && !p.manifest.as_ref().is_some_and(|a| a.tier == Some(ServiceTier::Tier3)) {
        return false;
    }
    if filters.contains(&"tier4") && !p.manifest.as_ref().is_some_and(|a| a.tier == Some(ServiceTier::Tier4)) {
        return false;
    }

    if filters.contains(&"lifecycle-active") && !p.manifest.as_ref().is_some_and(|a| a.lifecycle == Some(LifecycleType::Active)) {
        return false;
    }
    if filters.contains(&"lifecycle-deprecated") && !p.manifest.as_ref().is_some_and(|a| a.lifecycle == Some(LifecycleType::Deprecated)) {
        return false;
    }
    if filters.contains(&"lifecycle-end-of-life") && !p.manifest.as_ref().is_some_and(|a| a.lifecycle == Some(LifecycleType::EndOfLife)) {
        return false;
    }
    if filters.contains(&"lifecycle-maintenance") && !p.manifest.as_ref().is_some_and(|a| a.lifecycle == Some(LifecycleType::Maintenance)) {
        return false;
    }
    if filters.contains(&"lifecycle-prototype") && !p.manifest.as_ref().is_some_and(|a| a.lifecycle == Some(LifecycleType::Prototype)) {
        return false;
    }
    if filters.contains(&"lifecycle-unmaintained") && !p.manifest.as_ref().is_some_and(|a| a.lifecycle == Some(LifecycleType::Unmaintained)) {
        return false;
    }

    let has_ingress = |exposure: ExposureType| {
        p.manifest
            .as_ref()
            .is_some_and(|a| a.environments.as_ref().is_some_and(|envs| envs.iter().any(|e| e.ingress == Some(exposure))))
    };

    if filters.contains(&"ingress-local") && !has_ingress(ExposureType::Local) {
        return false;
    }
    if filters.contains(&"ingress-restricted-vpn") && !has_ingress(ExposureType::RestrictedVpn) {
        return false;
    }
    if filters.contains(&"ingress-restricted-ip") && !has_ingress(ExposureType::RestrictedIp) {
        return false;
    }
    if filters.contains(&"ingress-restricted-pam") && !has_ingress(ExposureType::RestrictedPam) {
        return false;
    }
    if filters.contains(&"ingress-internet") && !has_ingress(ExposureType::Internet) {
        return false;
    }
    if filters.contains(&"ingress-none") && !has_ingress(ExposureType::None) {
        return false;
    }

    if filters.contains(&"service") && !p.manifest.as_ref().is_some_and(|a| a.project_type == Some(ProjectType::Service)) {
        return false;
    }
    if filters.contains(&"library") && !p.manifest.as_ref().is_some_and(|a| a.project_type == Some(ProjectType::Library)) {
        return false;
    }
    if filters.contains(&"tool") && !p.manifest.as_ref().is_some_and(|a| a.project_type == Some(ProjectType::Tool)) {
        return false;
    }
    if filters.contains(&"infrastructure") && !p.manifest.as_ref().is_some_and(|a| a.project_type == Some(ProjectType::Infrastructure)) {
        return false;
    }
    if filters.contains(&"documentation") && !p.manifest.as_ref().is_some_and(|a| a.project_type == Some(ProjectType::Documentation)) {
        return false;
    }

    if filters.contains(&"playground") && !p.manifest.as_ref().is_some_and(|a| a.project_type == Some(ProjectType::Playground)) {
        return false;
    }

    let compliant = p.manifest.as_ref().and_then(|a| a.compliance.as_ref()).map(|c| {
        c.ads != AdsResponsibility::PendingAssessment
            && c.ads != AdsResponsibility::PendingNomination
            && c.ai_act != AiActClass::PendingAssessment
            && c.cra != CraClass::PendingAssessment
            && c.dora != DoraCriticality::PendingAssessment
            && c.gdpr != GdprRole::PendingAssessment
            && c.nis2 != Nis2Category::PendingAssessment
    });

    if filters.contains(&"compliant") && compliant.is_none_or(|c| !c) {
        return false;
    }
    if filters.contains(&"non-compliant") && compliant.is_none_or(|c| c) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::GithubRepository;
    use crate::scanners::RepoStats;

    fn repo(audit_json: Option<&str>) -> RepoStats {
        let mut r = RepoStats::new_from_github(&GithubRepository {
            name: "x".into(),
            ..Default::default()
        });
        if let Some(json) = audit_json {
            r.manifest = Some(serde_json::from_str(json).unwrap());
        }
        r
    }

    #[test]
    fn ingress_filters_match_any_environment_ingress() {
        let exposed = repo(Some(
            r#"{ "schema_version": 1, "name": "x", "environments": [ { "name": "prod", "type": "production", "ingress": "internet" } ] }"#,
        ));
        assert!(matches_filters(&exposed, &["ingress-internet"]));
        assert!(!matches_filters(&exposed, &["ingress-local"]));
    }
}
