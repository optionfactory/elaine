use crate::schema::{ExposureType, LifecycleType, ProjectType, ServiceTier};
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, put},
};
use axum_extra::extract::Query;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;

use super::login::{self, SignedIn};
use super::{AppState, CacheData, FrontendAssets};
use crate::images::{ImageScan, ImageSummary, ImageVulnerability};
use crate::scanners::RepoStats;
use crate::stats::StatsStore;

#[derive(Deserialize)]
pub struct ApiQuery {
    pub search: Option<String>,
    pub filter: Option<Vec<String>>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

pub async fn api_config_handler(State(state): State<Arc<AppState>>, signed_in: Option<Extension<SignedIn>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "organization": state.config.organization,
        "email": signed_in.map(|Extension(SignedIn(email))| email),
    }))
}

pub async fn api_stats_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cache = state.cache.read().await;
    Json(cache.stats.clone()).into_response()
}

/// Precalculated analytics for the governance/security/inventory pages.
/// Computed once per stats cache refresh (see Aggregates::calculate), not per request.
pub async fn api_aggregates_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cache = state.cache.read().await;
    Json(cache.aggregates.clone()).into_response()
}

#[derive(serde::Serialize)]
struct StalenessRow {
    name: String,
    html_url: String,
    pushed_at: String,
    months: i64,
    manifest: bool,
    #[serde(rename = "type")]
    project_type: Option<ProjectType>,
    tier: Option<ServiceTier>,
    lifecycle: Option<LifecycleType>,
}

/// Months since the last push for live repositories. Depends on the current time,
/// so it is computed per request instead of being cached with the aggregates.
pub async fn api_staleness_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    const MONTH_SECONDS: f64 = 30.44 * 24.0 * 3600.0;
    let cache = state.cache.read().await;
    let now = jiff::Timestamp::now();
    let mut rows: Vec<StalenessRow> = cache
        .projects
        .iter()
        .filter(|p| !p.archived && !p.pushed_at.is_empty())
        .filter_map(|p| {
            let pushed: jiff::Timestamp = p.pushed_at.parse().ok()?;
            let months = ((now - pushed).as_secs() as f64 / MONTH_SECONDS).floor() as i64;
            Some(StalenessRow {
                name: p.name.clone(),
                html_url: p.html_url.clone(),
                pushed_at: p.pushed_at.clone(),
                months,
                manifest: p.manifest.is_some(),
                project_type: p.manifest.as_ref().and_then(|m| m.project_type),
                tier: p.manifest.as_ref().and_then(|m| m.tier),
                lifecycle: p.manifest.as_ref().and_then(|m| m.lifecycle),
            })
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.months));
    Json(rows).into_response()
}

/// The generated JSON schema (schema/elaine-v1.schema.json, produced by build.rs from
/// the #[doc] comments in src/schema/manifest.rs). Compile-time static content.
pub async fn api_schema_handler() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        include_str!("../../schema/elaine-v1.schema.json"),
    )
}

pub async fn api_projects_handler(State(state): State<Arc<AppState>>, Query(query): Query<ApiQuery>) -> impl IntoResponse {
    let cache = state.cache.read().await;
    let term = query.search.as_deref().map(|s| s.to_lowercase());
    let filter_values = query.filter.unwrap_or_default();
    let filters: Vec<&str> = filter_values.iter().map(|s| s.as_str()).collect();

    let mut filtered: Vec<&RepoStats> = cache
        .projects
        .iter()
        .filter(|p| {
            if let Some(t) = &term
                && !searched_text(p).any(|text| text.to_lowercase().contains(t))
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

    let total = filtered.len();
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(5);
    let paginated: Vec<ProjectView> = filtered
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|repo| ProjectView::of(repo, &cache.images))
        .collect();
    ([(TOTAL_COUNT, total.to_string())], Json(paginated)).into_response()
}

/// A repository with what the last image scan found in each image it runs.
#[derive(serde::Serialize)]
struct ProjectView<'a> {
    #[serde(flatten)]
    repo: &'a RepoStats,
    images: Vec<ImageSummary>,
}

impl<'a> ProjectView<'a> {
    fn of(repo: &'a RepoStats, images: &BTreeMap<String, ImageScan>) -> Self {
        Self {
            repo,
            images: repo
                .containers
                .iter()
                .flatten()
                .map(|image| ImageSummary::of(image, images.get(image)))
                .collect(),
        }
    }
}

/// A repository as `/api/projects` lists it, plus what only its own page shows: the compliance frameworks still
/// pending and the vulnerabilities found in the images it runs.
#[derive(serde::Serialize)]
struct ProjectDetail<'a> {
    #[serde(flatten)]
    view: ProjectView<'a>,
    pending_frameworks: Vec<&'static str>,
    image_vulnerabilities: BTreeMap<&'a str, &'a [ImageVulnerability]>,
}

fn find_project<'a>(cache: &'a CacheData, name: &str) -> Option<ProjectDetail<'a>> {
    let repo = cache.projects.iter().find(|p| p.name == name)?;
    let compliance = repo.manifest.as_ref().and_then(|m| m.compliance.as_ref());
    Some(ProjectDetail {
        view: ProjectView::of(repo, &cache.images),
        pending_frameworks: super::aggregates::FRAMEWORKS
            .iter()
            .filter(|(_, is_pending)| compliance.is_some_and(is_pending))
            .map(|(framework, _)| *framework)
            .collect(),
        image_vulnerabilities: repo
            .containers
            .iter()
            .flatten()
            .filter_map(|image| match cache.images.get(image) {
                Some(ImageScan::Scanned { vulnerabilities }) if !vulnerabilities.is_empty() => Some((image.as_str(), vulnerabilities.as_slice())),
                _ => None,
            })
            .collect(),
    })
}

pub async fn api_project_handler(State(state): State<Arc<AppState>>, Path(name): Path<String>) -> impl IntoResponse {
    let cache = state.cache.read().await;
    match find_project(&cache, &name) {
        Some(project) => Json(project).into_response(),
        None => (StatusCode::NOT_FOUND, "No such repository").into_response(),
    }
}

/// What the search of the dashboard looks in: the name, the description, and from the manifest the stewards, the
/// commissioner and the domains of the environments.
fn searched_text(p: &RepoStats) -> impl Iterator<Item = &str> {
    let manifest = p.manifest.as_ref();
    std::iter::once(p.name.as_str())
        .chain(p.description.as_deref())
        .chain(manifest.into_iter().flat_map(|m| m.stewards.iter().flatten().map(String::as_str)))
        .chain(manifest.and_then(|m| m.commissioner.as_deref()))
        .chain(
            manifest
                .into_iter()
                .flat_map(|m| m.environments.iter().flatten())
                .flat_map(|environment| environment.domains.iter().flatten().map(String::as_str)),
        )
}

/// How many repositories match the search and the filters, whatever the page asked: the body stays a plain array.
const TOTAL_COUNT: &str = "x-total-count";

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
pub async fn api_logs_handler(State(state): State<Arc<AppState>>, Query(query): Query<LogQuery>) -> impl IntoResponse {
    if !StatsStore::is_safe_log_name(&query.repo) || !StatsStore::is_safe_log_name(&query.scanner) {
        return (StatusCode::BAD_REQUEST, "Invalid repo or scanner").into_response();
    }
    let path = state.stats.repo_logs_dir(&query.repo).join(format!("{}.log", query.scanner));
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => ([(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], content).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Log not found").into_response(),
    }
}

/// Everything is behind the login except the favicon (the browser tab and the monitoring), the pushes (their own
/// token) and the login itself.
pub fn create_router(app_state: Arc<AppState>, dev: bool) -> Router {
    let mut behind_login = Router::new()
        .route("/api/config", get(api_config_handler))
        .route("/api/stats", get(api_stats_handler))
        .route("/api/aggregates", get(api_aggregates_handler))
        .route("/api/staleness", get(api_staleness_handler))
        .route("/api/schema", get(api_schema_handler))
        .route("/api/projects", get(api_projects_handler))
        .route("/api/projects/{name}", get(api_project_handler))
        .route("/api/stewards/{name}", get(super::steward::api_steward_handler))
        .route("/api/logs", get(api_logs_handler));
    if dev {
        behind_login = behind_login.fallback_service(tower_http::services::ServeDir::new("src/frontend"));
    } else {
        behind_login = behind_login.fallback(get(embedded_assets_handler));
    }
    let behind_login = behind_login.layer(middleware::from_fn_with_state(Arc::clone(&app_state), login::require_session));

    let mut public = Router::new().route("/favicon.svg", get(embedded_assets_handler)).route(
        "/api/snapshot",
        put(crate::push::receive_snapshot_handler).layer(DefaultBodyLimit::max(64 * 1024 * 1024)),
    );
    if app_state.config.login.is_some() {
        public = public
            .route("/login", get(login::sign_in))
            .route("/oidc/callback", get(login::callback))
            .route("/logout", get(login::sign_out));
    }
    public.merge(behind_login).with_state(app_state)
}

fn matches_filters(p: &RepoStats, filters: &[&str]) -> bool {
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
    if filters.contains(&"ingress-restricted-geo-ip") && !has_ingress(ExposureType::RestrictedGeoIp) {
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

    let compliant = p
        .manifest
        .as_ref()
        .and_then(|a| a.compliance.as_ref())
        .map(|c| !super::aggregates::FRAMEWORKS.iter().any(|(_, is_pending)| is_pending(c)));

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

    #[test]
    fn ingress_filter_matches_restricted_geo_ip() {
        let geo = repo(Some(
            r#"{ "schema_version": 1, "name": "x", "environments": [ { "name": "prod", "type": "production", "ingress": "restricted-geo-ip" } ] }"#,
        ));
        let internet = repo(Some(
            r#"{ "schema_version": 1, "name": "x", "environments": [ { "name": "prod", "type": "production", "ingress": "internet" } ] }"#,
        ));
        assert!(matches_filters(&geo, &["ingress-restricted-geo-ip"]));
        assert!(!matches_filters(&internet, &["ingress-restricted-geo-ip"]));
    }

    #[test]
    fn pending_data_residency_is_non_compliant() {
        let pending = repo(Some(
            r#"{ "schema_version": 1, "name": "x", "compliance": { "dora": "non-critical", "cra": "default", "nis2": "out-of-scope", "ai_act": "out-of-scope", "gdpr": "controller", "data_residency": "pending-assessment", "ads": "internal" } }"#,
        ));
        assert!(matches_filters(&pending, &["non-compliant"]));
        assert!(!matches_filters(&pending, &["compliant"]));
    }

    #[test]
    fn a_project_is_found_by_name_with_its_pending_frameworks_and_image_vulnerabilities() {
        let mut x = repo(Some(
            r#"{ "schema_version": 1, "name": "x", "compliance": { "dora": "non-critical", "cra": "default", "nis2": "out-of-scope", "ai_act": "out-of-scope", "gdpr": "pending-assessment", "data_residency": "eu", "ads": "internal" } }"#,
        ));
        x.containers = Some(vec!["acme/nginx:257".into()]);
        let vulnerability = ImageVulnerability {
            package: "openssl".into(),
            version: "3.0".into(),
            fixed_in: "3.1".into(),
            severity: crate::images::Severity::High,
            vuln_id: "CVE-1".into(),
        };
        let cache = CacheData {
            projects: vec![x],
            images: BTreeMap::from([(
                "acme/nginx:257".to_string(),
                ImageScan::Scanned {
                    vulnerabilities: vec![vulnerability],
                },
            )]),
            stats: Default::default(),
            aggregates: Default::default(),
        };
        let found = find_project(&cache, "x").unwrap();
        assert_eq!(found.pending_frameworks, ["gdpr"]);
        assert_eq!(found.image_vulnerabilities["acme/nginx:257"].len(), 1);
        assert!(find_project(&cache, "y").is_none());
    }
}
