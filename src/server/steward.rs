use super::AppState;
use super::aggregates::{FRAMEWORKS, manifest_meta, steward_name, tier_weight};
use crate::scanners::RepoStats;
use crate::schema::{ComplianceManifest, LifecycleType, ProjectType, ServiceTier};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Two steward entries name the same person when their names match ignoring case.
pub(crate) fn same_steward(a: &str, b: &str) -> bool {
    steward_name(a).to_lowercase() == steward_name(b).to_lowercase()
}

#[derive(Debug, Serialize)]
struct StewardPage<'a> {
    steward: String,
    /// How the manifests write this steward, archived repositories included.
    written_as: BTreeSet<&'a str>,
    /// Live repositories, highest tier first.
    repositories: Vec<StewardRepository<'a>>,
    /// The frameworks still pending on at least one of the live repositories.
    pending: Vec<PendingFramework<'a>>,
    /// Live repositories whose manifest has no compliance block.
    without_compliance: Vec<&'a str>,
}

#[derive(Debug, Serialize)]
struct StewardRepository<'a> {
    name: &'a str,
    html_url: &'a str,
    #[serde(rename = "type")]
    project_type: Option<ProjectType>,
    tier: Option<ServiceTier>,
    lifecycle: Option<LifecycleType>,
    /// `None` when no scanner checked the repository.
    vulnerabilities: Option<usize>,
    outdated: Option<usize>,
    pushed_at: &'a str,
}

#[derive(Debug, Serialize)]
struct PendingFramework<'a> {
    framework: &'static str,
    repositories: Vec<&'a str>,
}

fn find_steward<'a>(projects: &'a [RepoStats], steward: &str) -> Option<StewardPage<'a>> {
    let named = |p: &&'a RepoStats| p.manifest.iter().flat_map(|m| m.stewards.iter().flatten()).any(|s| same_steward(s, steward));
    let all: Vec<&RepoStats> = projects.iter().filter(named).collect();
    if all.is_empty() {
        return None;
    }
    let written_as: BTreeSet<&str> = all
        .iter()
        .flat_map(|p| p.manifest.iter().flat_map(|m| m.stewards.iter().flatten()))
        .filter(|s| same_steward(s, steward))
        .map(String::as_str)
        .collect();
    let mut live: Vec<&RepoStats> = all.into_iter().filter(|p| !p.archived).collect();
    let tier_order = |p: &RepoStats| std::cmp::Reverse(p.manifest.as_ref().and_then(|m| m.tier).map(tier_weight).unwrap_or(0));
    live.sort_by(|a, b| tier_order(a).cmp(&tier_order(b)).then_with(|| a.name.cmp(&b.name)));

    let compliance = |p: &'a RepoStats| -> Option<&'a ComplianceManifest> { p.manifest.as_ref().and_then(|m| m.compliance.as_ref()) };
    let pending = FRAMEWORKS
        .iter()
        .map(|(framework, is_pending)| PendingFramework {
            framework,
            repositories: live.iter().filter(|p| compliance(p).is_some_and(is_pending)).map(|p| p.name.as_str()).collect(),
        })
        .filter(|f| !f.repositories.is_empty())
        .collect();
    let without_compliance = live.iter().filter(|p| compliance(p).is_none()).map(|p| p.name.as_str()).collect();

    Some(StewardPage {
        steward: written_as
            .iter()
            .find(|w| !w.contains('@'))
            .map(|w| w.to_string())
            .unwrap_or_else(|| steward_name(steward)),
        written_as,
        repositories: live
            .iter()
            .map(|p| {
                let (project_type, tier, lifecycle) = manifest_meta(p);
                StewardRepository {
                    name: &p.name,
                    html_url: &p.html_url,
                    project_type,
                    tier,
                    lifecycle,
                    vulnerabilities: p.vulnerabilities.as_ref().map(Vec::len),
                    outdated: p.outdated_dependencies.as_ref().map(Vec::len),
                    pushed_at: &p.pushed_at,
                }
            })
            .collect(),
        pending,
        without_compliance,
    })
}

pub async fn api_steward_handler(State(state): State<Arc<AppState>>, Path(steward): Path<String>) -> impl IntoResponse {
    let cache = state.cache.read().await;
    match find_steward(&cache.projects, &steward) {
        Some(page) => Json(page).into_response(),
        None => (StatusCode::NOT_FOUND, "No repository names this steward").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::aggregates::testutil::{repo, with_manifest};

    #[test]
    fn an_email_names_the_same_steward_as_the_name_whatever_the_case() {
        assert!(same_steward("gabriele.gustin@optionfactory.net", "Gabriele Gustin"));
        assert!(same_steward("gabriele gustin", "GABRIELE.GUSTIN@example.com"));
        assert!(!same_steward("Gabriele Gustin", "Gabriele Gustini"));
    }

    #[test]
    fn a_steward_has_the_live_repositories_of_every_spelling_and_their_pending_frameworks() {
        let written_as_name = with_manifest(
            repo("svc", false),
            r#"{ "schema_version": 1, "name": "svc", "tier": "tier3", "stewards": ["Gabriele Gustin"], "compliance": { "dora": "non-critical", "cra": "default", "nis2": "out-of-scope", "ai_act": "out-of-scope", "gdpr": "pending-assessment", "data_residency": "eu", "ads": "internal" } }"#,
        );
        let written_as_email = with_manifest(
            repo("api", false),
            r#"{ "schema_version": 1, "name": "api", "tier": "tier1", "stewards": ["gabriele.gustin@optionfactory.net"] }"#,
        );
        let archived = with_manifest(repo("old", true), r#"{ "schema_version": 1, "name": "old", "stewards": ["Gabriele Gustin"] }"#);
        let projects = [written_as_name, written_as_email, archived];

        let page = find_steward(&projects, "gabriele.gustin@optionfactory.net").unwrap();
        assert_eq!(page.steward, "Gabriele Gustin");
        let names: Vec<_> = page.repositories.iter().map(|r| r.name).collect();
        assert_eq!(names, ["api", "svc"]);
        let pending: Vec<_> = page.pending.iter().map(|f| (f.framework, f.repositories.clone())).collect();
        assert_eq!(pending, [("gdpr", vec!["svc"])]);
        assert_eq!(page.without_compliance, ["api"]);
        assert!(find_steward(&projects, "Someone Else").is_none());
    }
}
