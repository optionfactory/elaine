mod governance;
mod inventory;
mod security;

pub use governance::Governance;
pub use inventory::Inventory;
pub use security::Security;

use crate::scanners::RepoStats;
use crate::schema::{LifecycleType, ProjectType, ServiceTier};
use serde::Serialize;

/// Aggregated views for the analytics pages (governance, security, inventory).
///
/// Everything here is a pure function of the scan data, so it is precalculated
/// once whenever the stats cache is (re)loaded and served as-is by
/// `GET /api/aggregates`. Anything that depends on the current time
/// (e.g. staleness) or on presentation policy (colors, top-N slices)
/// lives elsewhere: request-time handlers or the frontend.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Aggregates {
    pub governance: Governance,
    pub security: Security,
    pub inventory: Inventory,
}

impl Aggregates {
    pub fn calculate(projects: &[RepoStats]) -> Self {
        let live: Vec<&RepoStats> = projects.iter().filter(|p| !p.archived).collect();
        Self {
            governance: Governance::calculate(&live),
            security: Security::calculate(&live),
            inventory: Inventory::calculate(&live),
        }
    }
}

/// The manifest metadata every per-repository row carries, in one place.
pub(crate) fn manifest_meta(p: &RepoStats) -> (Option<ProjectType>, Option<ServiceTier>, Option<LifecycleType>) {
    let m = p.manifest.as_ref();
    (m.and_then(|m| m.project_type), m.and_then(|m| m.tier), m.and_then(|m| m.lifecycle))
}

pub(crate) fn pct(part: usize, total: usize) -> u32 {
    if total == 0 {
        0
    } else {
        ((part as f64 / total as f64) * 100.0).round() as u32
    }
}

/// Operational weight of a service tier (tier1 heaviest). Also serves as a
/// descending sort key wherever tier order matters.
pub(crate) fn tier_weight(tier: ServiceTier) -> u32 {
    match tier {
        ServiceTier::Tier1 => 4,
        ServiceTier::Tier2 => 3,
        ServiceTier::Tier3 => 2,
        ServiceTier::Tier4 => 1,
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use crate::github::GithubRepository;
    use crate::scanners::RepoStats;

    pub(crate) fn repo(name: &str, archived: bool) -> RepoStats {
        RepoStats::new_from_github(&GithubRepository {
            name: name.into(),
            archived,
            ..Default::default()
        })
    }

    pub(crate) fn with_manifest(mut r: RepoStats, json: &str) -> RepoStats {
        r.manifest = Some(serde_json::from_str(json).unwrap());
        r
    }
}
