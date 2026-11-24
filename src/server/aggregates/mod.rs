mod governance;
mod inventory;
mod security;

pub(crate) use governance::FRAMEWORKS;
pub use governance::Governance;
pub use inventory::Inventory;
pub use security::Security;

use crate::images::ImageScan;
use crate::scanners::RepoStats;
use crate::schema::{LifecycleType, ProjectType, ServiceTier};
use serde::Serialize;
use std::collections::BTreeMap;

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
    pub fn calculate(projects: &[RepoStats], images: &BTreeMap<String, ImageScan>) -> Self {
        let live: Vec<&RepoStats> = projects.iter().filter(|p| !p.archived).collect();
        Self {
            governance: Governance::calculate(&live),
            security: Security::calculate(&live, images),
            inventory: Inventory::calculate(&live),
        }
    }
}

/// A repository as the pages link it: to its elaine page by name, and to GitHub.
#[derive(Debug, Clone, Serialize)]
pub struct RepoRef {
    pub name: String,
    pub html_url: String,
}

impl RepoRef {
    pub(crate) fn of(p: &RepoStats) -> Self {
        Self {
            name: p.name.clone(),
            html_url: p.html_url.clone(),
        }
    }
}

/// The person a steward entry names: `first.last@domain` is `First Last`, anything else is the name as written.
pub(crate) fn steward_name(written: &str) -> String {
    let written = written.trim();
    let Some((local, _)) = written.split_once('@') else {
        return written.to_string();
    };
    local
        .split('.')
        .filter(|word| !word.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            chars
                .next()
                .into_iter()
                .flat_map(char::to_uppercase)
                .chain(chars.flat_map(char::to_lowercase))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// One display name per steward across the live repositories. Stewards compare case-insensitively and an
/// email counts as the name it spells; the display name is a spelling written as a name when there is one.
pub(crate) struct StewardNames(BTreeMap<String, (String, bool)>);

impl StewardNames {
    pub(crate) fn of(live: &[&RepoStats]) -> Self {
        let mut names: BTreeMap<String, (String, bool)> = BTreeMap::new();
        for written in live.iter().filter_map(|p| p.manifest.as_ref()?.stewards.as_ref()).flatten() {
            let name = steward_name(written);
            let from_email = written.contains('@');
            let entry = names.entry(name.to_lowercase()).or_insert_with(|| (name.clone(), from_email));
            if entry.1 && !from_email {
                *entry = (name, false);
            }
        }
        Self(names)
    }

    /// The display name of a steward as a manifest writes it.
    pub(crate) fn display(&self, written: &str) -> String {
        let name = steward_name(written);
        self.0.get(&name.to_lowercase()).map(|(display, _)| display.clone()).unwrap_or(name)
    }

    /// The distinct stewards of a repository, by display name, in manifest order.
    pub(crate) fn of_repo(&self, p: &RepoStats) -> Vec<String> {
        let mut stewards: Vec<String> = Vec::new();
        for written in p.manifest.iter().flat_map(|m| m.stewards.iter().flatten()) {
            let display = self.display(written);
            if !stewards.contains(&display) {
                stewards.push(display);
            }
        }
        stewards
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
