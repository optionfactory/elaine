use super::{manifest_meta, pct, tier_weight};
use crate::scanners::{RepoStats, ScannerKind};
use crate::schema::{CertManagement, EnvironmentManifest, EnvironmentType, ExposureType, LifecycleType, ProjectType, ServiceTier};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Inventory {
    /// One row per stewardship assignment, sorted by steward, tier, name.
    pub assignments: Vec<AssignmentRow>,
    /// One row per declared domain, sorted by domain.
    pub domains: Vec<DomainRow>,
    /// Detected toolchains with repository counts, sorted by count.
    pub toolchains: Vec<ToolchainRow>,
    /// Tiered repositories, sorted by tier then name.
    pub tiers: Vec<TierRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AssignmentRow {
    pub steward: String,
    pub name: String,
    pub html_url: String,
    #[serde(rename = "type")]
    pub project_type: Option<ProjectType>,
    pub tier: Option<ServiceTier>,
    pub lifecycle: Option<LifecycleType>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainRow {
    pub domain: String,
    pub repo: String,
    pub html_url: String,
    #[serde(rename = "type")]
    pub environment_type: Option<EnvironmentType>,
    pub ingress: Option<ExposureType>,
    pub certificates: Option<CertManagement>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolchainRow {
    pub toolchain: ScannerKind,
    pub repos: usize,
    pub pct: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct TierRow {
    pub name: String,
    pub html_url: String,
    #[serde(rename = "type")]
    pub project_type: Option<ProjectType>,
    pub tier: ServiceTier,
    pub lifecycle: Option<LifecycleType>,
}

impl Inventory {
    pub(super) fn calculate(live: &[&RepoStats]) -> Self {
        let mut assignments: Vec<AssignmentRow> = live
            .iter()
            .flat_map(|p| {
                let (project_type, tier, lifecycle) = manifest_meta(p);
                let stewards = p.manifest.as_ref().and_then(|m| m.stewards.clone()).unwrap_or_default();
                stewards.into_iter().map(move |steward| AssignmentRow {
                    steward,
                    name: p.name.clone(),
                    html_url: p.html_url.clone(),
                    project_type,
                    tier,
                    lifecycle,
                })
            })
            .collect();
        // tier_weight descending is tier order ascending; untiered (0) sorts last
        let tier_weight_or = |t: Option<ServiceTier>| t.map(tier_weight).unwrap_or(0);
        assignments.sort_by(|a, b| {
            a.steward
                .cmp(&b.steward)
                .then_with(|| tier_weight_or(b.tier).cmp(&tier_weight_or(a.tier)))
                .then_with(|| a.name.cmp(&b.name))
        });

        let mut domains: Vec<DomainRow> = live
            .iter()
            .flat_map(|p| {
                let envs: &[EnvironmentManifest] = p.manifest.as_ref().and_then(|m| m.environments.as_deref()).unwrap_or_default();
                envs.iter()
                    .filter(|e| e.domains.as_ref().is_some_and(|d| !d.is_empty()))
                    .flat_map(|e| {
                        e.domains.iter().flatten().map(move |domain| DomainRow {
                            domain: domain.clone(),
                            repo: p.name.clone(),
                            html_url: p.html_url.clone(),
                            environment_type: Some(e.environment_type),
                            ingress: e.ingress,
                            certificates: e.certificates,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        domains.sort_by(|a, b| a.domain.cmp(&b.domain));

        let mut toolchain_agg: BTreeMap<ScannerKind, usize> = BTreeMap::new();
        for p in live {
            for kind in p.health.keys() {
                if matches!(kind, ScannerKind::Elaine | ScannerKind::Pinch) {
                    continue;
                }
                *toolchain_agg.entry(*kind).or_insert(0) += 1;
            }
        }
        let mut toolchains: Vec<ToolchainRow> = toolchain_agg
            .into_iter()
            .map(|(toolchain, repos)| ToolchainRow {
                toolchain,
                repos,
                pct: pct(repos, live.len()),
            })
            .collect();
        toolchains.sort_by(|a, b| b.repos.cmp(&a.repos).then_with(|| a.toolchain.cmp(&b.toolchain)));

        let mut tiers: Vec<TierRow> = live
            .iter()
            .filter_map(|p| {
                let m = p.manifest.as_ref()?;
                let tier = m.tier?;
                Some(TierRow {
                    name: p.name.clone(),
                    html_url: p.html_url.clone(),
                    project_type: m.project_type,
                    tier,
                    lifecycle: m.lifecycle,
                })
            })
            .collect();
        tiers.sort_by(|a, b| tier_weight(b.tier).cmp(&tier_weight(a.tier)).then_with(|| a.name.cmp(&b.name)));

        Self {
            assignments,
            domains,
            toolchains,
            tiers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::aggregates::Aggregates;
    use crate::server::aggregates::testutil::{repo, with_manifest};

    #[test]
    fn toolchains_skip_manifest_scanners_and_compute_pct() {
        let mut a = repo("a", false);
        a.health.insert(ScannerKind::Maven, BTreeMap::new());
        a.health.insert(ScannerKind::Elaine, BTreeMap::new());
        let mut b = repo("b", false);
        b.health.insert(ScannerKind::Maven, BTreeMap::new());
        let agg = Aggregates::calculate(&[a, b]);
        let tc = &agg.inventory.toolchains;
        assert_eq!(tc.len(), 1);
        assert_eq!((tc[0].toolchain, tc[0].repos, tc[0].pct), (ScannerKind::Maven, 2, 100));
    }

    #[test]
    fn tiers_list_only_tiered_repos_sorted() {
        let t2 = with_manifest(repo("zzz", false), r#"{ "schema_version": 1, "name": "zzz", "tier": "tier2" }"#);
        let t1 = with_manifest(repo("aaa", false), r#"{ "schema_version": 1, "name": "aaa", "tier": "tier1" }"#);
        let un = with_manifest(repo("nope", false), r#"{ "schema_version": 1, "name": "nope" }"#);
        let agg = Aggregates::calculate(&[t2, t1, un]);
        let tiers = &agg.inventory.tiers;
        assert_eq!(tiers.len(), 2);
        assert_eq!(tiers[0].name, "aaa");
        assert_eq!(tiers[1].name, "zzz");
    }
}
