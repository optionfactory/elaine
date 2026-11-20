use super::{manifest_meta, tier_weight};
use crate::images::{ImageScan, ImageSummary, ImageVulnerability};
use crate::scanners::{CheckStatus, RepoStats, ScannerKind};
use crate::schema::{ElaineManifest, ExposureType, LifecycleType, ProjectType, ServiceTier};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, Serialize)]
pub struct Security {
    /// One row per (repository, scanner) pair with failed checks.
    pub failures: Vec<FailureRow>,
    /// Live repositories with known vulnerabilities, sorted by count.
    pub vulns: Vec<VulnsRow>,
    /// Live repositories with outdated dependencies, sorted by count.
    pub outdated: Vec<OutdatedRow>,
    /// Outdated artifacts aggregated across the organization, sorted by affected repositories.
    pub artifacts: Vec<ArtifactRow>,
    /// The container images live repositories run, the most serious first; apart from `vulns`, which are the
    /// dependencies' own.
    pub images: Vec<ImageRow>,
    pub risk: Risk,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImageRow {
    #[serde(flatten)]
    pub summary: ImageSummary,
    /// The live repositories that run it.
    pub repos: Vec<String>,
    pub vulnerabilities: Vec<ImageVulnerability>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FailureRow {
    pub name: String,
    pub html_url: String,
    pub tier: Option<ServiceTier>,
    pub scanner: ScannerKind,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnsRow {
    pub name: String,
    pub html_url: String,
    pub vulns: usize,
    #[serde(rename = "type")]
    pub project_type: Option<ProjectType>,
    pub tier: Option<ServiceTier>,
    pub lifecycle: Option<LifecycleType>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutdatedRow {
    pub name: String,
    pub html_url: String,
    pub outdated: usize,
    #[serde(rename = "type")]
    pub project_type: Option<ProjectType>,
    pub tier: Option<ServiceTier>,
    pub lifecycle: Option<LifecycleType>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactRow {
    pub artifact: String,
    pub repos: usize,
    pub latest: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Risk {
    pub exposures: Vec<&'static str>,
    pub rows: Vec<RiskMatrixRow>,
    /// Highest-risk repositories, sorted by score (full list; top-N slicing is presentation).
    pub worst: Vec<WorstRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskMatrixRow {
    pub tier: ServiceTier,
    pub cells: Vec<RiskCell>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskCell {
    pub repos: usize,
    pub vulns: usize,
    pub score: u32,
    pub level: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorstRow {
    pub name: String,
    pub html_url: String,
    pub tier: ServiceTier,
    pub exposure: &'static str,
    #[serde(rename = "type")]
    pub project_type: Option<ProjectType>,
    pub lifecycle: Option<LifecycleType>,
    pub vulns: usize,
    pub outdated: usize,
    /// Fixable high and critical vulnerabilities of the images it runs: shown, not part of the ranking.
    pub image_vulns: usize,
}

/// Network exposure classification, from most to least permissive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Exposure {
    Internet,
    RestrictedVpn,
    RestrictedIp,
    RestrictedGeoIp,
    RestrictedPam,
    Local,
    NoneExposed,
    Unknown,
}

impl Exposure {
    /// Lower = more permissive; the most permissive ingress across environments wins.
    fn priority(self) -> u32 {
        match self {
            Exposure::Internet => 0,
            Exposure::RestrictedVpn => 1,
            Exposure::RestrictedIp | Exposure::RestrictedGeoIp => 2,
            Exposure::RestrictedPam => 3,
            Exposure::Local => 4,
            Exposure::NoneExposed => 5,
            Exposure::Unknown => 6,
        }
    }

    fn weight(self) -> u32 {
        match self {
            Exposure::Internet => 4,
            Exposure::RestrictedVpn | Exposure::RestrictedIp | Exposure::RestrictedGeoIp => 3,
            Exposure::RestrictedPam => 2,
            Exposure::Local => 1,
            Exposure::NoneExposed => 0,
            Exposure::Unknown => 2,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Exposure::Internet => "internet",
            Exposure::RestrictedVpn => "restricted-vpn",
            Exposure::RestrictedIp => "restricted-ip",
            Exposure::RestrictedGeoIp => "restricted-geo-ip",
            Exposure::RestrictedPam => "restricted-pam",
            Exposure::Local => "local",
            Exposure::NoneExposed => "none",
            Exposure::Unknown => "unknown",
        }
    }

    fn from_ingress(ingress: ExposureType) -> Self {
        match ingress {
            ExposureType::Internet => Exposure::Internet,
            ExposureType::RestrictedVpn => Exposure::RestrictedVpn,
            ExposureType::RestrictedIp => Exposure::RestrictedIp,
            ExposureType::RestrictedGeoIp => Exposure::RestrictedGeoIp,
            ExposureType::RestrictedPam => Exposure::RestrictedPam,
            ExposureType::Local => Exposure::Local,
            ExposureType::None => Exposure::NoneExposed,
        }
    }

    fn from_manifest(m: &ElaineManifest) -> Self {
        let Some(envs) = &m.environments else { return Exposure::Unknown };
        if envs.is_empty() {
            return Exposure::Unknown;
        }
        envs.iter()
            .filter_map(|e| e.ingress.map(Exposure::from_ingress))
            .min_by_key(|e| e.priority())
            .unwrap_or(Exposure::Unknown)
    }
}

const EXPOSURES: [Exposure; 8] = [
    Exposure::Internet,
    Exposure::RestrictedVpn,
    Exposure::RestrictedIp,
    Exposure::RestrictedGeoIp,
    Exposure::RestrictedPam,
    Exposure::Local,
    Exposure::NoneExposed,
    Exposure::Unknown,
];

fn risk_level(score: u32) -> &'static str {
    match score {
        s if s >= 12 => "critical",
        s if s >= 6 => "high",
        s if s >= 2 => "medium",
        _ => "low",
    }
}

impl Security {
    pub(super) fn calculate(live: &[&RepoStats], images: &BTreeMap<String, ImageScan>) -> Self {
        // Failures: repositories with failed checks, busiest first, flattened per scanner.
        let mut failing: Vec<(usize, &RepoStats)> = live
            .iter()
            .filter_map(|p| {
                let count = p
                    .health
                    .values()
                    .map(|checks| checks.values().filter(|s| **s == CheckStatus::Failed).count())
                    .sum::<usize>();
                (count > 0).then_some((count, *p))
            })
            .collect();
        failing.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.name.cmp(&b.1.name)));
        let failures = failing
            .into_iter()
            .flat_map(|(_, p)| {
                let tier = p.manifest.as_ref().and_then(|m| m.tier);
                p.health
                    .iter()
                    .map(move |(kind, checks)| FailureRow {
                        name: p.name.clone(),
                        html_url: p.html_url.clone(),
                        tier,
                        scanner: *kind,
                        checks: checks
                            .iter()
                            .filter(|(_, s)| **s == CheckStatus::Failed)
                            .map(|(check, _)| check.clone())
                            .collect(),
                    })
                    .filter(|r| !r.checks.is_empty())
            })
            .collect();

        let mut vulns: Vec<VulnsRow> = live
            .iter()
            .filter_map(|p| {
                let count = p.vulnerabilities.as_ref().map(|v| v.len()).unwrap_or(0);
                let (project_type, tier, lifecycle) = manifest_meta(p);
                (count > 0).then(|| VulnsRow {
                    name: p.name.clone(),
                    html_url: p.html_url.clone(),
                    vulns: count,
                    project_type,
                    tier,
                    lifecycle,
                })
            })
            .collect();
        vulns.sort_by_key(|r| std::cmp::Reverse(r.vulns));

        let mut outdated: Vec<OutdatedRow> = live
            .iter()
            .filter_map(|p| {
                let count = p.outdated_dependencies.as_ref().map(|v| v.len()).unwrap_or(0);
                let (project_type, tier, lifecycle) = manifest_meta(p);
                (count > 0).then(|| OutdatedRow {
                    name: p.name.clone(),
                    html_url: p.html_url.clone(),
                    outdated: count,
                    project_type,
                    tier,
                    lifecycle,
                })
            })
            .collect();
        outdated.sort_by_key(|r| std::cmp::Reverse(r.outdated));

        let mut artifact_agg: BTreeMap<String, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
        for p in live {
            for dep in p.outdated_dependencies.iter().flatten() {
                let entry = artifact_agg.entry(dep.artifact.clone()).or_insert_with(|| (BTreeSet::new(), BTreeSet::new()));
                entry.0.insert(p.name.clone());
                entry.1.insert(dep.latest.clone());
            }
        }
        let mut artifacts: Vec<ArtifactRow> = artifact_agg
            .into_iter()
            .map(|(artifact, (repos, latest))| ArtifactRow {
                artifact,
                repos: repos.len(),
                latest: latest.into_iter().collect::<Vec<_>>().join(", "),
            })
            .collect();
        artifacts.sort_by(|a, b| b.repos.cmp(&a.repos).then_with(|| a.artifact.cmp(&b.artifact)));

        let mut runners: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for p in live {
            for image in p.containers.iter().flatten() {
                runners.entry(image.as_str()).or_default().push(p.name.clone());
            }
        }
        let mut image_rows: Vec<ImageRow> = runners
            .into_iter()
            .map(|(image, repos)| {
                let scan = images.get(image);
                let vulnerabilities = match scan {
                    Some(ImageScan::Scanned { vulnerabilities }) => vulnerabilities.clone(),
                    _ => Vec::new(),
                };
                ImageRow {
                    summary: ImageSummary::of(image, scan),
                    repos,
                    vulnerabilities,
                }
            })
            .collect();
        image_rows.sort_by(|a, b| {
            b.summary
                .serious
                .cmp(&a.summary.serious)
                .then_with(|| b.summary.fixable.cmp(&a.summary.fixable))
                .then_with(|| a.summary.image.cmp(&b.summary.image))
        });

        let risk = Risk::calculate(live, images);

        Self {
            failures,
            vulns,
            outdated,
            artifacts,
            images: image_rows,
            risk,
        }
    }
}

impl Risk {
    fn calculate(live: &[&RepoStats], images: &BTreeMap<String, ImageScan>) -> Self {
        const TIERS: [ServiceTier; 4] = [ServiceTier::Tier1, ServiceTier::Tier2, ServiceTier::Tier3, ServiceTier::Tier4];

        let classified: Vec<(&RepoStats, ServiceTier, Exposure, usize, usize)> = live
            .iter()
            .map(|p| {
                let tier = p.manifest.as_ref().and_then(|m| m.tier).unwrap_or(ServiceTier::Tier4);
                let exposure = p.manifest.as_ref().map(Exposure::from_manifest).unwrap_or(Exposure::Unknown);
                let vulns = p.vulnerabilities.as_ref().map(|v| v.len()).unwrap_or(0);
                let outdated = p.outdated_dependencies.as_ref().map(|v| v.len()).unwrap_or(0);
                (*p, tier, exposure, vulns, outdated)
            })
            .collect();

        let rows = TIERS
            .iter()
            .map(|&tier| RiskMatrixRow {
                tier,
                cells: EXPOSURES
                    .iter()
                    .map(|&exposure| {
                        let cell = classified.iter().filter(|(_, t, e, _, _)| *t == tier && *e == exposure);
                        let repos = cell.clone().count();
                        let vulns = cell.map(|(_, _, _, v, _)| v).sum();
                        let score = tier_weight(tier) * exposure.weight();
                        RiskCell {
                            repos,
                            vulns,
                            score,
                            level: risk_level(score),
                        }
                    })
                    .collect(),
            })
            .collect();

        let mut worst: Vec<(u32, WorstRow)> = classified
            .iter()
            .filter_map(|(p, tier, exposure, vulns, outdated)| {
                let score = tier_weight(*tier) * exposure.weight();
                let (project_type, _, lifecycle) = manifest_meta(p);
                let row = WorstRow {
                    name: p.name.clone(),
                    html_url: p.html_url.clone(),
                    tier: *tier,
                    exposure: exposure.as_str(),
                    project_type,
                    lifecycle,
                    vulns: *vulns,
                    outdated: *outdated,
                    image_vulns: p
                        .containers
                        .iter()
                        .flatten()
                        .map(|image| ImageSummary::of(image, images.get(image)).serious)
                        .sum(),
                };
                (score > 0).then_some((score, row))
            })
            .collect();
        worst.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then_with(|| b.1.vulns.cmp(&a.1.vulns))
                .then_with(|| b.1.outdated.cmp(&a.1.outdated))
        });

        Self {
            exposures: EXPOSURES.iter().map(|e| e.as_str()).collect(),
            rows,
            worst: worst.into_iter().map(|(_, row)| row).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::aggregates::Aggregates;
    use crate::server::aggregates::testutil::{repo, with_manifest};

    fn dep(artifact: &str, current: &str, latest: &str) -> crate::scanners::OutdatedDependency {
        crate::scanners::OutdatedDependency {
            project: String::new(),
            kind: String::new(),
            artifact: artifact.into(),
            current: current.into(),
            latest: latest.into(),
            ..Default::default()
        }
    }

    #[test]
    fn exposure_picks_most_permissive_ingress() {
        let exposed = with_manifest(
            repo("a", false),
            r#"{ "schema_version": 1, "name": "a", "environments": [ { "name": "dev", "type": "development", "ingress": "local" }, { "name": "prod", "type": "production", "ingress": "internet" } ] }"#,
        );
        let agg = Aggregates::calculate(&[exposed], &Default::default());
        let worst = &agg.security.risk.worst;
        assert_eq!(worst[0].exposure, "internet");
    }

    #[test]
    fn risk_matrix_counts_cells_and_worst_omits_zero_score() {
        let t1_net = with_manifest(
            repo("critical", false),
            r#"{ "schema_version": 1, "name": "critical", "tier": "tier1", "environments": [ { "name": "prod", "type": "production", "ingress": "internet" } ] }"#,
        );
        let t4_local = with_manifest(
            repo("sandbox", false),
            r#"{ "schema_version": 1, "name": "sandbox", "tier": "tier4", "environments": [ { "name": "dev", "type": "development", "ingress": "local" } ] }"#,
        );
        let agg = Aggregates::calculate(&[t1_net, t4_local], &Default::default());
        let risk = &agg.security.risk;
        let t1 = risk.rows.iter().find(|r| r.tier == ServiceTier::Tier1).unwrap();
        let net = t1.cells.iter().find(|c| c.repos == 1).unwrap();
        assert_eq!((net.score, net.level), (16, "critical"));
        // tier4 * local = 1*1 = 1 > 0 so both are listed, ordered by score desc
        assert_eq!(risk.worst[0].name, "critical");
        assert!(risk.worst.iter().all(|w| w.tier == ServiceTier::Tier1 || w.name == "sandbox"));
    }

    #[test]
    fn images_are_listed_apart_and_shown_next_to_the_ranking_without_changing_it() {
        use crate::images::{ImageScan, ImageVulnerability, Severity};
        let manifest =
            r#"{ "schema_version": 1, "name": "x", "tier": "tier1", "environments": [ { "name": "prod", "type": "production", "ingress": "internet" } ] }"#;
        let mut stale = with_manifest(repo("stale", false), manifest);
        stale.containers = Some(vec!["acme/nginx:257".into()]);
        let mut fresh = with_manifest(repo("fresh", false), manifest);
        fresh.vulnerabilities = Some(vec![crate::scanners::Vulnerability::default()]);
        let vuln = |severity| ImageVulnerability {
            package: "openssl".into(),
            version: "3.0".into(),
            fixed_in: "3.1".into(),
            severity,
            vuln_id: "CVE-1".into(),
        };
        let images = BTreeMap::from([(
            "acme/nginx:257".to_string(),
            ImageScan::Scanned {
                vulnerabilities: vec![vuln(Severity::Critical), vuln(Severity::Low)],
            },
        )]);
        let agg = Aggregates::calculate(&[stale, fresh], &images);
        let row = &agg.security.images[0];
        assert_eq!((row.summary.fixable, row.summary.serious, row.repos.clone()), (2, 1, vec!["stale".to_string()]));
        let worst: Vec<_> = agg.security.risk.worst.iter().map(|w| (w.name.as_str(), w.vulns, w.image_vulns)).collect();
        assert_eq!(worst, [("fresh", 1, 0), ("stale", 0, 1)]);
        assert!(agg.security.vulns.iter().all(|r| r.name == "fresh"));
    }

    #[test]
    fn artifacts_aggregate_repos_and_latest_versions() {
        let mut a = repo("a", false);
        a.outdated_dependencies = Some(vec![dep("lib:x", "1.0", "2.0"), dep("lib:y", "1.0", "2.0")]);
        let mut b = repo("b", false);
        b.outdated_dependencies = Some(vec![dep("lib:x", "1.0", "2.0"), dep("lib:x", "1.0", "3.0")]);
        let agg = Aggregates::calculate(&[a, b], &Default::default());
        let x = agg.security.artifacts.iter().find(|r| r.artifact == "lib:x").unwrap();
        assert_eq!(x.repos, 2);
        assert_eq!(x.latest, "2.0, 3.0");
    }
}
