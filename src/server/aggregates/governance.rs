use super::pct;
use crate::scanners::RepoStats;
use crate::schema::{
    AdsResponsibility, AiActClass, ComplianceManifest, CraClass, DataResidency, DoraCriticality, GdprRole, LifecycleType, Nis2Category, ServiceTier,
};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Governance {
    /// One row per compliance framework, in canonical order.
    pub coverage: Vec<CoverageRow>,
    /// Live repositories declaring a compliance block.
    pub with_compliance: usize,
    /// Live repositories without a compliance block (manifest missing or partial).
    pub missing: usize,
    /// Stewardship recap, sorted by active project count then steward name.
    pub stewards_recap: Vec<StewardRecap>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageRow {
    pub framework: String,
    pub assessed: usize,
    pub pending: usize,
    pub coverage_pct: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct StewardRecap {
    pub steward: String,
    pub projects: usize,
    pub critical: usize,
    pub active: usize,
}

/// Compliance framework keys paired with their pending-value predicates.
/// The keys are the JSON field names of ComplianceManifest; each predicate is a
/// typed match, so a framework forgotten here is absent from the output rather
/// than silently counted as assessed.
const FRAMEWORKS: [(&str, fn(&ComplianceManifest) -> bool); 7] = [
    ("dora", |c| matches!(c.dora, DoraCriticality::PendingAssessment)),
    ("cra", |c| matches!(c.cra, CraClass::PendingAssessment)),
    ("nis2", |c| matches!(c.nis2, Nis2Category::PendingAssessment)),
    ("ai_act", |c| matches!(c.ai_act, AiActClass::PendingAssessment)),
    ("gdpr", |c| matches!(c.gdpr, GdprRole::PendingAssessment)),
    ("data_residency", |c| matches!(c.data_residency, DataResidency::PendingAssessment)),
    ("ads", |c| {
        matches!(c.ads, AdsResponsibility::PendingAssessment | AdsResponsibility::PendingNomination)
    }),
];

impl Governance {
    pub(super) fn calculate(live: &[&RepoStats]) -> Self {
        let compliances: Vec<&ComplianceManifest> = live.iter().filter_map(|p| p.manifest.as_ref().and_then(|m| m.compliance.as_ref())).collect();

        let coverage = FRAMEWORKS
            .iter()
            .map(|&(framework, is_pending)| {
                let mut assessed = 0;
                let mut pending = 0;
                for c in &compliances {
                    if is_pending(c) {
                        pending += 1;
                    } else {
                        assessed += 1;
                    }
                }
                let coverage_pct = pct(assessed, compliances.len());
                CoverageRow {
                    framework: framework.to_string(),
                    assessed,
                    pending,
                    coverage_pct,
                }
            })
            .collect();

        let mut by_steward: BTreeMap<String, StewardRecap> = BTreeMap::new();
        for p in live {
            let Some(m) = &p.manifest else { continue };
            for steward in m.stewards.iter().flatten() {
                let entry = by_steward.entry(steward.clone()).or_insert(StewardRecap {
                    steward: steward.clone(),
                    projects: 0,
                    critical: 0,
                    active: 0,
                });
                entry.projects += 1;
                if matches!(m.tier, Some(ServiceTier::Tier1 | ServiceTier::Tier2)) {
                    entry.critical += 1;
                }
                if matches!(m.lifecycle, Some(LifecycleType::Active)) {
                    entry.active += 1;
                }
            }
        }
        let mut stewards_recap: Vec<StewardRecap> = by_steward.into_values().collect();
        stewards_recap.sort_by(|a, b| b.active.cmp(&a.active).then_with(|| a.steward.cmp(&b.steward)));

        Self {
            coverage,
            with_compliance: compliances.len(),
            missing: live.len() - compliances.len(),
            stewards_recap,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::aggregates::Aggregates;
    use crate::server::aggregates::testutil::{repo, with_manifest};

    #[test]
    fn coverage_counts_pending_vs_assessed_and_missing() {
        let assessed = with_manifest(
            repo("a", false),
            r#"{ "schema_version": 1, "name": "a", "compliance": { "dora": "non-critical", "cra": "default", "nis2": "out-of-scope", "ai_act": "out-of-scope", "gdpr": "controller", "data_residency": "eu", "ads": "internal" } }"#,
        );
        let pending = with_manifest(
            repo("b", false),
            r#"{ "schema_version": 1, "name": "b", "compliance": { "dora": "pending-assessment", "cra": "default", "nis2": "out-of-scope", "ai_act": "out-of-scope", "gdpr": "controller", "data_residency": "eu", "ads": "internal" } }"#,
        );
        let no_compliance = with_manifest(repo("c", false), r#"{ "schema_version": 1, "name": "c" }"#);
        let archived = repo("d", true);

        let agg = Aggregates::calculate(&[assessed, pending, no_compliance, archived]);
        let g = &agg.governance;
        assert_eq!(g.with_compliance, 2);
        assert_eq!(g.missing, 1); // live without compliance block
        let dora = g.coverage.iter().find(|r| r.framework == "dora").unwrap();
        assert_eq!((dora.assessed, dora.pending, dora.coverage_pct), (1, 1, 50));
        let cra = g.coverage.iter().find(|r| r.framework == "cra").unwrap();
        assert_eq!((cra.assessed, cra.pending, cra.coverage_pct), (2, 0, 100));
    }

    #[test]
    fn ads_pending_nomination_counts_as_pending() {
        let r = with_manifest(
            repo("a", false),
            r#"{ "schema_version": 1, "name": "a", "compliance": { "dora": "non-critical", "cra": "default", "nis2": "out-of-scope", "ai_act": "out-of-scope", "gdpr": "controller", "data_residency": "eu", "ads": "pending-nomination" } }"#,
        );
        let agg = Aggregates::calculate(&[r]);
        let ads = agg.governance.coverage.iter().find(|r| r.framework == "ads").unwrap();
        assert_eq!((ads.assessed, ads.pending), (0, 1));
    }

    #[test]
    fn stewards_recap_counts_projects_critical_and_active() {
        let a = with_manifest(
            repo("svc", false),
            r#"{ "schema_version": 1, "name": "svc", "tier": "tier1", "lifecycle": "active", "stewards": ["alice", "bob"] }"#,
        );
        let b = with_manifest(
            repo("lib", false),
            r#"{ "schema_version": 1, "name": "lib", "tier": "tier3", "lifecycle": "unmaintained", "stewards": ["alice"] }"#,
        );
        let agg = Aggregates::calculate(&[a, b]);
        let recap = &agg.governance.stewards_recap;
        // sorted by active desc: alice first
        assert_eq!(recap[0].steward, "alice");
        assert_eq!((recap[0].projects, recap[0].critical, recap[0].active), (2, 1, 1));
        assert_eq!(recap[1].steward, "bob");
        assert_eq!((recap[1].projects, recap[1].critical, recap[1].active), (1, 1, 1));
    }
}
