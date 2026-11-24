use super::{RepoRef, StewardNames, pct};
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
    /// Stewards written as an email, one row per repository and email, sorted by repository.
    pub steward_emails: Vec<StewardEmailRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageRow {
    pub framework: String,
    pub assessed: usize,
    pub pending: usize,
    pub coverage_pct: u32,
    /// The repositories behind `assessed` and `pending`, sorted by name.
    pub assessed_repos: Vec<RepoRef>,
    pub pending_repos: Vec<RepoRef>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StewardRecap {
    pub steward: String,
    pub projects: usize,
    pub critical: usize,
    pub active: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct StewardEmailRow {
    pub name: String,
    pub html_url: String,
    /// The steward as the manifest writes it.
    pub written: String,
    /// The steward it is counted as.
    pub steward: String,
}

type IsPending = fn(&ComplianceManifest) -> bool;

/// Compliance framework keys paired with their pending-value predicates.
/// The keys are the JSON field names of ComplianceManifest; each predicate is a
/// typed match, so a framework forgotten here is absent from the output rather
/// than silently counted as assessed.
pub(crate) const FRAMEWORKS: [(&str, IsPending); 7] = [
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
        let mut compliances: Vec<(&RepoStats, &ComplianceManifest)> =
            live.iter().filter_map(|p| Some((*p, p.manifest.as_ref()?.compliance.as_ref()?))).collect();
        compliances.sort_by(|a, b| a.0.name.cmp(&b.0.name));

        let coverage = FRAMEWORKS
            .iter()
            .map(|&(framework, is_pending)| {
                let mut assessed_repos = Vec::new();
                let mut pending_repos = Vec::new();
                for (p, c) in &compliances {
                    if is_pending(c) {
                        pending_repos.push(RepoRef::of(p));
                    } else {
                        assessed_repos.push(RepoRef::of(p));
                    }
                }
                CoverageRow {
                    framework: framework.to_string(),
                    assessed: assessed_repos.len(),
                    pending: pending_repos.len(),
                    coverage_pct: pct(assessed_repos.len(), compliances.len()),
                    assessed_repos,
                    pending_repos,
                }
            })
            .collect();

        let names = StewardNames::of(live);
        let mut by_steward: BTreeMap<String, StewardRecap> = BTreeMap::new();
        for p in live {
            let Some(m) = &p.manifest else { continue };
            for steward in names.of_repo(p) {
                let entry = by_steward.entry(steward.clone()).or_insert(StewardRecap {
                    steward,
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

        let mut steward_emails: Vec<StewardEmailRow> = live
            .iter()
            .flat_map(|p| {
                let written = p.manifest.iter().flat_map(|m| m.stewards.iter().flatten());
                written.filter(|w| w.contains('@')).map(|w| StewardEmailRow {
                    name: p.name.clone(),
                    html_url: p.html_url.clone(),
                    written: w.clone(),
                    steward: names.display(w),
                })
            })
            .collect();
        steward_emails.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.written.cmp(&b.written)));

        Self {
            coverage,
            with_compliance: compliances.len(),
            missing: live.len() - compliances.len(),
            stewards_recap,
            steward_emails,
        }
    }
}

#[cfg(test)]
mod tests {
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

        let agg = Aggregates::calculate(&[assessed, pending, no_compliance, archived], &Default::default());
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
        let agg = Aggregates::calculate(&[r], &Default::default());
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
        let agg = Aggregates::calculate(&[a, b], &Default::default());
        let recap = &agg.governance.stewards_recap;
        // sorted by active desc: alice first
        assert_eq!(recap[0].steward, "alice");
        assert_eq!((recap[0].projects, recap[0].critical, recap[0].active), (2, 1, 1));
        assert_eq!(recap[1].steward, "bob");
        assert_eq!((recap[1].projects, recap[1].critical, recap[1].active), (1, 1, 1));
    }

    #[test]
    fn stewards_written_as_email_or_in_another_case_merge_into_the_name() {
        let by_email = with_manifest(
            repo("svc", false),
            r#"{ "schema_version": 1, "name": "svc", "stewards": ["gabriele.gustin@optionfactory.net"] }"#,
        );
        let by_name = with_manifest(repo("lib", false), r#"{ "schema_version": 1, "name": "lib", "stewards": ["Gabriele Gustin"] }"#);
        let twice = with_manifest(
            repo("app", false),
            r#"{ "schema_version": 1, "name": "app", "stewards": ["GABRIELE GUSTIN", "Gabriele.Gustin@optionfactory.net"] }"#,
        );
        let agg = Aggregates::calculate(&[by_email, by_name, twice], &Default::default());
        let recap: Vec<_> = agg.governance.stewards_recap.iter().map(|s| (s.steward.as_str(), s.projects)).collect();
        assert_eq!(recap, [("Gabriele Gustin", 3)]);
        let emails: Vec<_> = agg.governance.steward_emails.iter().map(|e| (e.name.as_str(), e.steward.as_str())).collect();
        assert_eq!(emails, [("app", "Gabriele Gustin"), ("svc", "Gabriele Gustin")]);
        assert!(agg.inventory.assignments.iter().all(|a| a.steward == "Gabriele Gustin"));
        assert_eq!(agg.inventory.assignments.len(), 3);
    }
}
