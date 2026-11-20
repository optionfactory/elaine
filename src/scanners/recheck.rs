use crate::scanners::osv::fetch_vulnerabilities;
use crate::scanners::{Dependency, RepoStats, ScannerKind, Vulnerability};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The advisories of one `(ecosystem, artifact, version)`.
type Advisories = HashMap<(String, String, String), Vec<String>>;

/// Checks again against OSV, in one batch per ecosystem, the dependencies each scanner recorded at the last full scan
/// of each repository, and replaces that scanner's vulnerabilities with what OSV says today. A scanner without a
/// recorded list keeps its vulnerabilities. Nothing changes when OSV fails.
pub fn recheck(client: &reqwest::Client, repos: &mut [(RepoStats, BTreeMap<ScannerKind, Vec<Dependency>>)]) -> anyhow::Result<()> {
    let mut by_ecosystem: BTreeMap<&str, BTreeSet<(&str, &str)>> = BTreeMap::new();
    for dep in repos.iter().flat_map(|(_, recorded)| recorded.values().flatten()) {
        by_ecosystem
            .entry(dep.ecosystem.as_str())
            .or_default()
            .insert((dep.artifact.as_str(), dep.version.as_str()));
    }
    let mut advisories = Advisories::new();
    for (ecosystem, deps) in by_ecosystem {
        let queries: Vec<(&str, &str, &str)> = deps.into_iter().map(|(artifact, version)| (ecosystem, artifact, version)).collect();
        for (artifact, version, id) in fetch_vulnerabilities(client, &queries)? {
            advisories.entry((ecosystem.to_string(), artifact, version)).or_default().push(id);
        }
    }
    for (repo, recorded) in repos.iter_mut() {
        replace_vulnerabilities(repo, recorded, &advisories);
    }
    Ok(())
}

fn replace_vulnerabilities(repo: &mut RepoStats, recorded: &BTreeMap<ScannerKind, Vec<Dependency>>, advisories: &Advisories) {
    let vulns = repo.vulnerabilities.get_or_insert_default();
    vulns.retain(|v| !v.scanner.is_some_and(|scanner| recorded.contains_key(&scanner)));
    for (scanner, deps) in recorded {
        for dep in deps {
            let key = (dep.ecosystem.clone(), dep.artifact.clone(), dep.version.clone());
            for id in advisories.get(&key).into_iter().flatten() {
                vulns.push(Vulnerability {
                    project: dep.project.clone(),
                    artifact: dep.artifact.clone(),
                    version: dep.version.clone(),
                    vuln_id: id.clone(),
                    trail: dep.trail.clone(),
                    scanner: Some(*scanner),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::GithubRepository;

    #[test]
    fn only_the_recorded_scanners_take_what_osv_says_today() {
        let mut repo = RepoStats::new_from_github(&GithubRepository::default());
        let found = |artifact: &str, id: &str, scanner| Vulnerability {
            artifact: artifact.into(),
            vuln_id: id.into(),
            scanner: Some(scanner),
            ..Default::default()
        };
        repo.vulnerabilities = Some(vec![
            found("lodash", "GHSA-old", ScannerKind::Npm),
            found("serde", "RUSTSEC-1", ScannerKind::Rust),
        ]);
        let lodash = Dependency {
            ecosystem: "npm".into(),
            project: "web".into(),
            artifact: "lodash".into(),
            version: "4.17.20".into(),
            trail: vec![],
        };
        let recorded = BTreeMap::from([(ScannerKind::Npm, vec![lodash])]);
        let advisories = Advisories::from([(("npm".into(), "lodash".into(), "4.17.20".into()), vec!["GHSA-new".into()])]);

        replace_vulnerabilities(&mut repo, &recorded, &advisories);

        let ids: Vec<_> = repo.vulnerabilities.unwrap().into_iter().map(|v| v.vuln_id).collect();
        assert_eq!(ids, ["RUSTSEC-1", "GHSA-new"]);
    }
}
