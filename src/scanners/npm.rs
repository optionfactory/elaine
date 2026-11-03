use crate::scanners::osv::fetch_vulnerabilities;
use crate::scanners::pathcollector::Pattern;
use crate::scanners::{CheckStatus, OutdatedDependency, RepoStats, ScanContext, Scanner, ScannerKind, Vulnerability};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;

#[derive(Deserialize)]
struct PackageLock {
    packages: Option<HashMap<String, NpmPackage>>,
}

#[derive(Deserialize)]
struct NpmPackage {
    version: Option<String>,
}

#[derive(Deserialize)]
struct NpmOutdatedDep {
    current: Option<String>,
    latest: Option<String>,
    #[serde(rename = "type")]
    dep_type: Option<String>,
}

pub struct NpmScanner;

impl Scanner for NpmScanner {
    fn patterns(&self) -> Vec<(&'static str, Pattern)> {
        vec![("package_locks", Pattern::FileName("package-lock.json".to_string()))]
    }

    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
        if ctx.repo.archived || ctx.repo.fork || ctx.repo.disabled {
            return Ok(());
        }

        let Some(lock_paths) = ctx.matches.get("package_locks") else {
            return Ok(());
        };
        if lock_paths.is_empty() {
            return Ok(());
        }

        stats.checked_for_vulnerabilities();
        stats.checked_for_outdated_dependencies();

        let mut vulns_ok = true;
        let mut outdated_ok = true;

        for lock_path in lock_paths {
            ctx.set_message(format!("[{}] Running npm checks...", ctx.repo.name));
            let run_dir = ctx.root.join(lock_path).parent().unwrap().to_path_buf();
            let lockfile = fs::read_to_string(ctx.root.join(lock_path))
                .map_err(anyhow::Error::from)
                .and_then(|content| Ok(serde_json::from_str::<PackageLock>(&content)?));
            let packages = match lockfile {
                Ok(PackageLock { packages: Some(packages) }) => Some(packages),
                Ok(PackageLock { packages: None }) => {
                    ctx.report_failure(
                        "npm",
                        format!("No 'packages' map in {} (lockfileVersion 1 is unsupported)", lock_path.display()),
                    );
                    None
                }
                Err(e) => {
                    ctx.report_failure("npm", format!("Failed to read package-lock.json {}: {}", lock_path.display(), e));
                    None
                }
            };

            let per_vulns_ok = (|| -> Option<()> {
                let packages = packages.as_ref()?;
                let mut deps = Vec::new();
                for (path, pkg) in packages {
                    if path.is_empty() {
                        continue;
                    }
                    let name = path.split("node_modules/").last().unwrap_or(path);
                    if let Some(version) = &pkg.version {
                        deps.push(("npm", name, version.as_str()));
                    }
                }
                match fetch_vulnerabilities(ctx.client, &deps) {
                    Ok(vulns) => {
                        stats.add_vulnerabilities(
                            vulns
                                .into_iter()
                                .map(|(pkg, ver, id)| Vulnerability {
                                    project: ctx.repo.name.clone(),
                                    artifact: pkg,
                                    version: ver,
                                    vuln_id: id,
                                    trail: vec![],
                                })
                                .collect(),
                        );
                        Some(())
                    }
                    Err(e) => {
                        ctx.report_failure("npm", format!("OSV check failed for {}: {}", lock_path.display(), e));
                        None
                    }
                }
            })()
            .is_some();
            vulns_ok &= per_vulns_ok;

            let per_outdated_ok = match ctx.run_logged("npm", "npm", &["outdated", "--json"], &run_dir) {
                Ok(out) => {
                    let payload = String::from_utf8_lossy(&out.stdout);
                    match serde_json::from_str::<HashMap<String, NpmOutdatedDep>>(&payload) {
                        Ok(parsed) => {
                            let updates = outdated_dependencies(&ctx.repo.name, parsed, packages.as_ref());
                            stats.add_outdated_dependencies(updates);
                            true
                        }
                        Err(e) => {
                            ctx.report_failure("npm", format!("Failed to parse npm outdated output for {}: {}", lock_path.display(), e));
                            false
                        }
                    }
                }
                Err(e) => {
                    ctx.report_failure("npm", format!("Failed to execute npm outdated for {}: {}", lock_path.display(), e));
                    false
                }
            };
            outdated_ok &= per_outdated_ok;
        }

        stats.record_check(ScannerKind::Npm, "vulns", if vulns_ok { CheckStatus::Ok } else { CheckStatus::Failed });
        stats.record_check(ScannerKind::Npm, "outdated", if outdated_ok { CheckStatus::Ok } else { CheckStatus::Failed });
        Ok(())
    }
}

/// Turns `npm outdated --json` output into outdated dependencies.
/// Without node_modules npm leaves `current` out and lists every direct dependency,
/// so the locked version stands in for `current` and up-to-date entries are dropped.
fn outdated_dependencies(project: &str, outdated: HashMap<String, NpmOutdatedDep>, packages: Option<&HashMap<String, NpmPackage>>) -> Vec<OutdatedDependency> {
    outdated
        .into_iter()
        .filter_map(|(name, dep)| {
            let current = dep.current.or_else(|| packages?.get(&format!("node_modules/{}", name))?.version.clone())?;
            let latest = dep.latest?;
            (current != latest).then(|| OutdatedDependency {
                project: project.to_string(),
                kind: dep.dep_type.unwrap_or_else(|| "dependency".to_string()),
                artifact: name,
                current,
                latest,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outdated_without_node_modules_uses_locked_version_and_skips_up_to_date() {
        let outdated = serde_json::from_str(
            r#"{
                "is-number": { "wanted": "7.0.0", "latest": "7.0.0", "dependent": "t" },
                "left-pad": { "wanted": "1.0.0", "latest": "1.3.0", "dependent": "t" }
            }"#,
        )
        .unwrap();
        let lock: PackageLock = serde_json::from_str(
            r#"{ "packages": { "": {}, "node_modules/is-number": { "version": "7.0.0" }, "node_modules/left-pad": { "version": "1.0.0" } } }"#,
        )
        .unwrap();

        let deps = outdated_dependencies("acme", outdated, lock.packages.as_ref());

        let found: Vec<(&str, &str, &str)> = deps.iter().map(|d| (d.artifact.as_str(), d.current.as_str(), d.latest.as_str())).collect();
        assert_eq!(found, vec![("left-pad", "1.0.0", "1.3.0")]);
    }
}
