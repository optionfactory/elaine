use crate::scanners::osv::fetch_vulnerabilities;
use crate::scanners::pathcollector::Pattern;
use crate::scanners::{DependencyUpdate, RepoStats, ScanContext, Scanner, StackInspectionStatus, Vulnerability};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::process::Command;

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

        for lock_path in lock_paths {
            let run_dir = ctx.root.join(lock_path).parent().unwrap().to_path_buf();
            stats.checked_for_vulnerabilities();
            stats.checked_for_upgrades();

            let content = fs::read_to_string(ctx.root.join(lock_path))?;
            let vulns_ok = (|| -> Option<()> {
                let lockfile = serde_json::from_str::<PackageLock>(&content).ok()?;
                let packages = lockfile.packages?;
                let mut deps = Vec::new();
                for (path, pkg) in &packages {
                    if path.is_empty() {
                        continue;
                    }
                    let name = path.split("node_modules/").last().unwrap_or(path);
                    if let Some(version) = &pkg.version {
                        deps.push(("npm", name, version.as_str()));
                    }
                }
                let vulns = fetch_vulnerabilities(ctx.client, &deps).ok()?;
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
            })()
            .is_some();

            let outdated_ok = match Command::new("npm").current_dir(&run_dir).args(["outdated", "--json"]).output() {
                Ok(out) => {
                    let payload = String::from_utf8_lossy(&out.stdout);
                    if let Ok(parsed) = serde_json::from_str::<HashMap<String, NpmOutdatedDep>>(&payload) {
                        let updates: Vec<DependencyUpdate> = parsed
                            .into_iter()
                            .filter_map(|(name, dep)| {
                                Some(DependencyUpdate {
                                    project: ctx.repo.name.clone(),
                                    kind: dep.dep_type.unwrap_or_else(|| "dependency".to_string()),
                                    artifact: name,
                                    current: dep.current?,
                                    latest: dep.latest?,
                                })
                            })
                            .collect();
                        stats.add_upgrades(updates);
                    }
                    true
                }
                Err(_) => false,
            };

            let success = vulns_ok && outdated_ok;
            stats.put_stack(
                "npm",
                if success {
                    StackInspectionStatus::Success
                } else {
                    StackInspectionStatus::Failure
                },
            );
        }
        Ok(())
    }
}
