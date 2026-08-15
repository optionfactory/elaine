use crate::scanners::osv::fetch_vulnerabilities;
use crate::scanners::pathcollector::Pattern;
use crate::scanners::{CheckStatus, OutdatedDependency, RepoStats, ScanContext, Scanner, ScannerKind, Vulnerability};
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
            let content = fs::read_to_string(ctx.root.join(lock_path))?;

            let per_vulns_ok = (|| -> Option<()> {
                let lockfile = match serde_json::from_str::<PackageLock>(&content) {
                    Ok(lf) => lf,
                    Err(e) => {
                        ctx.report_error(format!("[{}] 🔥 Failed to parse package-lock.json: {}", ctx.repo.name, e));
                        return None;
                    }
                };
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
                        ctx.report_error(format!("[{}] 🔥 OSV check failed: {}", ctx.repo.name, e));
                        None
                    }
                }
            })()
            .is_some();
            vulns_ok &= per_vulns_ok;

            let per_outdated_ok = match Command::new("npm").current_dir(&run_dir).args(["outdated", "--json"]).output() {
                Ok(out) => {
                    let payload = String::from_utf8_lossy(&out.stdout);
                    if let Ok(parsed) = serde_json::from_str::<HashMap<String, NpmOutdatedDep>>(&payload) {
                        let updates: Vec<OutdatedDependency> = parsed
                            .into_iter()
                            .filter_map(|(name, dep)| {
                                Some(OutdatedDependency {
                                    project: ctx.repo.name.clone(),
                                    kind: dep.dep_type.unwrap_or_else(|| "dependency".to_string()),
                                    artifact: name,
                                    current: dep.current?,
                                    latest: dep.latest?,
                                })
                            })
                            .collect();
                        stats.add_outdated_dependencies(updates);
                    }
                    true
                }
                Err(e) => {
                    ctx.report_error(format!("[{}] 🔥 Failed to execute npm outdated: {}", ctx.repo.name, e));
                    false
                }
            };
            outdated_ok &= per_outdated_ok;
        }

        stats.record_check(
            ScannerKind::Npm,
            "vulns",
            if vulns_ok { CheckStatus::Ok } else { CheckStatus::Failed },
        );
        stats.record_check(
            ScannerKind::Npm,
            "outdated",
            if outdated_ok { CheckStatus::Ok } else { CheckStatus::Failed },
        );
        Ok(())
    }
}
