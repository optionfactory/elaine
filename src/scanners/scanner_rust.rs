use crate::scanners::pathcollector::Pattern;
use crate::scanners::{DependencyUpdate, RepoStats, ScanContext, Scanner, StackInspectionStatus, Vulnerability};
use crate::scanners::osv::fetch_vulnerabilities;
use serde::Deserialize;
use std::fs;
use std::process::Command;

#[derive(Deserialize)]
struct CargoLock {
    package: Option<Vec<CargoPackage>>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
}

#[derive(Deserialize)]
struct OutdatedOutput {
    dependencies: Vec<OutdatedDep>,
}

#[derive(Deserialize)]
struct OutdatedDep {
    name: String,
    project: String,
    latest: String,
    kind: Option<String>,
}

pub struct RustScanner;

impl Scanner for RustScanner {
    fn patterns(&self) -> Vec<(&'static str, Pattern)> {
        vec![("cargo_locks", Pattern::FileName("Cargo.lock".to_string()))]
    }

    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
        if ctx.repo.archived || ctx.repo.fork || ctx.repo.disabled {
            return Ok(());
        }

        let Some(lock_paths) = ctx.matches.get("cargo_locks") else { return Ok(()) };

        for lock_path in lock_paths {
            let run_dir = ctx.root.join(lock_path).parent().unwrap().to_path_buf();
            let mut success = true;

            stats.checked_for_vulnerabilities();
            stats.checked_for_upgrades();

            let content = fs::read_to_string(ctx.root.join(lock_path))?;
            if let Ok(lockfile) = toml::from_str::<CargoLock>(&content) {
                if let Some(packages) = lockfile.package {
                    let deps: Vec<(&str, &str, &str)> = packages
                        .iter()
                        .map(|p| ("crates.io", p.name.as_str(), p.version.as_str()))
                        .collect();

                    if let Ok(vulns) = fetch_vulnerabilities(&deps) {
                        let vulnerabilities = vulns.into_iter().map(|(pkg, id)| Vulnerability {
                            project: ctx.repo.name.clone(),
                            artifact: pkg,
                            version: "unknown".to_string(),
                            vuln_id: id,
                            trail: vec![],
                        }).collect();
                        stats.add_vulnerabilities(vulnerabilities);
                    } else {
                        success = false;
                    }
                }
            }

            let outdated_cmd = Command::new("cargo")
                .current_dir(&run_dir)
                .args(["outdated", "--format", "json", "--workspace"])
                .output();

            if let Ok(out) = outdated_cmd {
                if let Ok(payload) = String::from_utf8(out.stdout) {
                    for line in payload.lines() {
                        if let Ok(parsed) = serde_json::from_str::<OutdatedOutput>(line) {
                            let updates: Vec<DependencyUpdate> = parsed.dependencies.into_iter().map(|dep| DependencyUpdate {
                                project: ctx.repo.name.clone(),
                                kind: dep.kind.unwrap_or_else(|| "Normal".to_string()),
                                artifact: dep.name,
                                current: dep.project,
                                latest: dep.latest,
                            }).collect();
                            stats.add_upgrades(updates);
                        }
                    }
                }
            } else {
                success = false;
            }

            if success {
                stats.put_stack("rust", StackInspectionStatus::Success);
            } else {
                stats.put_stack("rust", StackInspectionStatus::Failure);
            }
        }
        Ok(())
    }
}