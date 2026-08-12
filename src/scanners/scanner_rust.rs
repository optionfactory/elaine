use crate::scanners::osv::fetch_vulnerabilities;
use crate::scanners::pathcollector::Pattern;
use crate::scanners::{CheckStatus, DependencyUpdate, RepoStats, ScanContext, Scanner, ScannerKind, Vulnerability};
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

        let Some(lock_paths) = ctx.matches.get("cargo_locks") else {
            return Ok(());
        };
        if lock_paths.is_empty() {
            return Ok(());
        }

        stats.checked_for_vulnerabilities();
        stats.checked_for_upgrades();

        let mut vulns_ok = true;
        let mut outdated_ok = true;

        for lock_path in lock_paths {
            ctx.set_message(format!("[{}] Running Rust checks...", ctx.repo.name));
            let run_dir = ctx.root.join(lock_path).parent().unwrap().to_path_buf();
            let content = fs::read_to_string(ctx.root.join(lock_path))?;

            let per_vulns_ok = (|| -> Option<()> {
                let lockfile = match toml::from_str::<CargoLock>(&content) {
                    Ok(lf) => lf,
                    Err(e) => {
                        ctx.report_error(format!("[{}] 🔥 Failed to parse Cargo.lock: {}", ctx.repo.name, e));
                        return None;
                    }
                };
                let packages = lockfile.package?;
                let deps: Vec<(&str, &str, &str)> = packages
                    .iter()
                    .map(|p| ("crates.io", p.name.as_str(), p.version.as_str()))
                    .collect();
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

            let per_outdated_ok = match Command::new("cargo")
                .current_dir(&run_dir)
                .args(["outdated", "--format", "json", "--workspace"])
                .output()
            {
                Ok(out) => {
                    if let Ok(payload) = String::from_utf8(out.stdout) {
                        for line in payload.lines() {
                            if let Ok(parsed) = serde_json::from_str::<OutdatedOutput>(line) {
                                let updates: Vec<DependencyUpdate> = parsed
                                    .dependencies
                                    .into_iter()
                                    .map(|dep| DependencyUpdate {
                                        project: ctx.repo.name.clone(),
                                        kind: dep.kind.unwrap_or_else(|| "Normal".to_string()),
                                        artifact: dep.name,
                                        current: dep.project,
                                        latest: dep.latest,
                                    })
                                    .collect();
                                stats.add_upgrades(updates);
                            }
                        }
                    }
                    true
                }
                Err(e) => {
                    ctx.report_error(format!("[{}] 🔥 Failed to execute cargo outdated: {}", ctx.repo.name, e));
                    false
                }
            };
            outdated_ok &= per_outdated_ok;
        }

        stats.record_check(
            ScannerKind::Rust,
            "vulns",
            if vulns_ok { CheckStatus::Ok } else { CheckStatus::Failed },
        );
        stats.record_check(
            ScannerKind::Rust,
            "outdated",
            if outdated_ok { CheckStatus::Ok } else { CheckStatus::Failed },
        );
        Ok(())
    }
}
