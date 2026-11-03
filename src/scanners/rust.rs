use crate::scanners::osv::fetch_vulnerabilities;
use crate::scanners::pathcollector::Pattern;
use crate::scanners::{CheckStatus, OutdatedDependency, RepoStats, ScanContext, Scanner, ScannerKind, Vulnerability};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize)]
struct CargoLock {
    package: Option<Vec<CargoPackage>>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    source: Option<String>,
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
        stats.checked_for_outdated_dependencies();

        let mut vulns_ok = true;
        let mut outdated_ok = true;

        for lock_path in lock_paths {
            ctx.set_message(format!("[{}] Running Rust checks...", ctx.repo.name));
            let run_dir = ctx.root.join(lock_path).parent().unwrap().to_path_buf();
            let per_vulns_ok = (|| -> Option<()> {
                let content = match fs::read_to_string(ctx.root.join(lock_path)) {
                    Ok(content) => content,
                    Err(e) => {
                        ctx.report_failure("rust", format!("Failed to read Cargo.lock {}: {}", lock_path.display(), e));
                        return None;
                    }
                };
                let lockfile = match toml::from_str::<CargoLock>(&content) {
                    Ok(lf) => lf,
                    Err(e) => {
                        ctx.report_failure("rust", format!("Failed to parse Cargo.lock {}: {}", lock_path.display(), e));
                        return None;
                    }
                };
                let packages = match lockfile.package {
                    Some(p) => p,
                    None => {
                        ctx.report_failure("rust", format!("No 'package' table in {}", lock_path.display()));
                        return None;
                    }
                };
                let deps: Vec<(&str, &str, &str)> = packages
                    .iter()
                    .filter(|p| {
                        matches!(
                            p.source.as_deref(),
                            Some("registry+https://github.com/rust-lang/crates.io-index" | "sparse+https://index.crates.io/")
                        )
                    })
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
                        ctx.report_failure("rust", format!("OSV check failed for {}: {}", lock_path.display(), e));
                        None
                    }
                }
            })()
            .is_some();
            vulns_ok &= per_vulns_ok;

            let per_outdated_ok = match ctx.run_logged("rust", "cargo", &["outdated", "--format", "json", "--workspace"], &run_dir) {
                Ok(out) if !out.success => {
                    ctx.report_failure("rust", format!("cargo outdated failed for {}", lock_path.display()));
                    false
                }
                Ok(out) => {
                    let payload = String::from_utf8_lossy(&out.stdout);
                    let outputs: Vec<OutdatedOutput> = payload.lines().filter_map(|line| serde_json::from_str(line).ok()).collect();
                    for output in &outputs {
                        stats.add_outdated_dependencies(
                            output
                                .dependencies
                                .iter()
                                .map(|dep| OutdatedDependency {
                                    project: ctx.repo.name.clone(),
                                    kind: dep.kind.clone().unwrap_or_else(|| "Normal".to_string()),
                                    artifact: dep.name.clone(),
                                    current: dep.project.clone(),
                                    latest: dep.latest.clone(),
                                })
                                .collect(),
                        );
                    }
                    if outputs.is_empty() {
                        ctx.report_failure("rust", format!("Failed to parse cargo outdated output for {}", lock_path.display()));
                    }
                    !outputs.is_empty()
                }
                Err(e) => {
                    ctx.report_failure("rust", format!("Failed to execute cargo outdated for {}: {}", lock_path.display(), e));
                    false
                }
            };
            outdated_ok &= per_outdated_ok;
        }

        stats.record_check(ScannerKind::Rust, "vulns", if vulns_ok { CheckStatus::Ok } else { CheckStatus::Failed });
        stats.record_check(ScannerKind::Rust, "outdated", if outdated_ok { CheckStatus::Ok } else { CheckStatus::Failed });
        Ok(())
    }
}
