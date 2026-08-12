use crate::scanners::pathcollector::Pattern;
use crate::scanners::{DependencyUpdate, RepoStats, ScanContext, Scanner, StackInspectionStatus, Vulnerability};
use serde::Deserialize;
use std::path::Path;
use std::process::Command;

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

#[derive(Deserialize)]
struct AuditOutput {
    vulnerabilities: AuditVulnerabilities,
}

#[derive(Deserialize)]
struct AuditVulnerabilities {
    list: Vec<AuditVuln>,
}

#[derive(Deserialize)]
struct AuditVuln {
    advisory: Advisory,
    package: Package,
}

#[derive(Deserialize)]
struct Advisory {
    id: String,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    version: String,
}

pub struct RustScanner;

impl Scanner for RustScanner {
    fn patterns(&self) -> Vec<(&'static str, Pattern)> {
        vec![("cargo_tomls", Pattern::FileName("Cargo.toml".to_string()))]
    }

    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
        if ctx.repo.archived || ctx.repo.fork || ctx.repo.disabled {
            return Ok(());
        }

        let Some(cargo_paths) = ctx.matches.get("cargo_tomls") else {
            return Ok(());
        };

        let mut cargo_dirs: Vec<&Path> = cargo_paths.iter().filter_map(|p| p.parent()).collect();
        cargo_dirs.sort_by_key(|p| p.components().count());
        let mut selected_dirs: Vec<&Path> = Vec::new();

        for dir in cargo_dirs {
            let is_submodule = selected_dirs.iter().any(|selected| dir.starts_with(selected));
            if is_submodule {
                continue;
            }
            selected_dirs.push(dir);
            let run_dir = ctx.root.join(dir);

            if let Some(p) = ctx.pb {
                p.set_message(format!("[{}] Running Cargo checks...", ctx.repo.name));
            }

            stats.checked_for_vulnerabilities();
            stats.checked_for_upgrades();

            let mut success = true;

            let outdated_cmd = Command::new("cargo")
                .current_dir(&run_dir)
                .args(["outdated", "--format", "json", "--workspace"])
                .output();

            match outdated_cmd {
                Ok(out) => {
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
                }
                Err(e) => {
                    if let Some(p) = ctx.pb {
                        p.println(format!("[{}]   Failed to execute cargo outdated: {}", ctx.repo.name, e));
                    }
                    success = false;
                }
            }

            let audit_cmd = Command::new("cargo")
                .current_dir(&run_dir)
                .args(["audit", "--json"])
                .output();

            match audit_cmd {
                Ok(out) => {
                    if let Ok(payload) = String::from_utf8(out.stdout) {
                        if let Ok(parsed) = serde_json::from_str::<AuditOutput>(&payload) {
                            let vulns: Vec<Vulnerability> = parsed.vulnerabilities.list.into_iter().map(|v| Vulnerability {
                                project: ctx.repo.name.clone(),
                                artifact: v.package.name,
                                version: v.package.version,
                                vuln_id: v.advisory.id,
                                trail: vec![], // Dependency trail not natively exposed in basic audit JSON 
                            }).collect();
                            stats.add_vulnerabilities(vulns);
                        }
                    }
                }
                Err(e) => {
                    if let Some(p) = ctx.pb {
                        p.println(format!("[{}]   Failed to execute cargo audit: {}", ctx.repo.name, e));
                    }
                    success = false;
                }
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