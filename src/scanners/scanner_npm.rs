use crate::scanners::pathcollector::Pattern;
use crate::scanners::{DependencyUpdate, RepoStats, ScanContext, Scanner, StackInspectionStatus, Vulnerability};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

#[derive(Deserialize)]
struct NpmOutdatedDep {
    current: Option<String>,
    latest: Option<String>,
    #[serde(rename = "type")]
    dep_type: Option<String>,
}

#[derive(Deserialize)]
struct NpmAuditOutput {
    vulnerabilities: Option<HashMap<String, NpmAuditVuln>>,
}

#[derive(Deserialize)]
struct NpmAuditVuln {
    name: String,
}

pub struct NpmScanner;

impl Scanner for NpmScanner {
    fn patterns(&self) -> Vec<(&'static str, Pattern)> {
        vec![("package_jsons", Pattern::FileName("package.json".to_string()))]
    }

    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
        if ctx.repo.archived || ctx.repo.fork || ctx.repo.disabled {
            return Ok(());
        }

        let Some(package_paths) = ctx.matches.get("package_jsons") else {
            return Ok(());
        };

        let mut pkg_dirs: Vec<&Path> = package_paths.iter().filter_map(|p| p.parent()).collect();
        pkg_dirs.sort_by_key(|p| p.components().count());
        let mut selected_dirs: Vec<&Path> = Vec::new();

        for dir in pkg_dirs {
            let is_submodule = selected_dirs.iter().any(|selected| dir.starts_with(selected));
            if is_submodule {
                continue;
            }
            selected_dirs.push(dir);
            let run_dir = ctx.root.join(dir);

            if let Some(p) = ctx.pb {
                p.set_message(format!("[{}] Running NPM checks...", ctx.repo.name));
            }

            stats.checked_for_vulnerabilities();
            stats.checked_for_upgrades();

            let mut success = true;

            let outdated_cmd = Command::new("npm")
                .current_dir(&run_dir)
                .args(["outdated", "--json"])
                .output();

            match outdated_cmd {
                Ok(out) => {
                    let payload = String::from_utf8_lossy(&out.stdout);
                    if let Ok(parsed) = serde_json::from_str::<HashMap<String, NpmOutdatedDep>>(&payload) {
                        let updates: Vec<DependencyUpdate> = parsed.into_iter().filter_map(|(name, dep)| {
                            Some(DependencyUpdate {
                                project: ctx.repo.name.clone(),
                                kind: dep.dep_type.unwrap_or_else(|| "dependency".to_string()),
                                artifact: name,
                                current: dep.current?,
                                latest: dep.latest?,
                            })
                        }).collect();
                        stats.add_upgrades(updates);
                    }
                }
                Err(e) => {
                    if let Some(p) = ctx.pb {
                        p.println(format!("[{}]   Failed to execute npm outdated: {}", ctx.repo.name, e));
                    }
                    success = false;
                }
            }

            let audit_cmd = Command::new("npm")
                .current_dir(&run_dir)
                .args(["audit", "--json"])
                .output();

            match audit_cmd {
                Ok(out) => {
                    let payload = String::from_utf8_lossy(&out.stdout);
                    if let Ok(parsed) = serde_json::from_str::<NpmAuditOutput>(&payload) {
                        if let Some(vulns_map) = parsed.vulnerabilities {
                            let vulns: Vec<Vulnerability> = vulns_map.into_values().map(|v| Vulnerability {
                                project: ctx.repo.name.clone(),
                                artifact: v.name.clone(),
                                version: "unknown".to_string(), 
                                vuln_id: "npm-audit-vuln".to_string(),
                                trail: vec![],
                            }).collect();
                            stats.add_vulnerabilities(vulns);
                        }
                    }
                }
                Err(e) => {
                    if let Some(p) = ctx.pb {
                        p.println(format!("[{}]   Failed to execute npm audit: {}", ctx.repo.name, e));
                    }
                    success = false;
                }
            }

            if success {
                stats.put_stack("npm", StackInspectionStatus::Success);
            } else {
                stats.put_stack("npm", StackInspectionStatus::Failure);
            }
        }
        Ok(())
    }
}