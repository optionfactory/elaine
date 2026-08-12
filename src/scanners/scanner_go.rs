use crate::scanners::pathcollector::Pattern;
use crate::scanners::{DependencyUpdate, RepoStats, ScanContext, Scanner, StackInspectionStatus, Vulnerability};
use serde::Deserialize;
use std::path::Path;
use std::process::Command;

#[derive(Deserialize)]
struct GoListModule {
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Version")]
    version: Option<String>,
    #[serde(rename = "Update")]
    update: Option<GoListUpdate>,
}

#[derive(Deserialize)]
struct GoListUpdate {
    #[serde(rename = "Version")]
    version: String,
}

#[derive(Deserialize)]
struct GoVulnFinding {
    finding: Option<GoVulnDetail>,
}

#[derive(Deserialize)]
struct GoVulnDetail {
    osv: String,
    fixed_version: Option<String>,
}

pub struct GolangScanner;

impl Scanner for GolangScanner {
    fn patterns(&self) -> Vec<(&'static str, Pattern)> {
        vec![("go_mods", Pattern::FileName("go.mod".to_string()))]
    }

    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
        if ctx.repo.archived || ctx.repo.fork || ctx.repo.disabled {
            return Ok(());
        }

        let Some(go_mod_paths) = ctx.matches.get("go_mods") else {
            return Ok(());
        };

        let mut go_dirs: Vec<&Path> = go_mod_paths.iter().filter_map(|p| p.parent()).collect();
        go_dirs.sort_by_key(|p| p.components().count());
        let mut selected_dirs: Vec<&Path> = Vec::new();

        for dir in go_dirs {
            let is_submodule = selected_dirs.iter().any(|selected| dir.starts_with(selected));
            if is_submodule {
                continue;
            }
            selected_dirs.push(dir);
            let run_dir = ctx.root.join(dir);

            if let Some(p) = ctx.pb {
                p.set_message(format!("[{}] Running Golang checks...", ctx.repo.name));
            }

            stats.checked_for_vulnerabilities();
            stats.checked_for_upgrades();

            let mut success = true;

            let list_cmd = Command::new("go")
                .current_dir(&run_dir)
                .args(["list", "-u", "-m", "-json", "all"])
                .output();

            match list_cmd {
                Ok(out) => {
                    let payload = String::from_utf8_lossy(&out.stdout);
                    // go list -json outputs concatenated JSON objects, which requires wrapping into a JSON array for standard parsing
                    let fixed_payload = payload.replace("}\n{", "},\n{");
                    let array_payload = format!("[{}]", fixed_payload);

                    if let Ok(parsed) = serde_json::from_str::<Vec<GoListModule>>(&array_payload) {
                        let updates: Vec<DependencyUpdate> = parsed.into_iter().filter_map(|m| {
                            let update = m.update?;
                            Some(DependencyUpdate {
                                project: ctx.repo.name.clone(),
                                kind: "module".to_string(),
                                artifact: m.path,
                                current: m.version.unwrap_or_else(|| "unknown".to_string()),
                                latest: update.version,
                            })
                        }).collect();
                        stats.add_upgrades(updates);
                    }
                }
                Err(e) => {
                    if let Some(p) = ctx.pb {
                        p.println(format!("[{}]   Failed to execute go list: {}", ctx.repo.name, e));
                    }
                    success = false;
                }
            }

            let vuln_cmd = Command::new("govulncheck")
                .current_dir(&run_dir)
                .args(["-json", "./..."])
                .output();

            match vuln_cmd {
                Ok(out) => {
                    // govulncheck outputs JSON streaming format line-by-line
                    let payload = String::from_utf8_lossy(&out.stdout);
                    for line in payload.lines() {
                        if let Ok(parsed) = serde_json::from_str::<GoVulnFinding>(line) {
                            if let Some(finding) = parsed.finding {
                                stats.add_vulnerability(Vulnerability {
                                    project: ctx.repo.name.clone(),
                                    artifact: "unknown module".to_string(),
                                    version: "unknown".to_string(),
                                    vuln_id: finding.osv,
                                    trail: vec![],
                                });
                            }
                        }
                    }
                }
                Err(e) => {
                    if let Some(p) = ctx.pb {
                        p.println(format!("[{}]   Failed to execute govulncheck: {}", ctx.repo.name, e));
                    }
                    success = false;
                }
            }

            if success {
                stats.put_stack("golang", StackInspectionStatus::Success);
            } else {
                stats.put_stack("golang", StackInspectionStatus::Failure);
            }
        }

        Ok(())
    }
}