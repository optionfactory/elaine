use crate::scanners::pathcollector::Pattern;
use crate::scanners::{DependencyUpdate, RepoStats, ScanContext, Scanner, StackInspectionStatus, Vulnerability};
use crate::scanners::osv::fetch_vulnerabilities;
use serde::Deserialize;
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

pub struct GolangScanner;

impl Scanner for GolangScanner {
    fn patterns(&self) -> Vec<(&'static str, Pattern)> {
        vec![("go_mods", Pattern::FileName("go.mod".to_string()))]
    }

    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
        if ctx.repo.archived || ctx.repo.fork || ctx.repo.disabled {
            return Ok(());
        }

        let Some(go_mod_paths) = ctx.matches.get("go_mods") else { return Ok(()) };

        for mod_path in go_mod_paths {
            let run_dir = ctx.root.join(mod_path).parent().unwrap().to_path_buf();
            
            stats.checked_for_vulnerabilities();
            stats.checked_for_upgrades();

            let list_cmd = Command::new("go")
                .current_dir(&run_dir)
                .args(["list", "-u", "-m", "-json", "all"])
                .output();

            if let Ok(out) = list_cmd {
                let payload = String::from_utf8_lossy(&out.stdout);
                let fixed_payload = payload.replace("}\n{", "},\n{");
                let array_payload = format!("[{}]", fixed_payload);

                if let Ok(parsed) = serde_json::from_str::<Vec<GoListModule>>(&array_payload) {
                    
                    let updates: Vec<DependencyUpdate> = parsed.iter().filter_map(|m| {
                        let update = m.update.as_ref()?;
                        Some(DependencyUpdate {
                            project: ctx.repo.name.clone(),
                            kind: "module".to_string(),
                            artifact: m.path.clone(),
                            current: m.version.clone().unwrap_or_else(|| "unknown".to_string()),
                            latest: update.version.clone(),
                        })
                    }).collect();
                    stats.add_upgrades(updates);

                    let mut osv_deps = Vec::new();
                    for m in &parsed {
                        if let Some(ref version) = m.version {
                            osv_deps.push(("Go", m.path.as_str(), version.as_str()));
                        }
                    }

                    if let Ok(vulns) = fetch_vulnerabilities(&osv_deps) {
                        let vulnerabilities = vulns.into_iter().map(|(pkg, id)| Vulnerability {
                            project: ctx.repo.name.clone(),
                            artifact: pkg,
                            version: "unknown".to_string(),
                            vuln_id: id,
                            trail: vec![],
                        }).collect();
                        stats.add_vulnerabilities(vulnerabilities);
                        stats.put_stack("golang", StackInspectionStatus::Success);
                    } else {
                        stats.put_stack("golang", StackInspectionStatus::Failure);
                    }
                } else {
                    stats.put_stack("golang", StackInspectionStatus::Failure);
                }
            } else {
                stats.put_stack("golang", StackInspectionStatus::Failure);
            }
        }
        Ok(())
    }
}