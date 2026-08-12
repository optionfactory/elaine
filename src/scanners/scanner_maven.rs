use crate::scanners::pathcollector::Pattern;
use crate::scanners::{CheckStatus, DependencyUpdate, RepoStats, ScanContext, Scanner, ScannerKind, Vulnerability};
use std::fs;
use std::path::Path;
use std::process::Command;

pub struct MavenScanner;
impl Scanner for MavenScanner {
    fn patterns(&self) -> Vec<(&'static str, Pattern)> {
        vec![("pom_files", Pattern::FileName("pom.xml".to_string()))]
    }
    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
        if ctx.repo.archived || ctx.repo.fork || ctx.repo.disabled {
            return Ok(());
        }
        let Some(pom_paths) = ctx.matches.get("pom_files") else {
            return Ok(());
        };
        if pom_paths.is_empty() {
            return Ok(());
        }

        let mut pom_dirs: Vec<&Path> = pom_paths.iter().filter_map(|p| p.parent()).collect();
        pom_dirs.sort_by_key(|p| p.components().count());
        let mut selected_dirs: Vec<&Path> = Vec::new();

        let mut vulns_ok = true;
        let mut outdated_ok = true;

        for dir in pom_dirs {
            let is_submodule = selected_dirs.iter().any(|selected| dir.starts_with(selected));

            if is_submodule {
                continue;
            }

            selected_dirs.push(dir);
            let run_dir = ctx.root.join(dir);

            if let Some(p) = ctx.pb {
                p.set_message(format!("[{}] Running Maven checks...", ctx.repo.name));
            }

            let output = Command::new("mvn")
                .current_dir(&run_dir)
                .args([
                    "-B",
                    "-U",
                    "-ntp",
                    "net.optionfactory:anarchitect-maven-plugin:LATEST:check-vulns",
                    "net.optionfactory:anarchitect-maven-plugin:LATEST:check-updates",
                ])
                .output();

            match output {
                Ok(out) if out.status.success() => {
                    stats.checked_for_vulnerabilities();
                    stats.checked_for_upgrades();

                    let vulns_path = run_dir.join("target").join("anarchitect-vulns.json");
                    if let Ok(payload) = fs::read_to_string(&vulns_path)
                        && let Ok(parsed_vulns) = serde_json::from_str::<Vec<Vulnerability>>(&payload)
                    {
                        stats.add_vulnerabilities(parsed_vulns);
                    } else {
                        vulns_ok = false;
                    }

                    let updates_path = run_dir.join("target").join("anarchitect-dependency-upgrades.json");
                    if let Ok(payload) = fs::read_to_string(&updates_path)
                        && let Ok(parsed_updates) = serde_json::from_str::<Vec<DependencyUpdate>>(&payload)
                    {
                        stats.add_upgrades(parsed_updates);
                    } else {
                        outdated_ok = false;
                    }
                }
                Ok(_out) => {
                    vulns_ok = false;
                    outdated_ok = false;
                    if let Some(p) = ctx.pb {
                        p.println(format!("[{}] 🔥 Maven failed", ctx.repo.name));
                    }
                }
                Err(e) => {
                    vulns_ok = false;
                    outdated_ok = false;
                    if let Some(p) = ctx.pb {
                        p.println(format!("[{}] 🔥 Failed to execute Maven: {}", ctx.repo.name, e));
                    }
                }
            }
        }

        stats.record_check(
            ScannerKind::Maven,
            "vulns",
            if vulns_ok { CheckStatus::Ok } else { CheckStatus::Failed },
        );
        stats.record_check(
            ScannerKind::Maven,
            "outdated",
            if outdated_ok { CheckStatus::Ok } else { CheckStatus::Failed },
        );
        Ok(())
    }
}
