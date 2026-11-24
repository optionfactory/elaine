use crate::scanners::pathcollector::Pattern;
use crate::scanners::{CheckStatus, Dependency, OutdatedDependency, RepoStats, ScanContext, Scanner, ScannerKind, Vulnerability};
use std::fs;
use std::path::Path;

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
        // all the roots or none: a partial list would drop the vulnerabilities of the missing roots at the next recheck
        let mut audited: Option<Vec<Dependency>> = Some(Vec::new());

        for dir in pom_dirs {
            let is_submodule = selected_dirs.iter().any(|selected| dir.starts_with(selected));

            if is_submodule {
                continue;
            }

            selected_dirs.push(dir);
            let run_dir = ctx.root.join(dir);

            ctx.set_message(format!("[{}] Running Maven checks...", ctx.repo.name));

            let output = ctx.run_logged(
                "maven",
                "mvn",
                &[
                    "-B",
                    "-U",
                    "-ntp",
                    "net.optionfactory:anarchitect-maven-plugin:LATEST:check-vulns",
                    "net.optionfactory:anarchitect-maven-plugin:LATEST:check-updates",
                ],
                &run_dir,
            );

            match output {
                Ok(out) if out.success => {
                    stats.checked_for_vulnerabilities();
                    stats.checked_for_outdated_dependencies();

                    let vulns_path = run_dir.join("target").join("anarchitect-vulnerabilities.json");
                    match fs::read_to_string(&vulns_path) {
                        Ok(payload) => match serde_json::from_str::<Vec<AuditedVulnerability>>(&payload) {
                            Ok(parsed_vulns) => stats.add_vulnerabilities(
                                ScannerKind::Maven,
                                parsed_vulns
                                    .into_iter()
                                    .map(|v| Vulnerability {
                                        build_only: v.scope.as_deref() == Some("test"),
                                        project: v.project,
                                        artifact: v.artifact,
                                        version: v.version,
                                        vuln_id: v.vuln_id,
                                        trail: v.trail,
                                        scanner: None,
                                    })
                                    .collect(),
                            ),
                            Err(e) => {
                                ctx.report_failure("maven", format!("Failed to parse {}: {}", vulns_path.display(), e));
                                vulns_ok = false;
                            }
                        },
                        Err(e) => {
                            ctx.report_failure("maven", format!("Missing or unreadable {}: {}", vulns_path.display(), e));
                            vulns_ok = false;
                        }
                    }

                    // written by anarchitect since 1.17
                    let audited_path = run_dir.join("target").join("anarchitect-dependencies.json");
                    let read = fs::read_to_string(&audited_path)
                        .ok()
                        .and_then(|payload| serde_json::from_str::<Vec<AuditedDependency>>(&payload).ok());
                    match (audited.as_mut(), read) {
                        (Some(all), Some(read)) => all.extend(read.into_iter().map(|d| Dependency {
                            ecosystem: "Maven".to_string(),
                            project: d.project,
                            artifact: d.artifact,
                            version: d.version,
                            trail: d.trail,
                            build_only: d.scope.as_deref() == Some("test"),
                        })),
                        _ => audited = None,
                    }

                    let updates_path = run_dir.join("target").join("anarchitect-outdated-dependencies.json");
                    match fs::read_to_string(&updates_path) {
                        Ok(payload) => match serde_json::from_str::<Vec<OutdatedDependency>>(&payload) {
                            Ok(parsed_updates) => stats.add_outdated_dependencies(ScannerKind::Maven, parsed_updates),
                            Err(e) => {
                                ctx.report_failure("maven", format!("Failed to parse {}: {}", updates_path.display(), e));
                                outdated_ok = false;
                            }
                        },
                        Err(e) => {
                            ctx.report_failure("maven", format!("Missing or unreadable {}: {}", updates_path.display(), e));
                            outdated_ok = false;
                        }
                    }
                }
                Ok(_out) => {
                    vulns_ok = false;
                    outdated_ok = false;
                    let dir_label = if dir.as_os_str().is_empty() {
                        ".".to_string()
                    } else {
                        dir.display().to_string()
                    };
                    ctx.report_failure("maven", format!("Maven failed for {}", dir_label));
                }
                Err(e) => {
                    vulns_ok = false;
                    outdated_ok = false;
                    let dir_label = if dir.as_os_str().is_empty() {
                        ".".to_string()
                    } else {
                        dir.display().to_string()
                    };
                    ctx.report_failure("maven", format!("Failed to execute Maven for {}: {}", dir_label, e));
                }
            }
        }

        if vulns_ok && let Some(audited) = audited {
            stats.add_checked_dependencies(ScannerKind::Maven, audited);
        }
        stats.record_check(ScannerKind::Maven, "vulns", if vulns_ok { CheckStatus::Ok } else { CheckStatus::Failed });
        stats.record_check(ScannerKind::Maven, "outdated", if outdated_ok { CheckStatus::Ok } else { CheckStatus::Failed });
        Ok(())
    }
}

/// An entry of `anarchitect-vulnerabilities.json`.
#[derive(serde::Deserialize)]
struct AuditedVulnerability {
    project: String,
    artifact: String,
    version: String,
    vuln_id: String,
    #[serde(default)]
    trail: Vec<String>,
    /// The Maven scope, written by anarchitect since 1.19: `test` only builds and tests; `provided` counts as shipped,
    /// since the container that provides it runs it.
    #[serde(default)]
    scope: Option<String>,
}

/// An entry of `anarchitect-dependencies.json`.
#[derive(serde::Deserialize)]
struct AuditedDependency {
    project: String,
    artifact: String,
    version: String,
    #[serde(default)]
    trail: Vec<String>,
    #[serde(default)]
    scope: Option<String>,
}
