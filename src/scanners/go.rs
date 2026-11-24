use crate::scanners::osv::fetch_vulnerabilities;
use crate::scanners::pathcollector::Pattern;
use crate::scanners::{CheckStatus, Dependency, OutdatedDependency, RepoStats, ScanContext, Scanner, ScannerKind, Vulnerability};
use serde::Deserialize;
use std::collections::BTreeSet;

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

/// A package of `go list -deps -json=Module`: no module for the standard library.
#[derive(Deserialize)]
struct GoListPackage {
    #[serde(rename = "Module")]
    module: Option<GoListPackageModule>,
}

#[derive(Deserialize)]
struct GoListPackageModule {
    #[serde(rename = "Path")]
    path: String,
    /// Missing for the main module and the other modules of a workspace.
    #[serde(rename = "Version")]
    version: Option<String>,
}

/// The modules some package of the repository, its tests included, compiles code from. The module graph of
/// `go list -m all` also holds modules only required by a dependency's `go.mod`, which never reach the binary.
fn compiled_modules(go_list: &[u8]) -> serde_json::Result<BTreeSet<(String, String)>> {
    let mut modules = BTreeSet::new();
    for package in serde_json::Deserializer::from_slice(go_list).into_iter::<GoListPackage>() {
        if let Some(GoListPackageModule { path, version: Some(version) }) = package?.module {
            modules.insert((path, version));
        }
    }
    Ok(modules)
}

pub struct GoScanner;

impl Scanner for GoScanner {
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
        if go_mod_paths.is_empty() {
            return Ok(());
        }

        stats.checked_for_vulnerabilities();
        stats.checked_for_outdated_dependencies();

        let mut vulns_ok = true;
        let mut outdated_ok = true;

        for mod_path in go_mod_paths {
            let run_dir = ctx.root.join(mod_path).parent().unwrap().to_path_buf();
            ctx.set_message(format!("[{}] Running Go checks...", ctx.repo.name));

            let out = match ctx.run_logged("go", "go", &["list", "-u", "-m", "-json", "all"], &run_dir) {
                Ok(out) => out,
                Err(e) => {
                    ctx.report_failure("go", format!("Failed to execute go for {}: {}", mod_path.display(), e));
                    vulns_ok = false;
                    outdated_ok = false;
                    continue;
                }
            };
            let payload = String::from_utf8_lossy(&out.stdout);
            let fixed_payload = payload.replace("}\n{", "},\n{");
            let array_payload = format!("[{}]", fixed_payload);

            let Ok(parsed) = serde_json::from_str::<Vec<GoListModule>>(&array_payload) else {
                ctx.report_failure("go", format!("Failed to parse go list output for {}", mod_path.display()));
                vulns_ok = false;
                outdated_ok = false;
                continue;
            };

            let updates: Vec<OutdatedDependency> = parsed
                .iter()
                .filter_map(|m| {
                    let update = m.update.as_ref()?;
                    Some(OutdatedDependency {
                        project: ctx.repo.name.clone(),
                        kind: "module".to_string(),
                        artifact: m.path.clone(),
                        current: m.version.clone().unwrap_or_else(|| "unknown".to_string()),
                        latest: update.version.clone(),
                        ..Default::default()
                    })
                })
                .collect();
            stats.add_outdated_dependencies(ScannerKind::Go, updates);

            let compiled = match ctx.run_logged("go", "go", &["list", "-e", "-deps", "-test", "-json=Module", "./..."], &run_dir) {
                Ok(out) if out.success => compiled_modules(&out.stdout).map_err(anyhow::Error::from),
                Ok(out) => Err(anyhow::anyhow!("{}", String::from_utf8_lossy(&out.stderr).trim())),
                Err(e) => Err(e),
            };
            let compiled = match compiled {
                Ok(compiled) => compiled,
                Err(e) => {
                    ctx.report_failure("go", format!("Failed to list the compiled packages of {}: {}", mod_path.display(), e));
                    vulns_ok = false;
                    continue;
                }
            };
            let osv_deps: Vec<(&str, &str, &str)> = compiled.iter().map(|(path, version)| ("Go", path.as_str(), version.as_str())).collect();

            match fetch_vulnerabilities(ctx.client, &osv_deps) {
                Ok(vulns) => {
                    stats.add_checked_dependencies(
                        ScannerKind::Go,
                        osv_deps.iter().map(|(ecosystem, name, version)| Dependency {
                            ecosystem: ecosystem.to_string(),
                            project: ctx.repo.name.clone(),
                            artifact: name.to_string(),
                            version: version.to_string(),
                            trail: vec![],
                        }),
                    );
                    let vulnerabilities = vulns
                        .into_iter()
                        .map(|(pkg, ver, id)| Vulnerability {
                            project: ctx.repo.name.clone(),
                            artifact: pkg,
                            version: ver,
                            vuln_id: id,
                            ..Default::default()
                        })
                        .collect();
                    stats.add_vulnerabilities(ScannerKind::Go, vulnerabilities);
                }
                Err(e) => {
                    ctx.report_failure("go", format!("OSV check failed for {}: {}", mod_path.display(), e));
                    vulns_ok = false;
                }
            }
        }

        stats.record_check(ScannerKind::Go, "vulns", if vulns_ok { CheckStatus::Ok } else { CheckStatus::Failed });
        stats.record_check(ScannerKind::Go, "outdated", if outdated_ok { CheckStatus::Ok } else { CheckStatus::Failed });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_modules_with_compiled_packages_are_checked() {
        let go_list = br#"{}
{"Module": {"Path": "github.com/acme/service", "Main": true}}
{"Module": {"Path": "github.com/valyala/fasthttp", "Version": "v1.80.0"}}
{"Module": {"Path": "github.com/valyala/fasthttp", "Version": "v1.80.0"}}
{"Module": {"Path": "golang.org/x/net", "Version": "v0.63.0"}}
"#;
        let modules: Vec<_> = compiled_modules(go_list).unwrap().into_iter().map(|(path, _)| path).collect();
        assert_eq!(modules, ["github.com/valyala/fasthttp", "golang.org/x/net"]);
    }
}
