use crate::scanners::osv::{Locked, check_locked, lock};
use crate::scanners::pathcollector::Pattern;
use crate::scanners::{CheckStatus, OutdatedDependency, RepoStats, ScanContext, Scanner, ScannerKind};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
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

/// What `cargo metadata --filter-platform` says of the workspace: the crates built for that platform only, and the
/// kinds of each dependency.
#[derive(Deserialize)]
struct Metadata {
    packages: Vec<MetadataPackage>,
    workspace_members: Vec<String>,
    resolve: MetadataResolve,
}

#[derive(Deserialize)]
struct MetadataPackage {
    id: String,
    name: String,
    version: String,
    source: Option<String>,
    targets: Vec<MetadataTarget>,
}

#[derive(Deserialize)]
struct MetadataTarget {
    kind: Vec<String>,
}

#[derive(Deserialize)]
struct MetadataResolve {
    nodes: Vec<MetadataNode>,
}

#[derive(Deserialize)]
struct MetadataNode {
    id: String,
    deps: Vec<MetadataDep>,
}

#[derive(Deserialize)]
struct MetadataDep {
    pkg: String,
    dep_kinds: Vec<MetadataDepKind>,
}

#[derive(Deserialize)]
struct MetadataDepKind {
    /// `dev` or `build`; none for a normal dependency.
    kind: Option<String>,
}

const CRATES_IO: [&str; 2] = ["registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"];

impl Metadata {
    /// The crates.io crates built for Linux amd64, each with whether it only builds or tests the workspace: shipped
    /// are the crates the members reach through normal dependencies, without passing through a proc macro, whose code
    /// runs in the compiler.
    fn locked(&self) -> Locked {
        let packages: HashMap<&str, &MetadataPackage> = self.packages.iter().map(|p| (p.id.as_str(), p)).collect();
        let nodes: HashMap<&str, &MetadataNode> = self.resolve.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        let proc_macro = |id: &str| {
            packages
                .get(id)
                .is_some_and(|p| p.targets.iter().any(|t| t.kind.iter().any(|k| k == "proc-macro")))
        };
        let mut shipped: HashSet<&str> = HashSet::new();
        let mut pending: Vec<&str> = self.workspace_members.iter().map(String::as_str).collect();
        while let Some(id) = pending.pop() {
            if !shipped.insert(id) {
                continue;
            }
            for dep in nodes.get(id).map(|n| n.deps.as_slice()).unwrap_or_default() {
                if dep.dep_kinds.iter().any(|k| k.kind.is_none()) && !proc_macro(&dep.pkg) {
                    pending.push(&dep.pkg);
                }
            }
        }
        let mut locked = Locked::new();
        for p in self.packages.iter().filter(|p| p.source.as_deref().is_some_and(|s| CRATES_IO.contains(&s))) {
            lock(&mut locked, &p.name, &p.version, !shipped.contains(p.id.as_str()));
        }
        locked
    }
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
            let args = ["metadata", "--format-version", "1", "--locked", "--filter-platform", "x86_64-unknown-linux-gnu"];
            let metadata = match ctx.run_logged("rust", "cargo", &args, &run_dir) {
                Ok(out) if out.success => serde_json::from_slice::<Metadata>(&out.stdout).map_err(anyhow::Error::from),
                Ok(out) => Err(anyhow::anyhow!("{}", String::from_utf8_lossy(&out.stderr).trim())),
                Err(e) => Err(e),
            };
            let locked = match metadata {
                Ok(metadata) => Some(metadata.locked()),
                // a git dependency out of reach, say: every crate of the lockfile, all of them counted as shipped
                Err(e) => {
                    ctx.report_failure(
                        "rust",
                        format!(
                            "cargo metadata failed for {}, every locked crate counted as shipped: {}",
                            lock_path.display(),
                            e
                        ),
                    );
                    match fs::read_to_string(ctx.root.join(lock_path))
                        .map_err(anyhow::Error::from)
                        .and_then(|c| Ok(toml::from_str::<CargoLock>(&c)?))
                    {
                        Ok(CargoLock { package: Some(packages) }) => {
                            let mut locked = Locked::new();
                            for p in packages.iter().filter(|p| p.source.as_deref().is_some_and(|s| CRATES_IO.contains(&s))) {
                                lock(&mut locked, &p.name, &p.version, false);
                            }
                            Some(locked)
                        }
                        Ok(CargoLock { package: None }) => {
                            ctx.report_failure("rust", format!("No 'package' table in {}", lock_path.display()));
                            None
                        }
                        Err(e) => {
                            ctx.report_failure("rust", format!("Failed to read Cargo.lock {}: {}", lock_path.display(), e));
                            None
                        }
                    }
                }
            };
            let per_vulns_ok = locked.is_some_and(|locked| check_locked(ctx, stats, (ScannerKind::Rust, "rust"), "crates.io", lock_path, &locked));
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
                            ScannerKind::Rust,
                            output
                                .dependencies
                                .iter()
                                .map(|dep| OutdatedDependency {
                                    project: ctx.repo.name.clone(),
                                    kind: dep.kind.clone().unwrap_or_else(|| "Normal".to_string()),
                                    artifact: dep.name.clone(),
                                    current: dep.project.clone(),
                                    latest: dep.latest.clone(),
                                    ..Default::default()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crates_reached_only_through_dev_build_or_proc_macro_dependencies_only_build() {
        let crate_id = |name: &str| format!("registry+https://github.com/rust-lang/crates.io-index#{name}@1.0.0");
        let package = |name: &str, kind: &str| {
            format!(
                r#"{{"id": "{}", "name": "{name}", "version": "1.0.0", "source": "{}", "targets": [{{"kind": ["{kind}"]}}]}}"#,
                crate_id(name),
                CRATES_IO[0]
            )
        };
        let dep = |name: &str, kind: &str| format!(r#"{{"pkg": "{}", "dep_kinds": [{{"kind": {kind}}}]}}"#, crate_id(name));
        let json = format!(
            r#"{{
                "packages": [
                    {{"id": "path+file:///app#0.1.0", "name": "app", "version": "0.1.0", "source": null, "targets": [{{"kind": ["bin"]}}]}},
                    {}, {}, {}, {}, {}
                ],
                "workspace_members": ["path+file:///app#0.1.0"],
                "resolve": {{"nodes": [
                    {{"id": "path+file:///app#0.1.0", "deps": [{}, {}, {}, {}]}},
                    {{"id": "{}", "deps": [{}]}}
                ]}}
            }}"#,
            package("tokio", "lib"),
            package("serde_derive", "proc-macro"),
            package("syn", "lib"),
            package("cc", "lib"),
            package("mockito", "lib"),
            dep("tokio", "null"),
            dep("serde_derive", "null"),
            dep("cc", r#""build""#),
            dep("mockito", r#""dev""#),
            crate_id("serde_derive"),
            dep("syn", "null"),
        );
        let metadata: Metadata = serde_json::from_str(&json).unwrap();
        let build_only: Vec<_> = metadata.locked().into_iter().map(|((name, _), build_only)| (name, build_only)).collect();
        assert_eq!(
            build_only,
            [
                ("cc".into(), true),
                ("mockito".into(), true),
                ("serde_derive".into(), true),
                ("syn".into(), true),
                ("tokio".into(), false)
            ]
        );
    }
}
