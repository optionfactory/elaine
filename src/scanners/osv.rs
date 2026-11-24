use crate::scanners::{Dependency, RepoStats, ScanContext, ScannerKind, Vulnerability};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Serialize)]
struct OsvBatchQuery<'a> {
    queries: Vec<OsvQuery<'a>>,
}

#[derive(Serialize)]
struct OsvQuery<'a> {
    version: &'a str,
    package: OsvPackage<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    page_token: Option<&'a str>,
}

#[derive(Serialize)]
struct OsvPackage<'a> {
    name: &'a str,
    ecosystem: &'a str,
}

#[derive(Deserialize)]
struct OsvBatchResponse {
    results: Vec<OsvResult>,
}

#[derive(Deserialize)]
struct OsvResult {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
    #[serde(default)]
    next_page_token: Option<String>,
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
}

/// Takes a slice of (ecosystem, name, version) and queries OSV in batches of 1000,
/// following per-package `next_page` tokens so dependencies with >1000 vulnerabilities
/// are not silently truncated.
pub fn fetch_vulnerabilities(client: &reqwest::Client, dependencies: &[(&str, &str, &str)]) -> anyhow::Result<Vec<(String, String, String)>> {
    // Scanners run on a spawn_blocking thread; block_on is the intended bridge back to async HTTP.
    let found_vulns = tokio::runtime::Handle::current().block_on(async {
        let mut found_vulns = Vec::new();
        // pending entries carry an optional next_page token populated from the previous round.
        let mut pending: Vec<(&str, &str, &str, Option<String>)> = dependencies.iter().map(|(eco, name, ver)| (*eco, *name, *ver, None)).collect();

        while !pending.is_empty() {
            let mut next_round = Vec::new();

            for chunk in pending.chunks(1000) {
                let queries = chunk
                    .iter()
                    .map(|(eco, name, ver, token)| OsvQuery {
                        version: ver,
                        package: OsvPackage { name, ecosystem: eco },
                        page_token: token.as_deref(),
                    })
                    .collect();

                let response = client
                    .post("https://api.osv.dev/v1/querybatch")
                    .json(&OsvBatchQuery { queries })
                    .send()
                    .await?
                    .error_for_status()?;

                let osv_response: OsvBatchResponse = response.json().await?;

                // OSV response ordering matches the request ordering.
                for (dep, result) in chunk.iter().zip(osv_response.results) {
                    for vuln in result.vulns {
                        found_vulns.push((dep.1.to_string(), dep.2.to_string(), vuln.id));
                    }
                    if let Some(token) = result.next_page_token {
                        next_round.push((dep.0, dep.1, dep.2, Some(token)));
                    }
                }
            }

            pending = next_round;
        }

        Ok::<_, anyhow::Error>(found_vulns)
    })?;

    Ok(found_vulns)
}

/// Each `(artifact, version)` of a lockfile, with whether it only builds or tests the repository: a version the
/// lockfile holds several times is shipped when any of them is.
pub type Locked = BTreeMap<(String, String), bool>;

pub fn lock(locked: &mut Locked, artifact: &str, version: &str, build_only: bool) {
    locked
        .entry((artifact.to_string(), version.to_string()))
        .and_modify(|known| *known &= build_only)
        .or_insert(build_only);
}

/// Checks the locked dependencies against OSV and records them with the vulnerabilities found; false, with the
/// failure in the scanner's log, when OSV fails.
pub fn check_locked(ctx: &ScanContext, stats: &mut RepoStats, scanner: (ScannerKind, &str), ecosystem: &str, manifest: &Path, locked: &Locked) -> bool {
    let (scanner, log) = scanner;
    let queries: Vec<(&str, &str, &str)> = locked
        .keys()
        .map(|(artifact, version)| (ecosystem, artifact.as_str(), version.as_str()))
        .collect();
    match fetch_vulnerabilities(ctx.client, &queries) {
        Ok(found) => {
            stats.add_checked_dependencies(
                scanner,
                locked.iter().map(|((artifact, version), build_only)| Dependency {
                    ecosystem: ecosystem.to_string(),
                    project: ctx.repo.name.clone(),
                    artifact: artifact.clone(),
                    version: version.clone(),
                    trail: vec![],
                    build_only: *build_only,
                }),
            );
            let vulnerabilities = found
                .into_iter()
                .map(|(artifact, version, vuln_id)| Vulnerability {
                    project: ctx.repo.name.clone(),
                    build_only: locked.get(&(artifact.clone(), version.clone())).copied().unwrap_or(false),
                    artifact,
                    version,
                    vuln_id,
                    ..Default::default()
                })
                .collect();
            stats.add_vulnerabilities(scanner, vulnerabilities);
            true
        }
        Err(e) => {
            ctx.report_failure(log, format!("OSV check failed for {}: {}", manifest.display(), e));
            false
        }
    }
}
