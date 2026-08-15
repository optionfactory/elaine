use serde::{Deserialize, Serialize};

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
