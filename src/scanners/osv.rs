use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct OsvBatchQuery<'a> {
    queries: Vec<OsvQuery<'a>>,
}

#[derive(Serialize)]
struct OsvQuery<'a> {
    version: &'a str,
    package: OsvPackage<'a>,
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
}

#[derive(Deserialize)]
struct OsvVuln {
    id: String,
}

/// Takes a slice of (ecosystem, name, version) and queries OSV in chunks of 1000
pub fn fetch_vulnerabilities(
    client: &reqwest::Client,
    dependencies: &[(&str, &str, &str)],
) -> anyhow::Result<Vec<(String, String, String)>> {
    let mut found_vulns = Vec::new();

    // Scanners run on a spawn_blocking thread; block_on is the intended bridge back to async HTTP.
    tokio::runtime::Handle::current().block_on(async {
        // OSV API limits batches to 1000 queries
        for chunk in dependencies.chunks(1000) {
            let queries = chunk.iter().map(|(eco, name, ver)| OsvQuery {
                version: ver,
                package: OsvPackage { name, ecosystem: eco },
            }).collect();

            let response = client
                .post("https://api.osv.dev/v1/querybatch")
                .json(&OsvBatchQuery { queries })
                .send()
                .await?
                .error_for_status()?;

            let osv_response: OsvBatchResponse = response.json().await?;

            // OSV response ordering matches the request ordering
            for (input_dep, result) in chunk.iter().zip(osv_response.results) {
                for vuln in result.vulns {
                    found_vulns.push((input_dep.1.to_string(), input_dep.2.to_string(), vuln.id));
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    })?;

    Ok(found_vulns)
}