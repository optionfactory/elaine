use crate::alert;
use crate::config::RemoteConfig;
use crate::scanners::RepoStats;
use crate::server::AppState;
use crate::stats::Snapshot;
use anyhow::Context;
use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

/// A real snapshot of a few hundred repositories is about 1 MB gzipped and 10 MB of JSON: the bounds leave room for
/// growth and keep a push from filling the memory of the server.
pub const MOST_PUSH_BYTES: usize = 16 * 1024 * 1024;
const MOST_SNAPSHOT_BYTES: u64 = 256 * 1024 * 1024;

/// Sends `snapshot` as gzipped JSON to the `elaine serve` instance at `remote`, replacing what it shows.
pub async fn send_snapshot(remote: &RemoteConfig, snapshot: &Snapshot) -> anyhow::Result<()> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    serde_json::to_writer(&mut encoder, snapshot)?;
    let body = encoder.finish()?;
    let url = format!("{}/api/snapshot", remote.url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .put(&url)
        .bearer_auth(&remote.token)
        .header(header::CONTENT_TYPE, "application/gzip")
        .body(body)
        .send()
        .await
        .with_context(|| format!("Failed to reach {}", url))?;
    let status = response.status();
    if !status.is_success() {
        let reason = response.text().await.unwrap_or_default();
        anyhow::bail!("{} refused the snapshot: {} {}", url, status, reason);
    }
    Ok(())
}

/// The token is checked before the body is read, so that a request without it costs the server nothing; the body is
/// bounded gzipped and unzipped, and unzipped and parsed away from the threads that answer the other requests.
pub async fn receive_snapshot_handler(State(state): State<Arc<AppState>>, request: Request) -> Response {
    let Some(expected) = state.config.push_token.as_deref().filter(|t| !t.is_empty()) else {
        return (StatusCode::FORBIDDEN, "Pushing is not enabled on this server").into_response();
    };
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or_default();
    // Compares every byte, so the response time does not reveal how much of the token matched.
    let token_matches = presented.len() == expected.len() && presented.bytes().zip(expected.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if !token_matches {
        eprintln!("[Push] Refused a push with an invalid token.");
        return (StatusCode::UNAUTHORIZED, "Invalid push token").into_response();
    }
    let body = match axum::body::to_bytes(request.into_body(), MOST_PUSH_BYTES).await {
        Ok(body) => body,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "The push is larger than the server takes").into_response(),
    };
    let organization = state.config.organization.clone();
    let parsed = tokio::task::spawn_blocking(move || {
        let mut json = Vec::new();
        GzDecoder::new(&body[..])
            .take(MOST_SNAPSHOT_BYTES + 1)
            .read_to_end(&mut json)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid snapshot: {}", e)))?;
        if json.len() as u64 > MOST_SNAPSHOT_BYTES {
            return Err((StatusCode::PAYLOAD_TOO_LARGE, "The snapshot is larger than the server takes".to_string()));
        }
        let snapshot: Snapshot = serde_json::from_slice(&json).map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid snapshot: {}", e)))?;
        // the pages and the mails link each repository to it: only GitHub, under the organization
        let prefix = format!("https://github.com/{}/", organization);
        if let Some(stray) = snapshot.projects.iter().find(|p| !p.html_url.is_empty() && !p.html_url.starts_with(&prefix)) {
            return Err((StatusCode::BAD_REQUEST, format!("Invalid snapshot: {} links outside {}", stray.name, prefix)));
        }
        Ok(snapshot)
    })
    .await;
    let snapshot = match parsed {
        Ok(Ok(snapshot)) => snapshot,
        Ok(Err((status, reason))) => {
            eprintln!("[Push] Refused a push: {}", reason);
            return (status, reason).into_response();
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to read the snapshot: {}", e)).into_response(),
    };
    let stats = Arc::clone(&state.stats);
    let stored = tokio::task::spawn_blocking(move || {
        let previous = std::fs::read_to_string(stats.aggregate_file_path())
            .ok()
            .and_then(|data| serde_json::from_str::<Vec<RepoStats>>(&data).ok());
        let previous_images = stats.load_images().ok();
        stats
            .replace_with_snapshot(&snapshot)
            .map(|()| (previous, previous_images, snapshot.projects, snapshot.images))
    });
    match stored.await {
        Ok(Ok((previous, previous_images, projects, images))) => {
            eprintln!("[Push] Received a snapshot of {} repositories.", projects.len());
            if let Some(alerts) = state.config.alerts.clone() {
                let dashboard = state.config.login.as_ref().map(|login| login.public_url.clone());
                // the push answers at once; a mail that fails is only logged
                tokio::spawn(async move {
                    let empty = BTreeMap::new();
                    let previous = previous.as_deref().map(|projects| alert::Scan {
                        projects,
                        images: previous_images.as_ref().unwrap_or(&empty),
                    });
                    let current = alert::Scan {
                        projects: &projects,
                        images: &images,
                    };
                    if let Err(e) = alert::notify(&alerts, previous, current, dashboard.as_deref()).await {
                        eprintln!("[Alert] Failed to mail the new vulnerabilities: {:#}", e);
                    }
                });
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(e)) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store snapshot: {:#}", e)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store snapshot: {}", e)).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::GithubRepository;
    use crate::scanners::RepoStats;
    use crate::server::{CacheData, DashboardStats, aggregates::Aggregates};
    use crate::stats::StatsStore;
    use std::collections::BTreeMap;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn only_the_configured_token_replaces_the_server_stats() {
        let data_dir = tempfile::TempDir::new().unwrap();
        let config = serde_json::from_value(serde_json::json!({
            "organization": "acme",
            "data_dir": data_dir.path(),
            "push_token": "s3cret",
        }))
        .unwrap();
        let stats = Arc::new(StatsStore::new(data_dir.path()).unwrap());
        let state = Arc::new(AppState {
            config,
            http_client: reqwest::Client::new(),
            session_key: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"test"),
            cache: Arc::new(RwLock::new(CacheData {
                projects: vec![],
                images: Default::default(),
                stats: DashboardStats::calculate(&[]),
                aggregates: Aggregates::calculate(&[], &Default::default()),
            })),
            stats: Arc::clone(&stats),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(axum::serve(listener, crate::server::routes::create_router(state, false)).into_future());

        let repo = GithubRepository {
            name: "acme-api".into(),
            ..Default::default()
        };
        let snapshot = Snapshot {
            projects: vec![RepoStats::new_from_github(&repo)],
            logs: BTreeMap::from([("acme-api".into(), BTreeMap::from([("npm".into(), "npm ERR!".into())]))]),
            images: BTreeMap::new(),
        };

        let wrong = RemoteConfig {
            url: url.clone(),
            token: "guess".into(),
        };
        assert!(send_snapshot(&wrong, &snapshot).await.is_err());
        assert!(!stats.aggregate_file_path().exists());

        let right = RemoteConfig { url, token: "s3cret".into() };
        let mut stray = RepoStats::new_from_github(&repo);
        stray.html_url = "https://evil.example/acme-api".into();
        let elsewhere = Snapshot {
            projects: vec![stray],
            logs: BTreeMap::new(),
            images: BTreeMap::new(),
        };
        assert!(send_snapshot(&right, &elsewhere).await.is_err());
        assert!(!stats.aggregate_file_path().exists());

        send_snapshot(&right, &snapshot).await.unwrap();
        let stored = stats.load_snapshot().unwrap();
        assert_eq!(stored.projects[0].name, "acme-api");
        assert_eq!(stored.logs["acme-api"]["npm"], "npm ERR!");
    }
}
