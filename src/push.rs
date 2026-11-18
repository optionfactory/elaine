use crate::config::RemoteConfig;
use crate::server::AppState;
use crate::stats::Snapshot;
use anyhow::Context;
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use std::sync::Arc;

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

pub async fn receive_snapshot_handler(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(expected) = state.config.push_token.as_deref().filter(|t| !t.is_empty()) else {
        return (StatusCode::FORBIDDEN, "Pushing is not enabled on this server").into_response();
    };
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or_default();
    // Compares every byte, so the response time does not reveal how much of the token matched.
    let token_matches = presented.len() == expected.len() && presented.bytes().zip(expected.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if !token_matches {
        return (StatusCode::UNAUTHORIZED, "Invalid push token").into_response();
    }
    let snapshot: Snapshot = match serde_json::from_reader(GzDecoder::new(&body[..])) {
        Ok(snapshot) => snapshot,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("Invalid snapshot: {}", e)).into_response(),
    };
    let projects = snapshot.projects.len();
    let stats = Arc::clone(&state.stats);
    match tokio::task::spawn_blocking(move || stats.replace_with_snapshot(&snapshot)).await {
        Ok(Ok(())) => {
            eprintln!("[Push] Received a snapshot of {} repositories.", projects);
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
            jwks: None,
            cache: Arc::new(RwLock::new(CacheData {
                projects: vec![],
                stats: DashboardStats::calculate(&[]),
                aggregates: Aggregates::calculate(&[]),
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
        };

        let wrong = RemoteConfig {
            url: url.clone(),
            token: "guess".into(),
        };
        assert!(send_snapshot(&wrong, &snapshot).await.is_err());
        assert!(!stats.aggregate_file_path().exists());

        let right = RemoteConfig { url, token: "s3cret".into() };
        send_snapshot(&right, &snapshot).await.unwrap();
        let stored = stats.load_snapshot().unwrap();
        assert_eq!(stored.projects[0].name, "acme-api");
        assert_eq!(stored.logs["acme-api"]["npm"], "npm ERR!");
    }
}
