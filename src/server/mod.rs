pub mod routes;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GoogleAuthConfig {
    pub client_id: String,
    pub hosted_domain: Option<String>,
}

#[derive(Deserialize, Clone)]
pub struct Config {
    pub github_token: Option<String>,
    pub organization: String,
    pub address: Option<String>,
    pub port: Option<u16>,
    pub data_dir: std::path::PathBuf,
    pub google_auth: Option<GoogleAuthConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DashboardStats {
    pub all: usize,
    pub live: usize,
    pub live_audited: usize,
    pub live_unaudited: usize,
}

impl DashboardStats {
    pub fn calculate(projects: &[crate::scanners::RepoStats]) -> Self {
        let mut s = Self::default();
        for r in projects {
            s.all += 1;
            if r.archived {
                continue;
            }
            s.live += 1;
            if r.manifest.is_some() {
                s.live_audited += 1;
            } else {
                s.live_unaudited += 1;
            }
        }
        s
    }
}

pub struct CacheData {
    pub projects: Vec<crate::scanners::RepoStats>,
    pub stats: DashboardStats,
}

pub struct AppState {
    pub config: Config,
    pub http_client: reqwest::Client,
    pub jwks: Option<Arc<JwksCache>>,
    pub cache: Arc<RwLock<CacheData>>,
}

/// Google JWKS cache with on-miss refresh, rate-limited so bogus 'kid's
/// cannot turn the endpoint into a fetch amplifier.
pub struct JwksCache {
    keys: Arc<RwLock<JwksCacheInner>>,
}

struct JwksCacheInner {
    keys: jsonwebtoken::jwk::JwkSet,
    last_refresh: std::time::Instant,
}

const JWKS_REFRESH_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

impl JwksCache {
    pub fn new(keys: jsonwebtoken::jwk::JwkSet) -> Self {
        Self {
            keys: Arc::new(RwLock::new(JwksCacheInner {
                keys,
                last_refresh: std::time::Instant::now(),
            })),
        }
    }

    pub async fn find(&self, kid: &str) -> Option<jsonwebtoken::jwk::Jwk> {
        self.keys.read().await.find(kid).cloned()
    }

    /// Refetches the JWKS on an unknown 'kid' unless a refresh happened
    /// very recently. Returns the (possibly updated) key for `kid`.
    pub async fn refresh_and_find(&self, client: &reqwest::Client, kid: &str) -> Option<jsonwebtoken::jwk::Jwk> {
        let mut guard = self.keys.write().await;
        // Double-check: another request may have refreshed while we waited on the lock.
        if let Some(jwk) = guard.find(kid) {
            return Some(jwk.clone());
        }
        if guard.last_refresh.elapsed() < JWKS_REFRESH_MIN_INTERVAL {
            return None;
        }
        let keys = fetch_jwks(client).await.ok()?;
        guard.keys = keys;
        guard.last_refresh = std::time::Instant::now();
        guard.find(kid).cloned()
    }
}

impl JwksCacheInner {
    fn find(&self, kid: &str) -> Option<&jsonwebtoken::jwk::Jwk> {
        self.keys.find(kid)
    }
}

pub async fn fetch_jwks(client: &reqwest::Client) -> anyhow::Result<jsonwebtoken::jwk::JwkSet> {
    client
        .get("https://www.googleapis.com/oauth2/v3/certs")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .map_err(Into::into)
}

#[derive(RustEmbed)]
#[folder = "src/frontend/"]
pub struct FrontendAssets;

#[derive(Debug)]
pub struct AuthError(pub String);

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, self.0).into_response()
    }
}

pub struct ValidatedUser;

#[axum::async_trait]
impl<S> FromRequestParts<S> for ValidatedUser
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = Arc::<AppState>::from_ref(state);
        let Some(google_auth) = &app_state.config.google_auth else {
            return Ok(ValidatedUser);
        };

        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "));

        let Some(token) = auth_header else {
            return Err(AuthError("Missing Bearer token".into()));
        };

        let Some(jwks_cache) = app_state.jwks.as_ref() else {
            return Err(AuthError("Google JWKS not loaded on server".into()));
        };

        let header = jsonwebtoken::decode_header(token).map_err(|_| AuthError("Invalid token header".into()))?;
        let kid = header.kid.ok_or_else(|| AuthError("Missing 'kid' in token header".into()))?;
        let jwk = match jwks_cache.find(&kid).await {
            Some(jwk) => jwk,
            // Key rotation: refetch once and retry before rejecting.
            None => jwks_cache
                .refresh_and_find(&app_state.http_client, &kid)
                .await
                .ok_or_else(|| AuthError("Unknown 'kid'".into()))?,
        };
        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(&jwk).map_err(|_| AuthError("Invalid JWK formatting".into()))?;
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.set_audience(&[&google_auth.client_id]);
        validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);

        #[derive(Deserialize)]
        struct Claims {
            hd: Option<String>,
        }

        let token_data =
            jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation).map_err(|e| AuthError(format!("Invalid token: {}", e)))?;

        if let Some(expected_hd) = &google_auth.hosted_domain
            && token_data.claims.hd.as_deref() != Some(expected_hd.as_str())
        {
            return Err(AuthError(format!("Invalid organization domain. Expected {}", expected_hd)));
        }

        Ok(ValidatedUser)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::GithubRepository;
    use crate::scanners::RepoStats;

    fn repo(archived: bool, audited: bool) -> RepoStats {
        let mut r = RepoStats::new_from_github(&GithubRepository {
            name: "x".into(),
            archived,
            ..Default::default()
        });
        if audited {
            // ElaineManifest only requires `schema_version` and `name`; every other field is optional.
            r.manifest = Some(serde_json::from_str(r#"{"schema_version":1,"name":"x"}"#).unwrap());
        }
        r
    }

    #[test]
    fn empty_yields_zeros() {
        let s = DashboardStats::calculate(&[]);
        assert_eq!((s.all, s.live, s.live_audited, s.live_unaudited), (0, 0, 0, 0));
    }

    #[test]
    fn counts_live_audited_vs_unaudited() {
        let projects = vec![
            repo(false, true),
            repo(false, false),
            repo(false, false),
            repo(true, true), // archived: excluded from live counts
        ];
        let s = DashboardStats::calculate(&projects);
        assert_eq!(s.all, 4);
        assert_eq!(s.live, 3);
        assert_eq!(s.live_audited, 1);
        assert_eq!(s.live_unaudited, 2);
    }

    #[test]
    fn archived_does_not_count_as_live_even_when_audited() {
        let s = DashboardStats::calculate(&[repo(true, true), repo(false, true)]);
        assert_eq!(s.all, 2);
        assert_eq!(s.live, 1);
        assert_eq!(s.live_audited, 1);
    }
}
