use crate::server::AppState;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Google JWKS cache with on-miss refresh, rate-limited so bogus 'kid's
/// cannot turn the endpoint into a fetch amplifier.
pub struct JwksCache {
    keys: Arc<RwLock<JwksCacheInner>>,
}

struct JwksCacheInner {
    keys: jsonwebtoken::jwk::JwkSet,
    last_refresh: Instant,
}

const JWKS_REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(60);

impl JwksCache {
    pub fn new(keys: jsonwebtoken::jwk::JwkSet) -> Self {
        Self {
            keys: Arc::new(RwLock::new(JwksCacheInner {
                keys,
                last_refresh: Instant::now(),
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
        guard.last_refresh = Instant::now();
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

        let token_data = jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation).map_err(|e| AuthError(format!("Invalid token: {}", e)))?;

        if let Some(expected_hd) = &google_auth.hosted_domain
            && token_data.claims.hd.as_deref() != Some(expected_hd.as_str())
        {
            return Err(AuthError(format!("Invalid organization domain. Expected {}", expected_hd)));
        }

        Ok(ValidatedUser)
    }
}
