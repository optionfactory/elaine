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
            if r.audit.is_some() {
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
    pub jwks: Option<jsonwebtoken::jwk::JwkSet>,
    pub cache: Arc<RwLock<CacheData>>,
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
        let google_auth = match &app_state.config.google_auth {
            Some(g) => g,
            None => return Ok(ValidatedUser),
        };

        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "));

        let token = match auth_header {
            Some(t) => t,
            None => return Err(AuthError("Missing Bearer token".into())),
        };

        let jwks = match app_state.jwks.as_ref() {
            Some(j) => j,
            None => return Err(AuthError("Google JWKS not loaded on server".into())),
        };

        let header = jsonwebtoken::decode_header(token).map_err(|_| AuthError("Invalid token header".into()))?;
        let kid = header.kid.ok_or_else(|| AuthError("Missing 'kid' in token header".into()))?;
        let jwk = jwks.find(&kid).ok_or_else(|| AuthError("Unknown 'kid'".into()))?;
        let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk).map_err(|_| AuthError("Invalid JWK formatting".into()))?;
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
