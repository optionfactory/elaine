//! Google sign-in in front of the whole dashboard, as in optionfactory-posture: the authorization code flow with PKCE,
//! then a session cookie signed with a key of this run.

use crate::config::LoginConfig;
use crate::server::AppState;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{AppendHeaders, Html, IntoResponse, Redirect, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

const SESSION_SECONDS: i64 = 12 * 3600;
/// `__Host-`: only this host, over HTTPS, at `/`, so that no sibling subdomain can plant it.
const SESSION_COOKIE: &str = "__Host-elaine_session";
/// `__Secure-`: over HTTPS only; it stays under `/oidc`, which `__Host-` would not allow.
const LOGIN_COOKIE: &str = "__Secure-elaine_login";

/// The email of the signed-in user, for the handlers behind the login.
#[derive(Clone)]
pub struct SignedIn(pub String);

/// Lets through only the requests with a valid session: API calls without one get 401, pages and assets go through
/// the Google login and come back to where they were. Everything passes when no login is configured.
pub async fn require_session(State(state): State<Arc<AppState>>, mut request: Request, next: Next) -> Response {
    let Some(login) = &state.config.login else {
        return next.run(request).await;
    };
    if let Some(email) = cookie(request.headers(), SESSION_COOKIE).and_then(|session| signed_in(&state.session_key, session)) {
        request.extensions_mut().insert(SignedIn(email));
        return next.run(request).await;
    }
    if request.uri().path().starts_with("/api/") {
        return (StatusCode::UNAUTHORIZED, "Not signed in").into_response();
    }
    let path = request.uri().path_and_query().map_or("/", |path| path.as_str());
    start_login(login, path)
}

pub async fn sign_in(State(state): State<Arc<AppState>>) -> Response {
    match &state.config.login {
        Some(login) => start_login(login, "/"),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Sends the browser to Google; the state, the PKCE verifier and the page to come back to wait in a short cookie.
fn start_login(login: &LoginConfig, return_to: &str) -> Response {
    let rng = ring::rand::SystemRandom::new();
    let random = |len: usize| {
        let mut bytes = vec![0u8; len];
        ring::rand::SecureRandom::fill(&rng, &mut bytes).map(|()| URL_SAFE_NO_PAD.encode(bytes))
    };
    let (Ok(state), Ok(verifier)) = (random(16), random(32)) else {
        return message(StatusCode::INTERNAL_SERVER_ERROR, "No randomness for the login.");
    };
    let challenge = URL_SAFE_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()));
    let redirect_uri = redirect_uri(login);
    let mut params = vec![
        ("response_type", "code"),
        ("scope", "openid email"),
        ("client_id", login.client_id.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("state", state.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("prompt", "select_account"),
    ];
    params.push(("hd", &login.domain));
    let Ok(url) = reqwest::Url::parse_with_params("https://accounts.google.com/o/oauth2/v2/auth", &params) else {
        return message(StatusCode::INTERNAL_SERVER_ERROR, "The login address cannot be built.");
    };
    let return_to = URL_SAFE_NO_PAD.encode(return_to);
    (
        AppendHeaders([(
            header::SET_COOKIE,
            format!("{LOGIN_COOKIE}={state}.{verifier}.{return_to}; Path=/oidc; Max-Age=600; HttpOnly; Secure; SameSite=Lax"),
        )]),
        Redirect::to(url.as_str()),
    )
        .into_response()
}

fn redirect_uri(login: &LoginConfig) -> String {
    format!("{}/oidc/callback", login.public_url.trim_end_matches('/'))
}

#[derive(Deserialize)]
pub struct Callback {
    code: Option<String>,
    state: Option<String>,
}

pub async fn callback(State(state): State<Arc<AppState>>, headers: HeaderMap, Query(query): Query<Callback>) -> Response {
    let Some(login) = &state.config.login else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some([expected_state, verifier, return_to]) = cookie(&headers, LOGIN_COOKIE).and_then(|value| {
        let mut parts = value.splitn(3, '.');
        Some([parts.next()?, parts.next()?, parts.next()?])
    }) else {
        return message(StatusCode::BAD_REQUEST, "The login took too long: sign in again.");
    };
    let (Some(code), true) = (query.code, query.state.as_deref() == Some(expected_state)) else {
        return message(StatusCode::BAD_REQUEST, "The login was refused or did not start here: sign in again.");
    };
    let email = match google_email(&state.http_client, login, &code, verifier).await {
        Ok(email) => {
            eprintln!("[Login] {email} signed in.");
            email
        }
        Err(e) => {
            eprintln!("[Login] Refused: {e:#}");
            return message(StatusCode::BAD_GATEWAY, "Google did not confirm the login: sign in again.");
        }
    };
    let expiry = jiff::Timestamp::now().as_second() + SESSION_SECONDS;
    (
        AppendHeaders([
            (
                header::SET_COOKIE,
                format!(
                    "{SESSION_COOKIE}={}; Path=/; Max-Age={SESSION_SECONDS}; HttpOnly; Secure; SameSite=Lax",
                    session(&state.session_key, &email, expiry)
                ),
            ),
            (
                header::SET_COOKIE,
                format!("{LOGIN_COOKIE}=; Path=/oidc; Max-Age=0; HttpOnly; Secure; SameSite=Lax"),
            ),
        ]),
        Redirect::to(&local_path(return_to)),
    )
        .into_response()
}

/// The page saved at the start of the login, only when it is a path of this site.
fn local_path(encoded: &str) -> String {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        // browsers drop tabs and newlines from a URL: "/\t/host" would become "//host"
        .filter(|path| path.starts_with('/') && !path.starts_with("//") && !path.contains('\\') && !path.contains(char::is_control))
        .unwrap_or_else(|| "/".to_string())
}

/// Exchanges the code for the ID token and returns its verified email. The token comes straight from Google over TLS,
/// so its signature need not be checked (OpenID Connect Core 1.0, 3.1.3.7); its claims still are.
async fn google_email(http: &reqwest::Client, login: &LoginConfig, code: &str, verifier: &str) -> anyhow::Result<String> {
    #[derive(Deserialize)]
    struct Tokens {
        id_token: String,
    }
    let redirect_uri = redirect_uri(login);
    let tokens: Tokens = http
        .post("https://oauth2.googleapis.com/token")
        .timeout(Duration::from_secs(20))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &login.client_id),
            ("client_secret", &login.client_secret),
            ("redirect_uri", &redirect_uri),
            ("code_verifier", verifier),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    id_token_email(login, &tokens.id_token)
}

/// The verified email of an ID token whose issuer, audience, expiry and domain are the expected ones.
fn id_token_email(login: &LoginConfig, id_token: &str) -> anyhow::Result<String> {
    #[derive(Deserialize)]
    struct Claims {
        iss: String,
        aud: String,
        exp: i64,
        email: String,
        #[serde(default)]
        email_verified: bool,
        hd: Option<String>,
    }
    let claims = id_token.split('.').nth(1).ok_or_else(|| anyhow::anyhow!("ID token without claims"))?;
    let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(claims)?)?;
    if !matches!(claims.iss.as_str(), "https://accounts.google.com" | "accounts.google.com") {
        anyhow::bail!("ID token from {}", claims.iss);
    }
    if claims.aud != login.client_id {
        anyhow::bail!("ID token for {}", claims.aud);
    }
    if claims.exp <= jiff::Timestamp::now().as_second() {
        anyhow::bail!("expired ID token");
    }
    if !claims.email_verified {
        anyhow::bail!("{} is not verified", claims.email);
    }
    if claims.hd.as_ref() != Some(&login.domain) {
        anyhow::bail!("{} is not an account of {}", claims.email, login.domain);
    }
    Ok(claims.email.to_ascii_lowercase())
}

pub async fn sign_out() -> Response {
    (
        AppendHeaders([(
            header::SET_COOKIE,
            format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax"),
        )]),
        message(StatusCode::OK, "Signed out."),
    )
        .into_response()
}

/// The email and the expiry, signed with the key of this run.
fn session(key: &ring::hmac::Key, email: &str, expiry: i64) -> String {
    let payload = URL_SAFE_NO_PAD.encode(format!("{email} {expiry}"));
    let tag = URL_SAFE_NO_PAD.encode(ring::hmac::sign(key, payload.as_bytes()));
    format!("{payload}.{tag}")
}

/// The email of a session cookie signed with the key of this run and not yet expired.
fn signed_in(key: &ring::hmac::Key, session: &str) -> Option<String> {
    let (payload, tag) = session.split_once('.')?;
    ring::hmac::verify(key, payload.as_bytes(), &URL_SAFE_NO_PAD.decode(tag).ok()?).ok()?;
    let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    let (email, expiry) = payload.split_once(' ')?;
    (expiry.parse::<i64>().ok()? > jiff::Timestamp::now().as_second()).then(|| email.to_string())
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| pair.trim().strip_prefix(name)?.strip_prefix('='))
}

/// The pages of the login itself, which cannot use the stylesheet of the dashboard: it is behind the login.
fn message(status: StatusCode, text: &str) -> Response {
    (
        status,
        Html(format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Elaine</title>\
             <link rel=\"icon\" href=\"/favicon.svg\"></head><body><p>{text}</p><p><a href=\"/login\">Sign in</a></p></body></html>"
        )),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{CacheData, DashboardStats, aggregates::Aggregates};
    use crate::stats::StatsStore;
    use tokio::sync::RwLock;

    fn login() -> LoginConfig {
        LoginConfig {
            client_id: "elaine.apps.googleusercontent.com".into(),
            client_secret: String::new(),
            public_url: "https://elaine.example.com".into(),
            domain: "example.com".into(),
        }
    }

    #[test]
    fn a_session_counts_only_signed_with_this_key_and_unexpired() {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"this run");
        let other_run = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"previous run");
        let later = jiff::Timestamp::now().as_second() + 60;
        let valid = session(&key, "mario.rossi@example.com", later);
        let forged = session(&other_run, "mario.rossi@example.com", later);
        let expired = session(&key, "mario.rossi@example.com", jiff::Timestamp::now().as_second() - 1);
        let tampered = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(format!("luigi.verdi@example.com {later}")),
            valid.split_once('.').unwrap().1
        );

        let accepted = [&valid, &forged, &expired, &tampered].map(|cookie| signed_in(&key, cookie));

        assert_eq!(accepted, [Some("mario.rossi@example.com".to_string()), None, None, None]);
    }

    #[test]
    fn only_verified_id_tokens_of_the_domain_and_of_this_client_sign_in() {
        let id_token = |email: &str, hd: Option<&str>, aud: &str, verified: bool| {
            let claims = serde_json::json!({
                "iss": "https://accounts.google.com",
                "aud": aud,
                "exp": jiff::Timestamp::now().as_second() + 60,
                "email": email,
                "email_verified": verified,
                "hd": hd,
            });
            format!("e30.{}.unsigned", URL_SAFE_NO_PAD.encode(claims.to_string()))
        };
        let login = login();
        let client = login.client_id.as_str();

        let emails = [
            id_token("Mario.Rossi@example.com", Some("example.com"), client, true),
            id_token("mario.rossi@gmail.com", None, client, true),
            id_token("mario.rossi@guests.example.com", Some("guests.example.com"), client, true),
            id_token("mario.rossi@example.com", Some("example.com"), "another-client", true),
            id_token("mario.rossi@example.com", Some("example.com"), client, false),
        ]
        .map(|token| id_token_email(&login, &token).ok());

        assert_eq!(emails, [Some("mario.rossi@example.com".to_string()), None, None, None, None]);
    }

    #[test]
    fn the_login_returns_only_to_paths_of_this_site() {
        let returned = [
            "/security.html?x=1",
            "//evil.example/x",
            "/\\evil.example",
            "/\t/evil.example",
            "https://evil.example/",
        ]
        .map(|path| local_path(&URL_SAFE_NO_PAD.encode(path)));

        assert_eq!(returned, ["/security.html?x=1", "/", "/", "/", "/"]);
        assert_eq!(local_path("not base64!"), "/");
    }

    #[tokio::test]
    async fn without_a_session_pages_go_to_google_and_the_api_refuses() {
        let data_dir = tempfile::TempDir::new().unwrap();
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"this run");
        let signed = session(&key, "mario.rossi@example.com", jiff::Timestamp::now().as_second() + 60);
        let mut config: crate::config::Config = serde_json::from_value(serde_json::json!({
            "organization": "acme",
            "data_dir": data_dir.path(),
        }))
        .unwrap();
        config.login = Some(login());
        let state = Arc::new(AppState {
            config,
            http_client: reqwest::Client::new(),
            session_key: key,
            cache: Arc::new(RwLock::new(CacheData {
                projects: vec![],
                images: Default::default(),
                stats: DashboardStats::calculate(&[]),
                aggregates: Aggregates::calculate(&[], &Default::default()),
            })),
            stats: Arc::new(StatsStore::new(data_dir.path()).unwrap()),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(axum::serve(listener, crate::server::routes::create_router(state, false)).into_future());
        let http = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
        let get = |path: &str, cookie: Option<&str>| {
            let request = http.get(format!("{url}{path}"));
            match cookie {
                Some(cookie) => request.header(header::COOKIE, cookie),
                None => request,
            }
            .send()
        };

        let page = get("/governance.html", None).await.unwrap();
        let api = get("/api/stats", None).await.unwrap();
        let favicon = get("/favicon.svg", None).await.unwrap();
        let signed_in_api = get("/api/config", Some(&format!("{SESSION_COOKIE}={signed}"))).await.unwrap();

        assert_eq!(page.status(), StatusCode::SEE_OTHER);
        assert!(page.headers()[header::LOCATION].to_str().unwrap().starts_with("https://accounts.google.com/"));
        assert_eq!(api.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(favicon.status(), StatusCode::OK);
        assert_eq!(signed_in_api.json::<serde_json::Value>().await.unwrap()["email"], "mario.rossi@example.com");
    }
}
