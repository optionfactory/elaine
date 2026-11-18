use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GoogleAuthConfig {
    pub client_id: String,
    pub hosted_domain: Option<String>,
}

/// Where `elaine push` sends the scan results.
#[derive(Deserialize, Clone)]
pub struct RemoteConfig {
    /// Base URL of the `elaine serve` instance, e.g. `https://elaine.example.com`.
    pub url: String,
    /// Must match the server's `push_token`.
    pub token: String,
}

#[derive(Deserialize, Clone)]
pub struct Config {
    pub github_token: Option<String>,
    pub organization: String,
    pub address: Option<String>,
    pub port: Option<u16>,
    #[serde(default = "default_data_dir")]
    pub data_dir: std::path::PathBuf,
    pub google_auth: Option<GoogleAuthConfig>,
    /// Token `serve` requires to accept pushed scan results; pushing is refused when absent.
    pub push_token: Option<String>,
    /// When set, `scan` pushes its results to this server, and `push` becomes available.
    pub remote: Option<RemoteConfig>,
}

fn default_data_dir() -> std::path::PathBuf {
    "data".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_defaults_to_data() {
        let config: Config = serde_json::from_str(r#"{ "organization": "acme" }"#).unwrap();
        assert_eq!(config.data_dir, std::path::PathBuf::from("data"));
    }
}
