use serde::{Deserialize, Serialize};

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
    #[serde(default = "default_data_dir")]
    pub data_dir: std::path::PathBuf,
    pub google_auth: Option<GoogleAuthConfig>,
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
