pub mod auth;
pub mod routes;

use crate::config::Config;
use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

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
    pub jwks: Option<Arc<auth::JwksCache>>,
    pub cache: Arc<RwLock<CacheData>>,
}

#[derive(RustEmbed)]
#[folder = "src/frontend/"]
pub struct FrontendAssets;

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
