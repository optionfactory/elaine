use anyhow::{Context, Result};
use indicatif::ProgressBar;
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GithubRepository {
    pub name: String,
    pub html_url: String,
    pub default_branch: String,
    pub created_at: String,
    pub updated_at: String,
    pub pushed_at: String,
    pub archived: bool,
    pub fork: bool,
    pub disabled: bool,
    pub private: bool,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Clone)]
pub struct GithubClient {
    client: reqwest::Client,
    organization: String,
    token: String,
}

impl GithubClient {
    pub fn new(github_token: Option<String>, organization: String) -> Result<Self> {
        let token =
            Self::get_token(github_token).context("Could not retrieve GitHub token from env (GITHUB_TOKEN/GH_TOKEN) or `gh auth token`")?;
        let client = reqwest::Client::new();
        Ok(Self {
            client,
            organization,
            token,
        })
    }

    fn get_token(auth_token: Option<String>) -> Option<String> {
        if auth_token.is_some() {
            return auth_token;
        }
        if let Ok(t) = std::env::var("GITHUB_TOKEN").or_else(|_| std::env::var("GH_TOKEN"))
            && !t.trim().is_empty()
        {
            return Some(t.trim().to_string());
        }
        if let Ok(out) = Command::new("gh").args(["auth", "token"]).output()
            && out.status.success()
        {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
        None
    }

    pub async fn fetch_org_repos(&self, pb: &ProgressBar) -> Result<Vec<GithubRepository>> {
        let mut all_repos = Vec::new();
        let mut page = 1;

        loop {
            let url = format!(
                "https://api.github.com/orgs/{}/repos?per_page=100&page={}&type=all",
                self.organization, page
            );
            let resp = self
                .client
                .get(&url)
                .header(AUTHORIZATION, format!("Bearer {}", self.token))
                .header(ACCEPT, "application/vnd.github+json")
                .header(USER_AGENT, "repospect")
                .send()
                .await?
                .error_for_status()?;

            let repos: Vec<GithubRepository> = resp.json().await?;
            let count = repos.len();
            all_repos.extend(repos);

            pb.set_message(format!("Fetched page {} ({} repositories found so far)...", page, all_repos.len()));

            if count < 100 {
                break;
            }
            page += 1;
        }

        Ok(all_repos)
    }

    pub async fn download_tarball(&self, repo: &str, branch: &str) -> Result<reqwest::Response> {
        let url = format!("https://api.github.com/repos/{}/{}/tarball/{}", self.organization, repo, branch);
        let resp = self
            .client
            .get(&url)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(ACCEPT, "application/vnd.github+json")
            .header(USER_AGENT, "repospect-rust")
            .send()
            .await?
            .error_for_status()?;

        Ok(resp)
    }
}
