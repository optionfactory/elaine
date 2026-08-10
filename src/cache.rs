use crate::github::{GithubClient, GithubRepository};
use anyhow::{Context, Result};
use futures::StreamExt;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

#[derive(Debug, PartialEq, Eq)]
pub enum SyncStatus {
    Cached,
    Downloaded,
}

pub struct RepositoryCache {
    pub dir: PathBuf,
}

impl RepositoryCache {
    pub fn new<P: AsRef<Path>>(cache_base_dir: P, org: &str) -> Result<Self> {
        let dir = cache_base_dir.as_ref().join(org);
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn tarball_path(&self, repo_name: &str) -> PathBuf {
        self.dir.join(format!("{}.tar.gz", repo_name))
    }

    pub fn metadata_path(&self, repo_name: &str) -> PathBuf {
        self.dir.join(format!("{}.json", repo_name))
    }

    pub fn is_cache_valid(&self, repo_name: &str, expected_pushed_at: &str) -> bool {
        if expected_pushed_at.is_empty() {
            return false;
        }

        let tar_path = self.tarball_path(repo_name);
        if !tar_path.exists() {
            return false;
        }

        let meta_path = self.metadata_path(repo_name);
        let Ok(data) = fs::read_to_string(meta_path) else {
            return false;
        };

        let Ok(local_meta) = serde_json::from_str::<GithubRepository>(&data) else {
            return false;
        };

        local_meta.pushed_at == expected_pushed_at
    }

    pub async fn sync_repo(
        &self,
        client: &GithubClient,
        org: &str,
        repo: &GithubRepository,
        force: bool,
    ) -> Result<SyncStatus> {
        if !force && self.is_cache_valid(&repo.name, &repo.pushed_at) {
            return Ok(SyncStatus::Cached);
        }

        let resp = client.download_tarball(org, &repo.name, &repo.default_branch).await?;
        let target_tar = self.tarball_path(&repo.name);
        let tmp_tar = target_tar.with_extension("tar.gz.tmp");

        let mut file = File::create(&tmp_tar)
            .await
            .context("Failed to create temporary tarball file")?;

        let mut stream = resp.bytes_stream();
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result.context("Error reading tarball stream from GitHub")?;
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        drop(file);

        fs::rename(&tmp_tar, &target_tar)?;

        let target_meta = self.metadata_path(&repo.name);
        let tmp_meta = target_meta.with_extension("json.tmp");
        let pretty_json = serde_json::to_string_pretty(repo)?;

        fs::write(&tmp_meta, pretty_json)?;
        fs::rename(&tmp_meta, &target_meta)?;

        Ok(SyncStatus::Downloaded)
    }

    pub fn load_all_metadata(&self) -> Result<BTreeMap<String, GithubRepository>> {
        let mut repos = BTreeMap::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "json") {
                if let Ok(data) = fs::read_to_string(&path) {
                    if let Ok(repo) = serde_json::from_str::<GithubRepository>(&data) {
                        repos.insert(repo.name.clone(), repo);
                    }
                }
            }
        }
        Ok(repos)
    }
}
