use crate::github::{GithubClient, GithubRepository};
use anyhow::{Context, Result};
use futures::StreamExt;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

pub struct RepositoryStore {
    pub dir: PathBuf,
}

impl RepositoryStore {
    pub fn new<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let dir = data_dir.as_ref().join("repos");
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn tarball_path(&self, repo_name: &str) -> PathBuf {
        self.dir.join(format!("{}.tar.gz", repo_name))
    }

    pub fn metadata_path(&self, repo_name: &str) -> PathBuf {
        self.dir.join(format!("{}.json", repo_name))
    }

    pub fn is_cache_valid(&self, repo_name: &str, expected_updated_at: &str, expected_pushed_at: &str) -> bool {
        if expected_updated_at.is_empty() || expected_pushed_at.is_empty() {
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

        local_meta.updated_at == expected_updated_at && local_meta.pushed_at == expected_pushed_at
    }

    pub async fn sync_repo(&self, client: &GithubClient, repo: &GithubRepository, force: bool) -> Result<()> {
        if !force && self.is_cache_valid(&repo.name, &repo.updated_at, &repo.pushed_at) {
            return Ok(());
        }

        let resp = client.download_tarball(&repo.name, &repo.default_branch).await?;
        let target_tar = self.tarball_path(&repo.name);
        let tmp_tar = target_tar.with_extension("tar.gz.tmp");

        let mut file = File::create(&tmp_tar).await.context("Failed to create temporary tarball file")?;

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

        Ok(())
    }

    pub fn load_all_metadata(&self) -> Result<BTreeMap<String, GithubRepository>> {
        let mut repos = BTreeMap::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json")
                && let Ok(data) = fs::read_to_string(&path)
                && let Ok(repo) = serde_json::from_str::<GithubRepository>(&data)
            {
                repos.insert(repo.name.clone(), repo);
            }
        }
        Ok(repos)
    }

    pub fn clean_orphans(&self, current_repo_names: &std::collections::HashSet<&str>) -> anyhow::Result<()> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Ok(());
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(repo_name) = file_name.strip_suffix(".json").or_else(|| file_name.strip_suffix(".tar.gz")) else {
                continue;
            };
            if !current_repo_names.contains(repo_name) {
                eprintln!("  Removing orphaned cache file: {}", file_name);
                let _ = std::fs::remove_file(&path);
            }
        }
        Ok(())
    }

    pub fn clean_all(&self) -> anyhow::Result<()> {
        if self.dir.exists() {
            std::fs::remove_dir_all(&self.dir)?;
        }
        Ok(())
    }
}
