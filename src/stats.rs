use crate::scanners::RepoStats;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::fs;
use std::path::{Path, PathBuf};

pub struct StatsStore {
    pub base_dir: PathBuf,
    pub stats_dir: PathBuf,
}

impl StatsStore {
    pub fn new<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let base_dir = data_dir.as_ref().to_path_buf();
        let stats_dir = base_dir.join("stats");
        fs::create_dir_all(&stats_dir)?;
        Ok(Self { base_dir, stats_dir })
    }

    pub fn project_file_path(&self, repo_name: &str) -> PathBuf {
        self.stats_dir.join(format!("{}.json", repo_name))
    }

    pub fn aggregate_file_path(&self) -> PathBuf {
        self.base_dir.join("stats.json")
    }

    pub fn is_scan_fresh(&self, repo_name: &str, pushed_at: &str) -> bool {
        let file_path = self.project_file_path(repo_name);
        if !file_path.exists() {
            return false;
        }
        let Ok(metadata) = fs::metadata(&file_path) else {
            return false;
        };
        let Ok(modified) = metadata.modified() else {
            return false;
        };
        let modified_dt: DateTime<Utc> = modified.into();
        if let Ok(pushed_dt) = DateTime::parse_from_rfc3339(pushed_at) {
            return modified_dt >= pushed_dt.with_timezone(&Utc);
        }
        false
    }

    pub fn save_project_scan(&self, stat: &RepoStats) -> Result<PathBuf> {
        let file_path = self.project_file_path(&stat.name);
        let json_data = serde_json::to_string_pretty(stat)?;
        fs::write(&file_path, &json_data).with_context(|| format!("Failed to write scan data to {:?}", file_path))?;
        Ok(file_path)
    }

    pub fn aggregate_scans(&self) -> Result<PathBuf> {
        let mut stats = Vec::new();
        if !self.stats_dir.exists() {
            return Ok(self.aggregate_file_path());
        }

        for entry in fs::read_dir(&self.stats_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension().unwrap_or_default() == "json" {
                let data = fs::read_to_string(&path)?;
                if let Ok(stat) = serde_json::from_str::<RepoStats>(&data) {
                    stats.push(stat);
                } else {
                    eprintln!("Warning: Failed to parse {:?}", path);
                }
            }
        }

        stats.sort_by(|a, b| a.name.cmp(&b.name));
        let aggregate_path = self.aggregate_file_path();
        let json_data = serde_json::to_string_pretty(&stats)?;
        fs::write(&aggregate_path, &json_data).with_context(|| format!("Failed to update aggregate scan data at {:?}", aggregate_path))?;

        Ok(aggregate_path)
    }

    pub fn list_scans(&self) -> Result<Vec<(String, u64)>> {
        let mut scans = Vec::new();
        if !self.stats_dir.exists() {
            return Ok(scans);
        }
        for entry in fs::read_dir(&self.stats_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    let metadata = entry.metadata()?;
                    scans.push((filename.to_string(), metadata.len()));
                }
            }
        }
        scans.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(scans)
    }

    pub fn clean_all(&self) -> anyhow::Result<()> {
        if self.stats_dir.exists() {
            std::fs::remove_dir_all(&self.stats_dir)?;
        }
        Ok(())
    }
}
