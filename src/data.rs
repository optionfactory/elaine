use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::fs;
use std::path::{Path, PathBuf};

use crate::scanners::RepoStats;

pub struct DataStore {
    pub dir: PathBuf,
}

impl DataStore {
    pub fn new<P: AsRef<Path>>(data_base_dir: P, org: &str) -> Result<Self> {
        let dir = data_base_dir.as_ref().join(org);
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn project_file_path(&self, repo_name: &str) -> PathBuf {
        self.dir.join(format!("{}.json", repo_name))
    }

    pub fn is_scan_fresh(&self, repo_name: &str, updated_at: &str) -> bool {
        let file_path = self.project_file_path(repo_name);
        if !file_path.exists() {
            return false;
        }

        let Ok(metadata) = fs::metadata(&file_path) else { return false; };
        let Ok(modified) = metadata.modified() else { return false; };
        let modified_dt: DateTime<Utc> = modified.into();

        if let Ok(updated_dt) = DateTime::parse_from_rfc3339(updated_at) {
            return modified_dt >= updated_dt.with_timezone(&Utc);
        }

        false
    }

    pub fn save_project_scan(&self, stat: &RepoStats) -> Result<PathBuf> {
        let file_path = self.project_file_path(&stat.name);
        let json_data = serde_json::to_string_pretty(stat)?;
        fs::write(&file_path, &json_data)
            .with_context(|| format!("Failed to write scan data to {:?}", file_path))?;
        
        Ok(file_path)
    }

    pub fn aggregate_scans(&self) -> Result<PathBuf> {
        let mut stats = Vec::new();

        if !self.dir.exists() {
            return Ok(self.dir.join("latest.json"));
        }

        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_file() 
               && path.extension().unwrap_or_default() == "json" 
               && path.file_name().unwrap_or_default() != "latest.json" 
            {
                let data = fs::read_to_string(&path)?;
                if let Ok(stat) = serde_json::from_str::<RepoStats>(&data) {
                    stats.push(stat);
                } else {
                    eprintln!("Warning: Failed to parse {:?}", path);
                }
            }
        }

        stats.sort_by(|a, b| a.name.cmp(&b.name));

        let latest_path = self.dir.join("latest.json");
        let json_data = serde_json::to_string_pretty(&stats)?;
        fs::write(&latest_path, &json_data)
            .with_context(|| format!("Failed to update latest scan data at {:?}", latest_path))?;
            
        Ok(latest_path)
    }

    pub fn list_scans(&self) -> Result<Vec<(String, u64)>> {
        let mut scans = Vec::new();

        if !self.dir.exists() {
            return Ok(scans);
        }

        for entry in fs::read_dir(&self.dir)? {
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
}