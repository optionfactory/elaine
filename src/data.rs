use anyhow::{Context, Result};
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

    pub fn save_scan(&self, stats: &[RepoStats]) -> Result<PathBuf> {
        let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H-%M-%SZ").to_string();
        let file_path = self.dir.join(format!("scan_{}.json", timestamp));
        let latest_path = self.dir.join("latest.json");
        let json_data = serde_json::to_string_pretty(stats)?;

        fs::write(&file_path, &json_data)
            .with_context(|| format!("Failed to write scan data to {:?}", file_path))?;
        fs::write(&latest_path, &json_data)
            .with_context(|| format!("Failed to update latest scan data at {:?}", latest_path))?;

        Ok(file_path)
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