use crate::scanners::{CheckStatus, RepoStats};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// Everything `elaine serve` reads: sent by `elaine push` from the machine that scans.
#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    pub projects: Vec<RepoStats>,
    /// Scanner failure logs by repository name, then by scanner name.
    pub logs: BTreeMap<String, BTreeMap<String, String>>,
}

pub struct StatsStore {
    pub base_dir: PathBuf,
    pub stats_dir: PathBuf,
    pub logs_dir: PathBuf,
    snapshot_replacement: Mutex<()>,
}

impl StatsStore {
    pub fn new<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let base_dir = data_dir.as_ref().to_path_buf();
        let stats_dir = base_dir.join("stats");
        fs::create_dir_all(&stats_dir)?;
        let logs_dir = base_dir.join("stats").join("logs");
        fs::create_dir_all(&logs_dir)?;
        Ok(Self {
            base_dir,
            stats_dir,
            logs_dir,
            snapshot_replacement: Mutex::new(()),
        })
    }

    /// Whether `name` can be used as a single path component under the logs directory.
    pub fn is_safe_log_name(name: &str) -> bool {
        !name.is_empty() && !name.contains('/') && !name.contains('\\') && !name.contains("..")
    }

    pub fn project_file_path(&self, repo_name: &str) -> PathBuf {
        self.stats_dir.join(format!("{}.json", repo_name))
    }

    pub fn repo_logs_dir(&self, repo_name: &str) -> PathBuf {
        self.logs_dir.join(repo_name)
    }

    pub fn aggregate_file_path(&self) -> PathBuf {
        self.base_dir.join("stats.json")
    }

    pub fn is_scan_fresh(&self, repo_name: &str, updated_at: &str, pushed_at: &str) -> bool {
        let Ok(data) = fs::read_to_string(self.project_file_path(repo_name)) else {
            return false;
        };
        let Ok(prev) = serde_json::from_str::<RepoStats>(&data) else {
            return false;
        };
        let has_failed_checks = prev
            .health
            .values()
            .flat_map(|checks| checks.values())
            .any(|status| *status == CheckStatus::Failed);
        prev.pushed_at == pushed_at && prev.updated_at == updated_at && !has_failed_checks
    }

    pub fn save_project_scan(&self, stat: &RepoStats) -> Result<PathBuf> {
        let file_path = self.project_file_path(&stat.name);
        let json_data = serde_json::to_string_pretty(stat)?;
        fs::write(&file_path, &json_data).with_context(|| format!("Failed to write scan data to {:?}", file_path))?;
        Ok(file_path)
    }

    pub fn remove_project_scan(&self, repo_name: &str) -> Result<()> {
        let path = self.project_file_path(repo_name);
        if path.exists() {
            fs::remove_file(&path).with_context(|| format!("Failed to remove scan data at {:?}", path))?;
        }
        let logs = self.repo_logs_dir(repo_name);
        if logs.is_dir() {
            fs::remove_dir_all(&logs).with_context(|| format!("Failed to remove scan logs at {:?}", logs))?;
        }
        Ok(())
    }

    pub fn clean_orphans(&self, current_repo_names: &std::collections::HashSet<&str>) -> Result<()> {
        let Ok(entries) = fs::read_dir(&self.stats_dir) else {
            return Ok(());
        };
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(repo_name) = file_name.strip_suffix(".json") else {
                continue;
            };
            if !current_repo_names.contains(repo_name) {
                eprintln!("  Removing orphaned scan file: {}", file_name);
                let _ = fs::remove_file(&path);
                let logs = self.repo_logs_dir(repo_name);
                if logs.is_dir() {
                    let _ = fs::remove_dir_all(&logs);
                }
            }
        }
        Ok(())
    }

    pub fn aggregate_scans(&self) -> Result<PathBuf> {
        let mut stats = Vec::new();
        if !self.stats_dir.exists() {
            return Ok(self.aggregate_file_path());
        }

        for entry in fs::read_dir(&self.stats_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() || path.extension().unwrap_or_default() != "json" {
                continue;
            }
            let data = fs::read_to_string(&path)?;
            let Ok(stat) = serde_json::from_str::<RepoStats>(&data) else {
                eprintln!("Warning: Failed to parse {:?}", path);
                continue;
            };
            stats.push(stat);
        }

        stats.sort_by(|a, b| a.name.cmp(&b.name));
        self.write_aggregate(&stats)
    }

    /// Writes through a renamed temporary file, so `serve` never reloads a half-written file.
    fn write_aggregate(&self, projects: &[RepoStats]) -> Result<PathBuf> {
        let aggregate_path = self.aggregate_file_path();
        let mut file = tempfile::Builder::new()
            .permissions(std::os::unix::fs::PermissionsExt::from_mode(0o644))
            .tempfile_in(&self.base_dir)?;
        serde_json::to_writer_pretty(&mut file, projects)?;
        file.persist(&aggregate_path)
            .with_context(|| format!("Failed to update aggregate scan data at {:?}", aggregate_path))?;
        Ok(aggregate_path)
    }

    pub fn load_snapshot(&self) -> Result<Snapshot> {
        let aggregate_path = self.aggregate_file_path();
        let data = fs::read_to_string(&aggregate_path).with_context(|| format!("Failed to read {:?}. Run 'elaine scan' first.", aggregate_path))?;
        let projects = serde_json::from_str(&data).with_context(|| format!("Failed to parse {:?}", aggregate_path))?;
        let mut logs = BTreeMap::new();
        for repo_dir in fs::read_dir(&self.logs_dir)?.filter_map(|e| e.ok()).filter(|e| e.path().is_dir()) {
            let mut repo_logs = BTreeMap::new();
            for log in fs::read_dir(repo_dir.path())?.filter_map(|e| e.ok()) {
                let path = log.path();
                let Some(scanner) = path.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".log")) else {
                    continue;
                };
                repo_logs.insert(scanner.to_string(), String::from_utf8_lossy(&fs::read(&path)?).into_owned());
            }
            logs.insert(repo_dir.file_name().to_string_lossy().into_owned(), repo_logs);
        }
        Ok(Snapshot { projects, logs })
    }

    /// Replaces the aggregated stats and every scanner log with the content of `snapshot`.
    pub fn replace_with_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        let mut names = snapshot.logs.iter().flat_map(|(repo, scanners)| std::iter::once(repo).chain(scanners.keys()));
        if let Some(unsafe_name) = names.find(|name| !Self::is_safe_log_name(name)) {
            anyhow::bail!("Invalid repository or scanner name in logs: {:?}", unsafe_name);
        }
        let _replacing = self.snapshot_replacement.lock().unwrap_or_else(PoisonError::into_inner);
        let incoming = tempfile::Builder::new().prefix("logs.incoming").tempdir_in(&self.stats_dir)?;
        for (repo, scanners) in &snapshot.logs {
            let repo_dir = incoming.path().join(repo);
            fs::create_dir_all(&repo_dir)?;
            for (scanner, content) in scanners {
                fs::write(repo_dir.join(format!("{}.log", scanner)), content)?;
            }
        }
        let previous = self.stats_dir.join("logs.previous");
        if previous.exists() {
            fs::remove_dir_all(&previous)?;
        }
        if self.logs_dir.exists() {
            fs::rename(&self.logs_dir, &previous)?;
        }
        fs::rename(incoming.keep(), &self.logs_dir)?;
        if previous.exists() {
            fs::remove_dir_all(&previous)?;
        }
        self.write_aggregate(&snapshot.projects)?;
        Ok(())
    }

    pub fn clean_all(&self) -> anyhow::Result<()> {
        if self.stats_dir.exists() {
            std::fs::remove_dir_all(&self.stats_dir)?;
        }
        let aggregate = self.aggregate_file_path();
        if aggregate.exists() {
            std::fs::remove_file(&aggregate)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::GithubRepository;
    use crate::scanners::ScannerKind;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, StatsStore) {
        let dir = TempDir::new().unwrap();
        let store = StatsStore::new(dir.path()).unwrap();
        (dir, store)
    }

    /// Writes a scan file for `name` carrying the given GitHub timestamps.
    fn write_scan(store: &StatsStore, name: &str, updated_at: &str, pushed_at: &str) {
        let repo = GithubRepository {
            name: name.to_string(),
            updated_at: updated_at.to_string(),
            pushed_at: pushed_at.to_string(),
            ..Default::default()
        };
        store.save_project_scan(&RepoStats::new_from_github(&repo)).unwrap();
    }

    #[test]
    fn fresh_when_fingerprints_match() {
        let (_dir, store) = fresh_store();
        write_scan(&store, "acme", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z");
        assert!(store.is_scan_fresh("acme", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z"));
    }

    #[test]
    fn stale_when_pushed_at_differs() {
        let (_dir, store) = fresh_store();
        write_scan(&store, "acme", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z");
        assert!(!store.is_scan_fresh("acme", "2024-01-01T00:00:00Z", "2024-01-09T00:00:00Z"));
    }

    #[test]
    fn stale_when_updated_at_differs() {
        let (_dir, store) = fresh_store();
        write_scan(&store, "acme", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z");
        assert!(!store.is_scan_fresh("acme", "2024-09-01T00:00:00Z", "2024-01-02T00:00:00Z"));
    }

    #[test]
    fn stale_when_prior_scan_has_failed_checks() {
        let (_dir, store) = fresh_store();
        let repo = GithubRepository {
            name: "acme".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
            pushed_at: "2024-01-02T00:00:00Z".to_string(),
            ..Default::default()
        };
        let mut stats = RepoStats::new_from_github(&repo);
        stats.record_check(ScannerKind::Npm, "vulns", CheckStatus::Failed);
        store.save_project_scan(&stats).unwrap();
        assert!(!store.is_scan_fresh("acme", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z"));
    }

    #[test]
    fn stale_when_no_prior_scan() {
        let (_dir, store) = fresh_store();
        assert!(!store.is_scan_fresh("ghost", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z"));
    }

    #[test]
    fn stale_when_timestamps_empty() {
        let (_dir, store) = fresh_store();
        write_scan(&store, "acme", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z");
        assert!(!store.is_scan_fresh("acme", "", "2024-01-02T00:00:00Z"));
    }

    #[test]
    fn remove_deletes_only_target_scan() {
        let (_dir, store) = fresh_store();
        write_scan(&store, "acme", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z");
        write_scan(&store, "other", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z");
        store.remove_project_scan("acme").unwrap();
        assert!(!store.project_file_path("acme").exists());
        assert!(store.project_file_path("other").exists());
    }

    #[test]
    fn remove_missing_scan_is_noop() {
        let (_dir, store) = fresh_store();
        store.remove_project_scan("ghost").unwrap();
    }

    #[test]
    fn snapshot_replaces_stats_and_drops_stale_logs() {
        let (_dir, store) = fresh_store();
        fs::create_dir_all(store.repo_logs_dir("gone")).unwrap();
        fs::write(store.repo_logs_dir("gone").join("npm.log"), "old").unwrap();
        let repo = GithubRepository {
            name: "acme".to_string(),
            ..Default::default()
        };
        let snapshot = Snapshot {
            projects: vec![RepoStats::new_from_github(&repo)],
            logs: BTreeMap::from([("acme".into(), BTreeMap::from([("go".into(), "go: not found".into())]))]),
        };

        store.replace_with_snapshot(&snapshot).unwrap();

        let stored = store.load_snapshot().unwrap();
        assert_eq!(stored.projects.len(), 1);
        assert_eq!(stored.logs.keys().collect::<Vec<_>>(), vec!["acme"]);
        assert_eq!(stored.logs["acme"]["go"], "go: not found");
    }

    #[test]
    fn snapshot_with_log_names_outside_the_logs_dir_is_refused() {
        let (dir, store) = fresh_store();
        let snapshot = Snapshot {
            projects: vec![],
            logs: BTreeMap::from([("..".into(), BTreeMap::from([("escape".into(), "x".into())]))]),
        };

        assert!(store.replace_with_snapshot(&snapshot).is_err());
        assert!(!dir.path().join("stats").join("escape.log").exists());
        assert!(!store.aggregate_file_path().exists());
    }

    #[test]
    fn clean_orphans_removes_stale_scans_only() {
        let (_dir, store) = fresh_store();
        write_scan(&store, "renamed-old", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z");
        write_scan(&store, "renamed-new", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z");
        write_scan(&store, "kept", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z");

        let current: std::collections::HashSet<&str> = ["renamed-new", "kept"].into_iter().collect();
        store.clean_orphans(&current).unwrap();

        assert!(!store.project_file_path("renamed-old").exists());
        assert!(store.project_file_path("renamed-new").exists());
        assert!(store.project_file_path("kept").exists());
    }
}
