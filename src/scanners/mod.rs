pub mod ecosystems;

use crate::github::GithubRepository;
use crate::sandbox::TarballSandbox;
use serde::Serialize;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct DependencyReport {
    pub ecosystem: String,
    pub format: String,
    pub payload: String,
}

#[derive(Debug, Serialize)]
pub struct RepoStats {
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    pub archived: bool,
    pub fork: bool,
    pub disabled: bool,
    pub private: bool,
    pub has_unique_commits: bool,
    pub description: String,
    pub has_ansible_configuration: bool,
    pub has_dockerfile: bool,
    pub has_legopfa: bool,
    pub ecosystems_detected: Vec<String>,
    pub dependency_reports: Vec<DependencyReport>,
    pub pinch_audit: Option<pinch::schema::PinchAudit>,
}

trait EcosystemScanner: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_present(&self, root: &Path) -> bool;
    fn scan(&self, root: &Path) -> anyhow::Result<DependencyReport>;
}

pub fn scan_repository(repo: &GithubRepository, tarball_path: &Path) -> anyhow::Result<RepoStats> {
    let sandbox = TarballSandbox::unpack(tarball_path)?;
    let root = sandbox.path();

    let pinch_audit = File::open(root.join("pinch.yaml"))
        .map(BufReader::new)
        .ok()
        .and_then(|reader| serde_yaml::from_reader::<_, pinch::schema::PinchManifest>(reader).ok())
        .map(|manifest| manifest.audit());

    let has_dockerfile = root.join("Dockerfile").exists() || root.join("docker-compose.yml").exists();
    let has_ansible =
        root.join("ansible.cfg").exists() || root.join("requirements.yml").exists() || root.join("roles").is_dir();

    let has_legopfa = walkdir(root).any(|p| {
        p.file_name()
            .and_then(|n| n.to_str())
            .map_or(false, |name| name.starts_with("legopfa") && name.ends_with(".json"))
    });

    let scanners: Vec<Box<dyn EcosystemScanner>> = vec![];

    let mut ecosystems_detected = Vec::new();
    let mut dependency_reports = Vec::new();

    for scanner in scanners {
        if scanner.is_present(root) {
            ecosystems_detected.push(scanner.name().to_string());
            if let Ok(report) = scanner.scan(root) {
                dependency_reports.push(report);
            }
        }
    }

    Ok(RepoStats {
        name: repo.name.clone(),
        created_at: repo.created_at.clone(),
        updated_at: repo.updated_at.clone(),
        archived: repo.archived,
        fork: repo.fork,
        disabled: repo.disabled,
        private: repo.private,
        has_unique_commits: !repo.fork,
        description: repo.description.clone().unwrap_or_default(),
        has_ansible_configuration: has_ansible,
        has_dockerfile,
        has_legopfa,
        ecosystems_detected,
        dependency_reports,
        pinch_audit,
    })
}

fn walkdir(root: &Path) -> impl Iterator<Item = std::path::PathBuf> {
    let mut dirs = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = dirs.pop() {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                } else {
                    files.push(path);
                }
            }
        }
    }
    files.into_iter()
}
