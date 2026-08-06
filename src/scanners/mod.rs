pub mod pathcollector;
use crate::github::GithubRepository;
use crate::sandbox::TarballSandbox;
use crate::scanners::pathcollector::{PathCollector, Pattern};
use serde::Serialize;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

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
    pub pinch_audit: Option<pinch::schema::PinchAudit>,
    pub ansible_confs: Vec<PathBuf>,
    pub docker_files: Vec<PathBuf>,
    pub legopfa_confs: Vec<PathBuf>,
    pub ecosystems_detected: Vec<String>,
    pub dependency_reports: Vec<DependencyReport>,
}

pub fn scan_repository(repo: &GithubRepository, tarball_path: &Path) -> anyhow::Result<RepoStats> {
    let sandbox = TarballSandbox::unpack(tarball_path)?;
    let root = sandbox.path();

    let matches = PathCollector::new()
        .register("pinch_manifest", Pattern::ExactPath(PathBuf::from("pinch.yaml")))
        .register("docker_files", Pattern::FileName("Dockerfile".to_string()))
        .register(
            "docker_compose_files",
            Pattern::FileName("docker-compose.yml".to_string()),
        )
        .register("ansible_confs", Pattern::FileName("ansible.cfg".to_string()))
        .register_pattern("legopfa_confs", |name| {
            name.starts_with("legopfa") && name.ends_with(".json")
        })
        .scan(root);

    // Combined path lists ready to be saved in RepoStats if needed
    let docker_files = matches["docker_files"]
        .iter()
        .chain(&matches["docker_compose_files"])
        .cloned()
        .collect();

    // 3. Parse pinch audit directly if matched
    let pinch_audit = matches["pinch_manifest"]
        .first()
        .and_then(|rel_path| File::open(root.join(rel_path)).ok())
        .map(BufReader::new)
        .and_then(|reader| serde_saphyr::from_reader::<_, pinch::schema::PinchManifest>(reader).ok())
        .map(|manifest| manifest.audit());

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
        ansible_confs: matches["ansible_confs"].clone(),
        docker_files: docker_files,
        legopfa_confs: matches["legopfa_confs"].clone(),
        ecosystems_detected: vec![],
        dependency_reports: vec![],
        pinch_audit,
    })
}
