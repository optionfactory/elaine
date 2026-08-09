pub mod pathcollector;
use crate::github::GithubRepository;
use crate::sandbox::TarballSandbox;
use crate::scanners::pathcollector::{PathCollector, Pattern};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::Command;


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vulnerability {
    pub project: String,
    pub artifact: String,
    pub version: String,
    pub vuln_id: String,
    pub trail: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DependencyUpdate {
    pub project: String,
    pub kind: String,
    pub artifact: String,
    pub current: String,
    pub latest: String,
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
    pub vulnerabilities: Vec<Vulnerability>,
    pub dependencies: Vec<DependencyUpdate>,
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
        .register("pom_files", Pattern::FileName("pom.xml".to_string()))
        .scan(root);

    let mut ecosystems_detected = Vec::new();
    let mut vulnerabilities = Vec::new();
    let mut dependencies = Vec::new();

    if let Some(pom_paths) = matches.get("pom_files") {
        let mut pom_dirs: Vec<&Path> = pom_paths
            .iter()
            .filter_map(|p| p.parent())
            .collect();
        
        pom_dirs.sort_by_key(|p| p.components().count());
        
        let mut selected_dirs: Vec<&Path> = Vec::new();
        
        for dir in pom_dirs {
            let is_submodule = selected_dirs.iter().any(|selected| dir.starts_with(selected));
            
            if !is_submodule {
                selected_dirs.push(dir);
                
                let run_dir = root.join(dir);
                eprintln!("Found independent root POM in {:?}. Running Maven...", run_dir);
                
                let status = Command::new("mvn")
                    .current_dir(&run_dir)
                    .args([
                        "-U", 
                        "-ntp", 
                        "net.optionfactory:anarchitect-maven-plugin:LATEST:check-vulns", 
                        "net.optionfactory:anarchitect-maven-plugin:LATEST:check-updates"
                    ])
                    .status();

                match status {
                    Ok(s) if s.success() => {
                        eprintln!("Maven finished successfully for {:?}", run_dir);
                        
                        if !ecosystems_detected.contains(&"maven".to_string()) {
                            ecosystems_detected.push("maven".to_string());
                        }
                        
                        // Parse vulnerabilities
                        let vulns_path = run_dir.join("target").join("anarchitect-vulns.json");
                        if let Ok(payload) = fs::read_to_string(&vulns_path) {
                            match serde_json::from_str::<Vec<Vulnerability>>(&payload) {
                                Ok(mut parsed_vulns) => vulnerabilities.append(&mut parsed_vulns),
                                Err(e) => eprintln!("Failed to parse vulnerabilities JSON at {:?}: {}", vulns_path, e),
                            }
                        }

                        // Parse updates
                        let updates_path = run_dir.join("target").join("anarchitect-updates.json");
                        if let Ok(payload) = fs::read_to_string(&updates_path) {
                            match serde_json::from_str::<Vec<DependencyUpdate>>(&payload) {
                                Ok(mut parsed_updates) => dependencies.append(&mut parsed_updates),
                                Err(e) => eprintln!("Failed to parse updates JSON at {:?}: {}", updates_path, e),
                            }
                        }
                    },
                    Ok(s) => eprintln!("Maven failed for {:?} with status: {}", run_dir, s),
                    Err(e) => eprintln!("Failed to execute Maven for {:?}: {}", run_dir, e),
                }
            }
        }
    }

    let docker_files = matches["docker_files"]
        .iter()
        .chain(&matches["docker_compose_files"])
        .cloned()
        .collect();
        
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
        docker_files,
        legopfa_confs: matches["legopfa_confs"].clone(),
        ecosystems_detected,
        vulnerabilities,
        dependencies,
        pinch_audit,
    })
}