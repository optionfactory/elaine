pub mod pathcollector;
mod scanner_ansible;
mod scanner_docker;
mod scanner_legopfa;
mod scanner_maven;
mod scanner_pinch;

use crate::github::GithubRepository;
use crate::sandbox::TarballSandbox;
use crate::scanners::pathcollector::{PathCollector, Pattern};
use crate::scanners::scanner_ansible::AnsibleScanner;
use crate::scanners::scanner_docker::DockerScanner;
use crate::scanners::scanner_legopfa::LegopfaScanner;
use crate::scanners::scanner_maven::MavenScanner;
use crate::scanners::scanner_pinch::PinchScanner;
use indicatif::ProgressBar;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoStats {
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
    pub pushed_at: String,
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
    pub vulnerabilities: Option<Vec<Vulnerability>>,
    pub dependencies: Option<Vec<DependencyUpdate>>,
}

impl RepoStats {
    /// Initializes a baseline RepoStats object from GitHub metadata
    pub fn new_from_github(repo: &GithubRepository) -> Self {
        Self {
            name: repo.name.clone(),
            created_at: repo.created_at.clone(),
            updated_at: repo.updated_at.clone(),
            pushed_at: repo.pushed_at.clone(),
            archived: repo.archived,
            fork: repo.fork,
            disabled: repo.disabled,
            private: repo.private,
            has_unique_commits: !repo.fork,
            description: repo.description.clone().unwrap_or_default(),
            pinch_audit: None,
            ansible_confs: Vec::new(),
            docker_files: Vec::new(),
            legopfa_confs: Vec::new(),
            ecosystems_detected: Vec::new(),
            vulnerabilities: None,
            dependencies: None,
        }
    }
    pub fn add_ecosystem(&mut self, name: &str, success: bool) {
        let eco_string = if success {
            name.to_string()
        } else {
            format!("{}:failed", name)
        };

        if !self.ecosystems_detected.contains(&eco_string) {
            self.ecosystems_detected.push(eco_string);
        }
    }

    pub fn checked_for_vulnerabilities(&mut self) {
        if self.vulnerabilities.is_none() {
            self.vulnerabilities = Some(Vec::new());
        }
    }

    pub fn add_vulnerability(&mut self, vuln: Vulnerability) {
        self.checked_for_vulnerabilities();
        if let Some(ref mut vulns) = self.vulnerabilities {
            vulns.push(vuln);
        }
    }

    pub fn add_vulnerabilities(&mut self, mut vulns: Vec<Vulnerability>) {
        self.checked_for_vulnerabilities();
        if let Some(ref mut v) = self.vulnerabilities {
            v.append(&mut vulns);
        }
    }

    pub fn checked_for_upgrades(&mut self) {
        if self.dependencies.is_none() {
            self.dependencies = Some(Vec::new());
        }
    }

    pub fn add_upgrade(&mut self, upgrade: DependencyUpdate) {
        self.checked_for_upgrades();
        if let Some(ref mut deps) = self.dependencies {
            deps.push(upgrade);
        }
    }

    pub fn add_upgrades(&mut self, mut upgrades: Vec<DependencyUpdate>) {
        self.checked_for_upgrades();
        if let Some(ref mut d) = self.dependencies {
            d.append(&mut upgrades);
        }
    }
}

pub struct ScanContext<'a> {
    pub repo: &'a GithubRepository,
    pub root: &'a Path,
    pub matches: &'a HashMap<String, Vec<PathBuf>>,
    pub pb: Option<&'a ProgressBar>,
}

/// The Trait implemented by all specific ecosystem/tool scanners
pub trait Scanner {
    /// Returns the patterns this scanner wants to collect during the filesystem pass
    fn patterns(&self) -> Vec<(&'static str, Pattern)>;

    /// Executes the scanner logic using the provided context, updating RepoStats
    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()>;
}

pub fn scan_repository(
    repo: &GithubRepository,
    tarball_path: &Path,
    pb: Option<ProgressBar>,
) -> anyhow::Result<RepoStats> {
    if let Some(ref p) = pb {
        p.set_message(format!("[{}] Unpacking archive...", repo.name));
    }
    let sandbox = TarballSandbox::unpack(tarball_path)?;
    let root = sandbox.path();

    if let Some(ref p) = pb {
        p.set_message(format!("[{}] Scanning filesystem...", repo.name));
    }

    let scanners: Vec<Box<dyn Scanner>> = vec![
        Box::new(PinchScanner),
        Box::new(DockerScanner),
        Box::new(AnsibleScanner),
        Box::new(LegopfaScanner),
        Box::new(MavenScanner),
    ];

    let mut collector = PathCollector::new();
    for scanner in &scanners {
        for (key, pattern) in scanner.patterns() {
            collector = collector.register(key, pattern);
        }
    }

    let matches = collector.scan(root);
    let mut stats = RepoStats::new_from_github(repo);
    let ctx = ScanContext {
        repo,
        root,
        matches: &matches,
        pb: pb.as_ref(),
    };
    for scanner in &scanners {
        scanner.scan(&ctx, &mut stats)?;
    }

    if let Some(ref p) = pb {
        p.set_message(format!("[{}] Finalizing...", repo.name));
    }

    Ok(stats)
}
