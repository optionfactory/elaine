mod osv;
pub mod pathcollector;
mod scanner_ansible;
mod scanner_docker;
mod scanner_elaine;
mod scanner_go;
mod scanner_legopfa;
mod scanner_maven;
mod scanner_npm;
mod scanner_pinch;
mod scanner_rust;

use crate::github::GithubRepository;
use crate::sandbox::TarballSandbox;
use crate::scanners::pathcollector::{PathCollector, Pattern};
use crate::scanners::scanner_ansible::AnsibleScanner;
use crate::scanners::scanner_docker::DockerScanner;
use crate::scanners::scanner_elaine::ElaineScanner;
use crate::scanners::scanner_go::GolangScanner;
use crate::scanners::scanner_legopfa::LegopfaScanner;
use crate::scanners::scanner_maven::MavenScanner;
use crate::scanners::scanner_npm::NpmScanner;
use crate::scanners::scanner_pinch::PinchScanner;
use crate::scanners::scanner_rust::RustScanner;
use indicatif::ProgressBar;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
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
pub struct OutdatedDependency {
    pub project: String,
    pub kind: String,
    pub artifact: String,
    pub current: String,
    pub latest: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoStats {
    pub name: String,
    pub html_url: String,
    pub created_at: String,
    pub updated_at: String,
    pub pushed_at: String,
    pub archived: bool,
    pub fork: bool,
    pub disabled: bool,
    pub private: bool,
    pub description: String,
    //
    pub manifest: Option<crate::schema::ElaineManifest>,
    //
    pub health: BTreeMap<ScannerKind, BTreeMap<String, CheckStatus>>,
    pub containers: Option<Vec<String>>,
    pub ansible_confs: Vec<PathBuf>,
    pub docker_files: Vec<PathBuf>,
    pub legopfa_confs: Vec<PathBuf>,
    //
    pub vulnerabilities: Option<Vec<Vulnerability>>,
    pub outdated_dependencies: Option<Vec<OutdatedDependency>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ScannerKind {
    Rust,
    Npm,
    Golang,
    Maven,
    Pinch,
    Elaine,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CheckStatus {
    Ok,
    Failed,
}

impl RepoStats {
    /// Initializes a baseline RepoStats object from GitHub metadata
    pub fn new_from_github(repo: &GithubRepository) -> Self {
        Self {
            name: repo.name.clone(),
            html_url: repo.html_url.clone(),
            created_at: repo.created_at.clone(),
            updated_at: repo.updated_at.clone(),
            pushed_at: repo.pushed_at.clone(),
            archived: repo.archived,
            fork: repo.fork,
            disabled: repo.disabled,
            private: repo.private,
            description: repo.description.clone().unwrap_or_default(),
            manifest: None,
            health: BTreeMap::new(),
            containers: None,
            ansible_confs: Vec::new(),
            docker_files: Vec::new(),
            legopfa_confs: Vec::new(),
            vulnerabilities: None,
            outdated_dependencies: None,
        }
    }
    pub fn record_check(&mut self, kind: ScannerKind, check: &str, status: CheckStatus) {
        self.health.entry(kind).or_default().insert(check.to_string(), status);
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

    pub fn checked_for_outdated_dependencies(&mut self) {
        if self.outdated_dependencies.is_none() {
            self.outdated_dependencies = Some(Vec::new());
        }
    }

    pub fn add_outdated_dependency(&mut self, dep: OutdatedDependency) {
        self.checked_for_outdated_dependencies();
        if let Some(ref mut deps) = self.outdated_dependencies {
            deps.push(dep);
        }
    }

    pub fn add_outdated_dependencies(&mut self, mut deps: Vec<OutdatedDependency>) {
        self.checked_for_outdated_dependencies();
        if let Some(ref mut d) = self.outdated_dependencies {
            d.append(&mut deps);
        }
    }

    pub fn checked_for_containers(&mut self) {
        if self.containers.is_none() {
            self.containers = Some(Vec::new());
        }
    }

    pub fn add_container(&mut self, container: String) {
        self.checked_for_containers();
        if let Some(ref mut deps) = self.containers {
            deps.push(container);
        }
    }

    pub fn add_containers(&mut self, mut containers: Vec<String>) {
        self.checked_for_containers();
        if let Some(ref mut d) = self.containers {
            d.append(&mut containers);
        }
    }
}

pub struct ScanContext<'a> {
    pub repo: &'a GithubRepository,
    pub root: &'a Path,
    pub matches: &'a HashMap<String, Vec<PathBuf>>,
    pub pb: Option<&'a ProgressBar>,
    pub client: &'a reqwest::Client,
}

impl<'a> ScanContext<'a> {
    pub fn set_message(&self, msg: String) {
        if let Some(p) = self.pb {
            p.set_message(msg);
        }
    }
    pub fn report_error(&self, msg: String) {
        if let Some(p) = self.pb {
            p.println(msg);
        }
    }
}

/// The Trait implemented by all specific ecosystem/tool scanners
pub trait Scanner {
    /// Returns the patterns this scanner wants to collect during the filesystem pass
    fn patterns(&self) -> Vec<(&'static str, Pattern)>;
    /// Executes the scanner logic using the provided context, updating RepoStats
    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()>;
}

pub fn scan_repository(repo: &GithubRepository, tarball_path: &Path, pb: Option<ProgressBar>) -> anyhow::Result<RepoStats> {
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
        Box::new(ElaineScanner),
        Box::new(DockerScanner),
        Box::new(MavenScanner),
        Box::new(RustScanner),
        Box::new(GolangScanner),
        Box::new(NpmScanner),
        Box::new(AnsibleScanner),
        Box::new(LegopfaScanner),
    ];

    let mut collector = PathCollector::new();
    for scanner in &scanners {
        for (key, pattern) in scanner.patterns() {
            collector = collector.register(key, pattern);
        }
    }

    let matches = collector.scan(root);
    let client = reqwest::Client::new();
    let mut stats = RepoStats::new_from_github(repo);
    let ctx = ScanContext {
        repo,
        root,
        matches: &matches,
        pb: pb.as_ref(),
        client: &client,
    };
    for scanner in &scanners {
        scanner.scan(&ctx, &mut stats)?;
    }

    if let Some(ref p) = pb {
        p.set_message(format!("[{}] Finalizing...", repo.name));
    }

    Ok(stats)
}
