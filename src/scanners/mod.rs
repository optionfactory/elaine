mod ansible;
mod docker;
mod elaine;
mod go;
mod legopfa;
mod maven;
mod npm;
mod osv;
pub mod pathcollector;
mod pinch;
mod rust;

use crate::github::GithubRepository;
use crate::sandbox::TarballSandbox;
use crate::scanners::ansible::AnsibleScanner;
use crate::scanners::docker::DockerScanner;
use crate::scanners::elaine::ElaineScanner;
use crate::scanners::go::GoScanner;
use crate::scanners::legopfa::LegopfaScanner;
use crate::scanners::maven::MavenScanner;
use crate::scanners::npm::NpmScanner;
use crate::scanners::pathcollector::{PathCollector, Pattern};
use crate::scanners::pinch::PinchScanner;
use crate::scanners::rust::RustScanner;
use indicatif::ProgressBar;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

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
    pub description: Option<String>,
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
    Go,
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
            description: repo.description.clone(),
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
    pub logs_dir: Option<&'a Path>,
    opened_logs: RefCell<HashSet<String>>,
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

    /// Opens the scanner's log file, truncating it on first use in this scan
    /// and appending afterwards. Registers the scanner so later writes append.
    fn open_log(&self, scanner: &str) -> anyhow::Result<Option<std::fs::File>> {
        match self.logs_dir {
            Some(dir) => {
                std::fs::create_dir_all(dir)?;
                let path = dir.join(format!("{}.log", scanner));
                let first_for_scanner = self.opened_logs.borrow_mut().insert(scanner.to_string());
                let mut opts = std::fs::OpenOptions::new();
                opts.create(true)
                    .append(!first_for_scanner)
                    .write(first_for_scanner)
                    .truncate(first_for_scanner);
                Ok(Some(opts.open(&path)?))
            }
            None => Ok(None),
        }
    }

    /// Reports a scanner failure: appends a `! <msg>` note to the scanner's
    /// log file and prints `[<repo>] 🔥 <msg>` to the progress console.
    pub fn report_failure(&self, scanner: &str, msg: impl AsRef<str>) {
        let msg = msg.as_ref();
        if let Ok(Some(mut f)) = self.open_log(scanner) {
            let _ = writeln!(f, "! {}", msg);
        }
        self.report_error(format!("[{}] 🔥 {}", self.repo.name, msg));
    }

    /// Runs a command, streaming its stdout/stderr to `<logs_dir>/<scanner>.log`
    /// while it executes, and returning the captured output for parsing.
    /// Errors only on spawn/IO failure; a non-zero exit is reported via
    /// `CommandOutput::success`.
    pub fn run_logged(&self, scanner: &str, program: &str, args: &[&str], current_dir: &Path) -> anyhow::Result<CommandOutput> {
        let (mut log_file, log_enabled) = match self.open_log(scanner) {
            Ok(f) => (f, true),
            Err(_) => (None, false),
        };

        if log_enabled && let Some(f) = log_file.as_mut() {
            let _ = writeln!(f, "> {} {}", program, args.join(" "));
        }

        let mut child = match Command::new(program)
            .args(args)
            .current_dir(current_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                if let Some(f) = log_file.as_mut() {
                    let _ = writeln!(f, "[spawn error] {}: {}", program, e);
                }
                return Err(e.into());
            }
        };

        let stdout_pipe = child.stdout.take().expect("stdout piped");
        let stderr_pipe = child.stderr.take().expect("stderr piped");

        fn tee(mut pipe: impl Read, mut sink: Option<std::fs::File>) -> Vec<u8> {
            let mut captured = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                match pipe.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Some(f) = sink.as_mut() {
                            let _ = f.write_all(&chunk[..n]);
                        }
                        captured.extend_from_slice(&chunk[..n]);
                    }
                }
            }
            captured
        }

        let stderr_file = log_file.as_ref().and_then(|f| f.try_clone().ok());
        let stdout_file = log_file.as_ref().and_then(|f| f.try_clone().ok());
        let stderr_handle = std::thread::spawn(move || tee(stderr_pipe, stderr_file));
        let stdout_handle = std::thread::spawn(move || tee(stdout_pipe, stdout_file));

        let status = child.wait()?;
        let stdout = stdout_handle.join().unwrap_or_default();
        let stderr = stderr_handle.join().unwrap_or_default();

        if let Some(f) = log_file.as_mut() {
            let _ = writeln!(f, "[exit: {}]", status);
        }

        Ok(CommandOutput {
            success: status.success(),
            stdout,
            stderr,
        })
    }
}

/// Captured result of a command spawned via `ScanContext::run_logged`.
pub struct CommandOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// The Trait implemented by all specific ecosystem/tool scanners
pub trait Scanner {
    /// Returns the patterns this scanner wants to collect during the filesystem pass
    fn patterns(&self) -> Vec<(&'static str, Pattern)>;
    /// Executes the scanner logic using the provided context, updating RepoStats
    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()>;
}

pub fn scan_repository(repo: &GithubRepository, tarball_path: &Path, pb: Option<ProgressBar>, logs_dir: Option<&Path>) -> anyhow::Result<RepoStats> {
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
        Box::new(GoScanner),
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
        logs_dir,
        opened_logs: RefCell::new(HashSet::new()),
    };
    for scanner in &scanners {
        scanner.scan(&ctx, &mut stats)?;
    }

    if let Some(ref p) = pb {
        p.set_message(format!("[{}] Finalizing...", repo.name));
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::GithubRepository;
    use tempfile::TempDir;

    #[test]
    fn run_logged_truncates_then_appends_with_command_headers() {
        let dir = TempDir::new().unwrap();
        let repo = GithubRepository::default();
        let matches = HashMap::new();
        let client = reqwest::Client::new();
        let ctx = ScanContext {
            repo: &repo,
            root: dir.path(),
            matches: &matches,
            pb: None,
            client: &client,
            logs_dir: Some(dir.path()),
            opened_logs: RefCell::new(HashSet::new()),
        };

        let first = ctx.run_logged("echo-test", "sh", &["-c", "echo one"], dir.path()).unwrap();
        assert!(first.success);
        assert_eq!(String::from_utf8_lossy(&first.stdout).trim(), "one");

        let second = ctx.run_logged("echo-test", "sh", &["-c", "echo two"], dir.path()).unwrap();
        assert!(second.success);

        let log = std::fs::read_to_string(dir.path().join("echo-test.log")).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines[0], "> sh -c echo one", "first run must start with a > header and truncate prior content");
        assert!(log.contains("one"));
        assert!(log.contains("> sh -c echo two"), "second run must append with its own > header");
        assert!(log.contains("two"));
        assert!(log.contains("[exit:"));
        // Content from run one must survive the append of run two.
        let one_pos = log.find("one").unwrap();
        let two_pos = log.find("two").unwrap();
        assert!(one_pos < two_pos);
    }

    #[test]
    fn run_logged_streams_stderr_too() {
        let dir = TempDir::new().unwrap();
        let repo = GithubRepository::default();
        let matches = HashMap::new();
        let client = reqwest::Client::new();
        let ctx = ScanContext {
            repo: &repo,
            root: dir.path(),
            matches: &matches,
            pb: None,
            client: &client,
            logs_dir: Some(dir.path()),
            opened_logs: RefCell::new(HashSet::new()),
        };
        let out = ctx.run_logged("err-test", "sh", &["-c", "echo oops 1>&2"], dir.path()).unwrap();
        assert!(out.success);
        assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "oops");
        let log = std::fs::read_to_string(dir.path().join("err-test.log")).unwrap();
        assert!(log.contains("oops"), "stderr must be teed into the log file");
    }
}
