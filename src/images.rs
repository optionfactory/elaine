use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

/// What the scan of a container image found, once per image whatever the number of repositories that run it.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum ImageScan {
    /// The vulnerabilities of the packages in the SBOM of the image that already have a fix.
    Scanned { vulnerabilities: Vec<ImageVulnerability> },
    /// The registry has no SBOM for the image; it is not pulled to make one.
    NoSbom,
    /// The registry, docker or grype failed.
    Failed { reason: String },
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ImageVulnerability {
    pub package: String,
    pub version: String,
    pub fixed_in: String,
    pub severity: Severity,
    pub vuln_id: String,
}

/// Grype's severities, from the least to the most severe.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Unknown,
    Negligible,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn from_grype(severity: &str) -> Self {
        match severity {
            "Critical" => Severity::Critical,
            "High" => Severity::High,
            "Medium" => Severity::Medium,
            "Low" => Severity::Low,
            "Negligible" => Severity::Negligible,
            _ => Severity::Unknown,
        }
    }
}

/// What the dashboard shows of an image: `status` is `vulnerable`, `clean`, `no-sbom`, `failed`, or `unscanned` for an
/// image the last scan or push did not cover.
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct ImageSummary {
    pub image: String,
    pub status: &'static str,
    pub fixable: usize,
    /// Fixable and high or critical.
    pub serious: usize,
    pub highest: Option<Severity>,
    pub reason: Option<String>,
}

impl ImageSummary {
    pub fn of(image: &str, scan: Option<&ImageScan>) -> Self {
        let mut summary = ImageSummary {
            image: image.to_string(),
            status: "unscanned",
            fixable: 0,
            serious: 0,
            highest: None,
            reason: None,
        };
        match scan {
            None => {}
            Some(ImageScan::NoSbom) => summary.status = "no-sbom",
            Some(ImageScan::Failed { reason }) => {
                summary.status = "failed";
                summary.reason = Some(reason.clone());
            }
            Some(ImageScan::Scanned { vulnerabilities }) => {
                summary.status = if vulnerabilities.is_empty() { "clean" } else { "vulnerable" };
                summary.fixable = vulnerabilities.len();
                summary.serious = vulnerabilities.iter().filter(|v| v.severity >= Severity::High).count();
                summary.highest = vulnerabilities.iter().map(|v| v.severity).max();
            }
        }
        summary
    }
}

/// The name of an image without its tag or digest: `optionfactory/debian13-nginx130:257` and `:258` are the same image
/// at two versions.
pub fn without_tag(image: &str) -> &str {
    let image = image.split_once('@').map_or(image, |(name, _)| name);
    match image.rsplit_once(':') {
        Some((name, tag)) if !tag.contains('/') => name,
        _ => image,
    }
}

const WORKERS: usize = 4;

/// Scans each image once: its SBOM from the registry, as `docker buildx imagetools inspect` gives it without pulling
/// the image (the `linux/amd64` one of a multi-platform image), then grype on that SBOM, keeping the vulnerabilities
/// that have a fix: the ones a newer image can remove.
pub fn scan_images(images: &BTreeSet<String>, work_dir: &Path) -> BTreeMap<String, ImageScan> {
    if images.is_empty() {
        return BTreeMap::new();
    }
    // once here, so that the parallel runs below do not each try to update the same database
    let updated = Command::new("grype").args(["db", "update"]).output();
    let failure = match updated {
        Ok(out) if out.status.success() => None,
        Ok(out) => Some(format!("grype db update: {}", String::from_utf8_lossy(&out.stderr).trim())),
        Err(e) => Some(format!("grype: {e}")),
    };
    if let Some(reason) = failure {
        return images
            .iter()
            .map(|image| (image.clone(), ImageScan::Failed { reason: reason.clone() }))
            .collect();
    }
    let queue = Mutex::new(images.iter());
    let scans = Mutex::new(BTreeMap::new());
    std::thread::scope(|scope| {
        for _ in 0..WORKERS {
            scope.spawn(|| {
                while let Some(image) = queue.lock().unwrap_or_else(|e| e.into_inner()).next() {
                    let scan = scan_image(image, work_dir).unwrap_or_else(|reason| ImageScan::Failed { reason });
                    scans.lock().unwrap_or_else(|e| e.into_inner()).insert(image.clone(), scan);
                }
            });
        }
    });
    scans.into_inner().unwrap_or_else(|e| e.into_inner())
}

fn scan_image(image: &str, work_dir: &Path) -> Result<ImageScan, String> {
    let inspected = Command::new("docker")
        .args(["buildx", "imagetools", "inspect", image, "--format", "{{ json .SBOM }}"])
        .output()
        .map_err(|e| format!("docker: {e}"))?;
    if !inspected.status.success() {
        return Err(String::from_utf8_lossy(&inspected.stderr).trim().to_string());
    }
    let sboms: serde_json::Value = serde_json::from_slice(&inspected.stdout).map_err(|e| format!("SBOM of {image}: {e}"))?;
    let Some(spdx) = sboms.get("SPDX").or_else(|| sboms.get("linux/amd64").and_then(|platform| platform.get("SPDX"))) else {
        return Ok(ImageScan::NoSbom);
    };
    let mut file = tempfile::Builder::new()
        .prefix("sbom")
        .suffix(".spdx.json")
        .tempfile_in(work_dir)
        .map_err(|e| e.to_string())?;
    serde_json::to_writer(&mut file, spdx).map_err(|e| e.to_string())?;
    let matched = Command::new("grype")
        .arg(format!("sbom:{}", file.path().display()))
        .args(["--only-fixed", "-o", "json"])
        .env("GRYPE_DB_AUTO_UPDATE", "false")
        .env("GRYPE_CHECK_FOR_APP_UPDATE", "false")
        .output()
        .map_err(|e| format!("grype: {e}"))?;
    if !matched.status.success() {
        return Err(format!("grype: {}", String::from_utf8_lossy(&matched.stderr).trim()));
    }
    let report: GrypeReport = serde_json::from_slice(&matched.stdout).map_err(|e| format!("grype output: {e}"))?;
    Ok(ImageScan::Scanned {
        vulnerabilities: fixable(report),
    })
}

#[derive(Deserialize)]
struct GrypeReport {
    matches: Vec<GrypeMatch>,
}

#[derive(Deserialize)]
struct GrypeMatch {
    vulnerability: GrypeVulnerability,
    artifact: GrypeArtifact,
}

#[derive(Deserialize)]
struct GrypeVulnerability {
    id: String,
    severity: String,
    fix: GrypeFix,
}

#[derive(Deserialize)]
struct GrypeFix {
    versions: Vec<String>,
}

#[derive(Deserialize)]
struct GrypeArtifact {
    name: String,
    version: String,
}

/// One entry per package, version and advisory (grype can match the same one more than once), the most severe first.
fn fixable(report: GrypeReport) -> Vec<ImageVulnerability> {
    let mut seen = BTreeSet::new();
    let mut vulnerabilities: Vec<ImageVulnerability> = report
        .matches
        .into_iter()
        .filter(|m| !m.vulnerability.fix.versions.is_empty())
        .filter(|m| seen.insert((m.artifact.name.clone(), m.artifact.version.clone(), m.vulnerability.id.clone())))
        .map(|m| ImageVulnerability {
            package: m.artifact.name,
            version: m.artifact.version,
            fixed_in: m.vulnerability.fix.versions.join(", "),
            severity: Severity::from_grype(&m.vulnerability.severity),
            vuln_id: m.vulnerability.id,
        })
        .collect();
    vulnerabilities.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.package.cmp(&b.package)));
    vulnerabilities
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tag_and_the_digest_are_not_part_of_the_image() {
        let names = [
            "optionfactory/debian13-nginx130:257",
            "localhost:5000/tool",
            "postgres@sha256:abc",
            "axllent/mailpit",
        ]
        .map(without_tag);
        assert_eq!(names, ["optionfactory/debian13-nginx130", "localhost:5000/tool", "postgres", "axllent/mailpit"]);
    }

    #[test]
    fn grype_matches_become_one_fixable_entry_each_most_severe_first() {
        let report: GrypeReport = serde_json::from_value(serde_json::json!({ "matches": [
            { "vulnerability": { "id": "CVE-1", "severity": "Medium", "fix": { "versions": ["1.1"] } }, "artifact": { "name": "zlib1g", "version": "1.0" } },
            { "vulnerability": { "id": "CVE-2", "severity": "High", "fix": { "versions": ["3.1"] } }, "artifact": { "name": "openssl", "version": "3.0" } },
            { "vulnerability": { "id": "CVE-2", "severity": "High", "fix": { "versions": ["3.1"] } }, "artifact": { "name": "openssl", "version": "3.0" } },
            { "vulnerability": { "id": "CVE-3", "severity": "Critical", "fix": { "versions": [] } }, "artifact": { "name": "glibc", "version": "2.41" } }
        ]}))
        .unwrap();
        let found: Vec<_> = fixable(report).into_iter().map(|v| (v.vuln_id, v.severity)).collect();
        assert_eq!(found, [("CVE-2".to_string(), Severity::High), ("CVE-1".to_string(), Severity::Medium)]);
    }
}
