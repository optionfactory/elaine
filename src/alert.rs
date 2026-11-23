use crate::config::AlertsConfig;
use crate::images::{self, ImageScan, ImageVulnerability, Severity};
use crate::scanners::{RepoStats, Vulnerability};
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::extension::ClientId;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write;
use std::net::IpAddr;

/// What one push carried.
pub struct Scan<'a> {
    pub projects: &'a [RepoStats],
    pub images: &'a BTreeMap<String, ImageScan>,
}

/// The vulnerabilities in `current` that `previous` did not have, once per repository, artifact and advisory: a new
/// version of a dependency still vulnerable to the same advisory is not new.
///
/// Without a previous push (the first one, or the first after a restore) nothing is new. A repository counts only when
/// both pushes scanned it for vulnerabilities, so one failed scan does not make all its vulnerabilities look new at the
/// next; one that appears for the first time counts whole. Archived repositories are left out.
pub fn new_vulnerabilities<'a>(previous: Option<&[RepoStats]>, current: &'a [RepoStats]) -> Vec<(&'a RepoStats, &'a Vulnerability)> {
    let Some(previous) = previous else {
        return Vec::new();
    };
    let known: HashMap<&str, Option<HashSet<(&str, &str)>>> = previous
        .iter()
        .map(|repo| {
            let vulns = repo
                .vulnerabilities
                .as_ref()
                .map(|vulns| vulns.iter().map(|v| (v.artifact.as_str(), v.vuln_id.as_str())).collect());
            (repo.name.as_str(), vulns)
        })
        .collect();
    let mut found = Vec::new();
    for repo in current.iter().filter(|repo| !repo.archived) {
        let Some(vulns) = &repo.vulnerabilities else {
            continue;
        };
        let before = match known.get(repo.name.as_str()) {
            Some(None) => continue,
            Some(Some(before)) => Some(before),
            None => None,
        };
        let mut seen = HashSet::new();
        for vuln in vulns {
            let key = (vuln.artifact.as_str(), vuln.vuln_id.as_str());
            if before.is_none_or(|before| !before.contains(&key)) && seen.insert(key) {
                found.push((repo, vuln));
            }
        }
    }
    found
}

/// A fixable vulnerability of an image, with the live repositories that run it.
pub struct NewImageVulnerability<'a> {
    pub image: &'a str,
    pub vuln: &'a ImageVulnerability,
    pub repos: Vec<&'a str>,
}

/// The fixable high and critical vulnerabilities of the images in `current` that `previous` did not have, once per
/// image, package and advisory. The image is compared without its tag, so that moving a project to a newer tag does not
/// announce again what the newer tag still has.
///
/// The same rules as for the dependencies: nothing when the previous push scanned no image at all (the first one, or
/// the first from a scanning machine with grype); an image counts only when both pushes scanned it, and one that
/// appears for the first time counts whole. A tag the previous push could not scan (the registry rate limits the
/// inspections) is skipped as well, not compared with the other tags of its image, which do not have its packages.
pub fn new_image_vulnerabilities<'a>(previous: Option<&BTreeMap<String, ImageScan>>, current: &Scan<'a>) -> Vec<NewImageVulnerability<'a>> {
    let Some(previous) = previous.filter(|previous| previous.values().any(|scan| matches!(scan, ImageScan::Scanned { .. }))) else {
        return Vec::new();
    };
    let mut known: HashMap<&str, Option<HashSet<(&str, &str)>>> = HashMap::new();
    for (image, scan) in previous {
        let entry = known.entry(images::without_tag(image)).or_default();
        if let ImageScan::Scanned { vulnerabilities } = scan {
            entry
                .get_or_insert_default()
                .extend(vulnerabilities.iter().map(|v| (v.package.as_str(), v.vuln_id.as_str())));
        }
    }
    let mut seen = HashSet::new();
    let mut found = Vec::new();
    for (image, scan) in current.images {
        let ImageScan::Scanned { vulnerabilities } = scan else {
            continue;
        };
        if previous.get(image).is_some_and(|before| !matches!(before, ImageScan::Scanned { .. })) {
            continue;
        }
        let name = images::without_tag(image);
        let before = match known.get(name) {
            Some(None) => continue,
            Some(Some(before)) => Some(before),
            None => None,
        };
        let repos: Vec<&str> = current
            .projects
            .iter()
            .filter(|p| !p.archived && p.containers.iter().flatten().any(|c| c == image))
            .map(|p| p.name.as_str())
            .collect();
        if repos.is_empty() {
            continue;
        }
        for vuln in vulnerabilities.iter().filter(|v| v.severity >= Severity::High) {
            let key = (vuln.package.as_str(), vuln.vuln_id.as_str());
            if before.is_none_or(|before| !before.contains(&key)) && seen.insert((name, key)) {
                found.push(NewImageVulnerability {
                    image,
                    vuln,
                    repos: repos.clone(),
                });
            }
        }
    }
    found
}

/// Mails the vulnerabilities `current` brings over `previous`, if any.
pub async fn notify(alerts: &AlertsConfig, previous: Option<Scan<'_>>, current: Scan<'_>, dashboard: Option<&str>) -> anyhow::Result<()> {
    let found = new_vulnerabilities(previous.as_ref().map(|p| p.projects), current.projects);
    let found_in_images = new_image_vulnerabilities(previous.as_ref().map(|p| p.images), &current);
    let total = found.len() + found_in_images.len();
    if total == 0 {
        return Ok(());
    }
    let subject = match total {
        1 => "Elaine: 1 new vulnerability".to_string(),
        n => format!("Elaine: {n} new vulnerabilities"),
    };
    let message = Message::builder()
        .from(Mailbox::new(Some("Elaine".into()), alerts.from.email.clone()))
        .to(alerts.to.clone())
        .subject(subject)
        .multipart(MultiPart::alternative_plain_html(
            text(&found, &found_in_images, dashboard),
            html(&found, &found_in_images, dashboard),
        ))?;
    let loopback = alerts.smtp_host == "localhost" || alerts.smtp_host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    let builder = if loopback {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&alerts.smtp_host)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&alerts.smtp_host)?
    };
    // the relay of Google Workspace refuses an EHLO name outside the domain
    let transport = builder
        .port(alerts.smtp_port)
        .hello_name(ClientId::Domain(alerts.from.email.domain().to_string()))
        .build();
    transport.send(message).await?;
    eprintln!("[Alert] Mailed {} new vulnerabilities to {}.", total, alerts.to);
    Ok(())
}

fn by_advisory<'a>(found: &[(&'a RepoStats, &'a Vulnerability)]) -> BTreeMap<&'a str, Vec<(&'a RepoStats, &'a Vulnerability)>> {
    let mut grouped: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    for (repo, vuln) in found {
        grouped.entry(vuln.vuln_id.as_str()).or_default().push((*repo, *vuln));
    }
    grouped
}

fn images_by_advisory<'a, 'b>(found: &'b [NewImageVulnerability<'a>]) -> BTreeMap<&'a str, Vec<&'b NewImageVulnerability<'a>>> {
    let mut grouped: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    for hit in found {
        grouped.entry(hit.vuln.vuln_id.as_str()).or_default().push(hit);
    }
    grouped
}

fn label<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn text(found: &[(&RepoStats, &Vulnerability)], found_in_images: &[NewImageVulnerability], dashboard: Option<&str>) -> String {
    let mut text = String::new();
    for (id, hits) in by_advisory(found) {
        let _ = writeln!(text, "{id}  https://osv.dev/vulnerability/{id}");
        for (repo, vuln) in hits {
            let scanner = vuln.scanner.as_ref().map(label).unwrap_or_default();
            let _ = writeln!(text, "  {}: {} {} ({})", repo.name, vuln.artifact, vuln.version, scanner);
        }
        text.push('\n');
    }
    if !found_in_images.is_empty() {
        text.push_str("Container images\n\n");
    }
    for (id, hits) in images_by_advisory(found_in_images) {
        let _ = writeln!(text, "{id}  https://osv.dev/vulnerability/{id}");
        for hit in hits {
            let _ = writeln!(
                text,
                "  {}: {} {}, fixed in {} ({}), run by {}",
                hit.image,
                hit.vuln.package,
                hit.vuln.version,
                hit.vuln.fixed_in,
                label(&hit.vuln.severity),
                hit.repos.join(", ")
            );
        }
        text.push('\n');
    }
    if let Some(dashboard) = dashboard {
        let _ = writeln!(text, "{dashboard}");
    }
    text
}

const FONT: &str = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MONO: &str = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace";
const MUTED: &str = "#475569";
const BORDER: &str = "#cbd5e1";
const PRIMARY: &str = "#0369a1";
const DANGER: &str = "#b91c1c";

fn card_header(html: &mut String, id: &str) {
    let id = escape(id);
    let _ = writeln!(
        html,
        "<tr><td style=\"padding:0 0 12px;\">\
         <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" \
         style=\"background:#ffffff;border:1px solid {BORDER};border-left:4px solid {DANGER};border-radius:8px;\">\
         <tr><td style=\"padding:14px 18px 6px;\"><a href=\"https://osv.dev/vulnerability/{id}\" \
         style=\"font-family:{MONO};font-size:15px;font-weight:600;color:{DANGER};text-decoration:none;\">{id}</a></td></tr>"
    );
}

const CARD_END: &str = "<tr><td style=\"padding:0 0 8px;\"></td></tr></table></td></tr>\n";

fn section_title(html: &mut String, title: &str) {
    let _ = writeln!(
        html,
        "<tr><td style=\"padding:10px 4px 8px;font-size:13px;font-weight:600;letter-spacing:0.04em;\
         text-transform:uppercase;color:{MUTED};\">{title}</td></tr>"
    );
}

/// Tables and inline styles in the light slate palette: mail clients drop stylesheets and most of CSS.
fn html(found: &[(&RepoStats, &Vulnerability)], found_in_images: &[NewImageVulnerability], dashboard: Option<&str>) -> String {
    let mut parts = Vec::new();
    if !found.is_empty() {
        let repos: HashSet<&str> = found.iter().map(|(repo, _)| repo.name.as_str()).collect();
        let noun = if found.len() == 1 { "vulnerability" } else { "vulnerabilities" };
        let place = if repos.len() == 1 {
            "1 repository".to_string()
        } else {
            format!("{} repositories", repos.len())
        };
        parts.push(format!("{} new {noun} in the dependencies of {place}", found.len()));
    }
    if !found_in_images.is_empty() {
        let images: HashSet<&str> = found_in_images.iter().map(|hit| hit.image).collect();
        let noun = if found_in_images.len() == 1 { "vulnerability" } else { "vulnerabilities" };
        let place = if images.len() == 1 {
            "1 container image".to_string()
        } else {
            format!("{} container images", images.len())
        };
        parts.push(format!("{} new high or critical {noun} in {place}", found_in_images.len()));
    }
    let summary = parts.join("; ");
    let mut html = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta name=\"color-scheme\" content=\"light\"><title>Elaine</title></head>\n\
         <body style=\"margin:0;padding:0;background:#f1f5f9;\">\n\
         <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background:#f1f5f9;\">\
         <tr><td align=\"center\" style=\"padding:28px 12px;\">\n\
         <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" \
         style=\"max-width:680px;font-family:{FONT};color:#0f172a;\">\n\
         <tr><td style=\"padding:0 4px 4px;font-size:22px;font-weight:700;\">Elaine\
         <span style=\"font-weight:400;color:{MUTED};\"> / new vulnerabilities</span></td></tr>\n\
         <tr><td style=\"padding:0 4px 22px;font-size:15px;color:{MUTED};\">{summary}, since the previous scan.</td></tr>\n"
    );
    if !found.is_empty() && !found_in_images.is_empty() {
        section_title(&mut html, "Dependencies");
    }
    for (id, hits) in by_advisory(found) {
        card_header(&mut html, id);
        for (repo, vuln) in hits {
            let scanner = vuln.scanner.as_ref().map(label).unwrap_or_default();
            let _ = writeln!(
                html,
                "<tr><td style=\"padding:6px 18px;border-top:1px solid #e2e8f0;font-size:14px;\">\
                 <a href=\"{}\" style=\"font-weight:600;color:{PRIMARY};text-decoration:none;\">{}</a>\
                 <span style=\"font-family:{MONO};font-size:13px;\">&nbsp;&nbsp;{} {}</span>\
                 <span style=\"font-size:12px;color:{MUTED};\">&nbsp;&nbsp;{}</span></td></tr>",
                escape(&repo.html_url),
                escape(&repo.name),
                escape(&vuln.artifact),
                escape(&vuln.version),
                escape(&scanner)
            );
        }
        html.push_str(CARD_END);
    }
    if !found_in_images.is_empty() {
        section_title(&mut html, "Container images");
    }
    for (id, hits) in images_by_advisory(found_in_images) {
        card_header(&mut html, id);
        for hit in hits {
            let _ = writeln!(
                html,
                "<tr><td style=\"padding:6px 18px;border-top:1px solid #e2e8f0;font-size:14px;\">\
                 <span style=\"font-family:{MONO};font-weight:600;\">{}</span>\
                 <span style=\"font-size:12px;color:{DANGER};font-weight:600;\">&nbsp;&nbsp;{}</span><br>\
                 <span style=\"font-family:{MONO};font-size:13px;\">{} {} &rarr; {}</span><br>\
                 <span style=\"font-size:12px;color:{MUTED};\">run by {}</span></td></tr>",
                escape(hit.image),
                escape(&label(&hit.vuln.severity)),
                escape(&hit.vuln.package),
                escape(&hit.vuln.version),
                escape(&hit.vuln.fixed_in),
                escape(&hit.repos.join(", "))
            );
        }
        html.push_str(CARD_END);
    }
    if let Some(dashboard) = dashboard {
        let _ = writeln!(
            html,
            "<tr><td style=\"padding:14px 4px 0;\"><a href=\"{}\" style=\"display:inline-block;padding:9px 18px;\
             background:{PRIMARY};color:#ffffff;border-radius:6px;font-size:14px;font-weight:600;\
             text-decoration:none;\">Open elaine</a></td></tr>",
            escape(dashboard)
        );
    }
    html.push_str("</table></td></tr></table>\n</body></html>\n");
    html
}

fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            c => escaped.push(c),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::GithubRepository;

    fn repo(name: &str, vulns: Option<&[(&str, &str)]>) -> RepoStats {
        let mut repo = RepoStats::new_from_github(&GithubRepository {
            name: name.to_string(),
            ..Default::default()
        });
        repo.vulnerabilities = vulns.map(|vulns| {
            vulns
                .iter()
                .map(|(artifact, id)| Vulnerability {
                    project: name.to_string(),
                    artifact: artifact.to_string(),
                    version: "1.0".to_string(),
                    vuln_id: id.to_string(),
                    ..Default::default()
                })
                .collect()
        });
        repo
    }

    fn ids(found: &[(&RepoStats, &Vulnerability)]) -> Vec<String> {
        found.iter().map(|(repo, vuln)| format!("{} {}", repo.name, vuln.vuln_id)).collect()
    }

    #[test]
    fn the_first_push_brings_nothing_new() {
        let current = [repo("core", Some(&[("log4j", "GHSA-1")]))];
        assert!(new_vulnerabilities(None, &current).is_empty());
    }

    #[test]
    fn only_the_advisories_missing_from_a_scanned_repository_are_new() {
        let previous = [repo("core", Some(&[("log4j", "GHSA-1")])), repo("web", None)];
        let current = [
            repo("core", Some(&[("log4j", "GHSA-1"), ("jackson", "GHSA-2")])),
            repo("web", Some(&[("lodash", "GHSA-3")])),
            repo("tool", Some(&[("serde", "RUSTSEC-4")])),
        ];
        let found = new_vulnerabilities(Some(&previous), &current);
        assert_eq!(ids(&found), ["core GHSA-2", "tool RUSTSEC-4"]);
    }

    fn scanned(vulns: &[(&str, &str, Severity)]) -> ImageScan {
        ImageScan::Scanned {
            vulnerabilities: vulns
                .iter()
                .map(|(package, id, severity)| ImageVulnerability {
                    package: package.to_string(),
                    version: "1.0".to_string(),
                    fixed_in: "1.1".to_string(),
                    severity: *severity,
                    vuln_id: id.to_string(),
                })
                .collect(),
        }
    }

    #[test]
    fn a_new_tag_brings_only_the_advisories_its_image_did_not_have() {
        let mut runner = repo("web", Some(&[]));
        runner.containers = Some(vec!["acme/nginx:258".into(), "postgres:17".into(), "redis:7".into()]);
        let previous = BTreeMap::from([
            ("acme/nginx:257".to_string(), scanned(&[("openssl", "CVE-1", Severity::High)])),
            ("postgres:17".to_string(), ImageScan::NoSbom),
        ]);
        let images = BTreeMap::from([
            (
                "acme/nginx:258".to_string(),
                scanned(&[
                    ("openssl", "CVE-1", Severity::High),
                    ("zlib", "CVE-2", Severity::Critical),
                    ("curl", "CVE-3", Severity::Medium),
                ]),
            ),
            ("postgres:17".to_string(), scanned(&[("libpq", "CVE-4", Severity::High)])),
            ("redis:7".to_string(), scanned(&[("redis", "CVE-5", Severity::High)])),
        ]);
        let projects = [runner];
        let current = Scan {
            projects: &projects,
            images: &images,
        };
        let found: Vec<_> = new_image_vulnerabilities(Some(&previous), &current)
            .into_iter()
            .map(|hit| format!("{} {} {}", hit.image, hit.vuln.vuln_id, hit.repos.join(",")))
            .collect();
        assert_eq!(found, ["acme/nginx:258 CVE-2 web", "redis:7 CVE-5 web"]);
        let never_scanned = BTreeMap::from([("acme/nginx:257".to_string(), ImageScan::NoSbom)]);
        assert!(new_image_vulnerabilities(Some(&never_scanned), &current).is_empty());
    }

    #[test]
    fn a_tag_the_previous_push_could_not_scan_brings_nothing() {
        let mut runner = repo("web", Some(&[]));
        runner.containers = Some(vec!["acme/nginx:257".into(), "acme/nginx:258".into()]);
        let previous = BTreeMap::from([
            (
                "acme/nginx:257".to_string(),
                ImageScan::Failed {
                    reason: "429 Too Many Requests".into(),
                },
            ),
            ("acme/nginx:258".to_string(), scanned(&[("openssl", "CVE-1", Severity::High)])),
        ]);
        let images = BTreeMap::from([
            (
                "acme/nginx:257".to_string(),
                scanned(&[("openssl", "CVE-1", Severity::High), ("zlib", "CVE-2", Severity::High)]),
            ),
            ("acme/nginx:258".to_string(), scanned(&[("openssl", "CVE-1", Severity::High)])),
        ]);
        let projects = [runner];
        let current = Scan {
            projects: &projects,
            images: &images,
        };
        assert!(new_image_vulnerabilities(Some(&previous), &current).is_empty());
    }

    #[test]
    fn the_mail_escapes_what_the_repositories_declare() {
        let current = [repo("core", Some(&[("<img src=x>", "GHSA-1")]))];
        let found = new_vulnerabilities(Some(&[]), &current);
        let html = html(&found, &[], Some("https://elaine.example.com"));
        assert!(!html.contains("<img"));
        assert!(html.contains("&lt;img src=x&gt;"));
    }
}
