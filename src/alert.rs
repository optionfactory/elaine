use crate::config::AlertsConfig;
use crate::scanners::{RepoStats, Vulnerability};
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::extension::ClientId;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write;
use std::net::IpAddr;

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

/// Mails the vulnerabilities `current` brings over `previous`, if any.
pub async fn notify(alerts: &AlertsConfig, previous: Option<&[RepoStats]>, current: &[RepoStats], dashboard: Option<&str>) -> anyhow::Result<()> {
    let found = new_vulnerabilities(previous, current);
    if found.is_empty() {
        return Ok(());
    }
    let subject = match found.len() {
        1 => "Elaine: 1 new vulnerability".to_string(),
        n => format!("Elaine: {n} new vulnerabilities"),
    };
    let message = Message::builder()
        .from(Mailbox::new(Some("Elaine".into()), alerts.from.email.clone()))
        .to(alerts.to.clone())
        .subject(subject)
        .multipart(MultiPart::alternative_plain_html(text(&found, dashboard), html(&found, dashboard)))?;
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
    eprintln!("[Alert] Mailed {} new vulnerabilities to {}.", found.len(), alerts.to);
    Ok(())
}

fn by_advisory<'a>(found: &[(&'a RepoStats, &'a Vulnerability)]) -> BTreeMap<&'a str, Vec<(&'a RepoStats, &'a Vulnerability)>> {
    let mut grouped: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    for (repo, vuln) in found {
        grouped.entry(vuln.vuln_id.as_str()).or_default().push((*repo, *vuln));
    }
    grouped
}

fn scanner(vuln: &Vulnerability) -> String {
    vuln.scanner
        .and_then(|kind| serde_json::to_value(kind).ok())
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn text(found: &[(&RepoStats, &Vulnerability)], dashboard: Option<&str>) -> String {
    let mut text = String::new();
    for (id, hits) in by_advisory(found) {
        let _ = writeln!(text, "{id}  https://osv.dev/vulnerability/{id}");
        for (repo, vuln) in hits {
            let _ = writeln!(text, "  {}: {} {} ({})", repo.name, vuln.artifact, vuln.version, scanner(vuln));
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

/// Tables and inline styles in the light slate palette: mail clients drop stylesheets and most of CSS.
fn html(found: &[(&RepoStats, &Vulnerability)], dashboard: Option<&str>) -> String {
    let repos: HashSet<&str> = found.iter().map(|(repo, _)| repo.name.as_str()).collect();
    let summary = match (found.len(), repos.len()) {
        (1, _) => "1 new vulnerability".to_string(),
        (n, 1) => format!("{n} new vulnerabilities in 1 repository"),
        (n, r) => format!("{n} new vulnerabilities in {r} repositories"),
    };
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
    for (id, hits) in by_advisory(found) {
        let id = escape(id);
        let _ = writeln!(
            html,
            "<tr><td style=\"padding:0 0 12px;\">\
             <table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" \
             style=\"background:#ffffff;border:1px solid {BORDER};border-left:4px solid {DANGER};border-radius:8px;\">\
             <tr><td style=\"padding:14px 18px 6px;\"><a href=\"https://osv.dev/vulnerability/{id}\" \
             style=\"font-family:{MONO};font-size:15px;font-weight:600;color:{DANGER};text-decoration:none;\">{id}</a></td></tr>"
        );
        for (repo, vuln) in hits {
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
                escape(&scanner(vuln))
            );
        }
        html.push_str("<tr><td style=\"padding:0 0 8px;\"></td></tr></table></td></tr>\n");
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

    #[test]
    fn the_mail_escapes_what_the_repositories_declare() {
        let current = [repo("core", Some(&[("<img src=x>", "GHSA-1")]))];
        let found = new_vulnerabilities(Some(&[]), &current);
        let html = html(&found, Some("https://elaine.example.com"));
        assert!(!html.contains("<img"));
        assert!(html.contains("&lt;img src=x&gt;"));
    }
}
