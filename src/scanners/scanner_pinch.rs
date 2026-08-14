use crate::scanners::pathcollector::Pattern;
use crate::scanners::{CheckStatus, RepoStats, ScanContext, Scanner, ScannerKind};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

pub struct PinchScanner;
impl Scanner for PinchScanner {
    fn patterns(&self) -> Vec<(&'static str, Pattern)> {
        vec![("pinch_manifest", Pattern::ExactPath(PathBuf::from("pinch.yaml")))]
    }
    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
        let Some(rel_path) = ctx.matches.get("pinch_manifest").and_then(|paths| paths.first()) else {
            stats.checked_for_containers();
            return Ok(());
        };
        ctx.set_message(format!("[{}] Running pinch checks...", ctx.repo.name));
        let pinch = File::open(ctx.root.join(rel_path))
            .ok()
            .and_then(|f| serde_saphyr::from_reader::<_, PinchFile>(BufReader::new(f)).ok());
        match pinch {
            Some(pinch) => {
                stats.add_containers(expand_images(pinch));
                stats.record_check(ScannerKind::Pinch, "containers", CheckStatus::Ok);
            }
            None => {
                stats.checked_for_containers();
                ctx.report_error(format!("[{}] 🔥 Failed to parse pinch.yaml", ctx.repo.name));
                stats.record_check(ScannerKind::Pinch, "containers", CheckStatus::Failed);
            }
        }
        Ok(())
    }
}

fn expand_images(pinch: PinchFile) -> Vec<String> {
    let mut seen = BTreeSet::new();
    pinch
        .processes
        .iter()
        .filter_map(|p| match &p.run {
            PinchRun::Detailed(d) if d.kind == "docker" => d.image.clone(),
            PinchRun::Shorthand(_) | PinchRun::Detailed(_) => None,
        })
        .map(|image| apply_vars(&image, &pinch.vars))
        .filter(|image| seen.insert(image.clone()))
        .collect()
}

fn apply_vars(input: &str, vars: &HashMap<String, String>) -> String {
    let mut out = input.to_string();
    for (key, value) in vars {
        let pattern = format!("{{{{{}}}}}", key);
        if out.contains(&pattern) {
            out = out.replace(&pattern, value);
        }
    }
    out
}

#[derive(Debug, Deserialize)]
struct PinchFile {
    #[serde(default)]
    vars: HashMap<String, String>,
    #[serde(default)]
    processes: Vec<PinchProcess>,
}

#[derive(Debug, Deserialize)]
struct PinchProcess {
    run: PinchRun,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PinchRun {
    Shorthand(#[allow(dead_code)] String),
    Detailed(PinchRunDetail),
}

#[derive(Debug, Deserialize)]
struct PinchRunDetail {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    image: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinch(yaml: &str) -> PinchFile {
        serde_saphyr::from_str(yaml).expect("valid pinch fixture")
    }

    #[test]
    fn extracts_docker_images_and_ignores_others() {
        let p = pinch(
            "processes:\n  - name: db\n    run:\n      type: docker\n      image: postgres:16\n  - name: web\n    run: npm run dev\n",
        );
        assert_eq!(expand_images(p), vec!["postgres:16".to_string()]);
    }

    #[test]
    fn expands_vars_in_image_names() {
        let p = pinch(
            "vars:\n  registry: registry.example.com\nprocesses:\n  - name: db\n    run:\n      type: docker\n      image: '{{registry}}/postgres:16'\n",
        );
        assert_eq!(expand_images(p), vec!["registry.example.com/postgres:16".to_string()]);
    }

    #[test]
    fn dedupes_identical_images() {
        let p = pinch(
            "processes:\n  - name: db1\n    run:\n      type: docker\n      image: postgres:16\n  - name: db2\n    run:\n      type: docker\n      image: postgres:16\n",
        );
        assert_eq!(expand_images(p), vec!["postgres:16".to_string()]);
    }
}
