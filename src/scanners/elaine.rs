use crate::scanners::pathcollector::Pattern;
use crate::scanners::{CheckStatus, RepoStats, ScanContext, Scanner, ScannerKind};
use crate::schema::ElaineManifest;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

pub struct ElaineScanner;
impl Scanner for ElaineScanner {
    fn patterns(&self) -> Vec<(&'static str, Pattern)> {
        vec![("elaine_manifest", Pattern::ExactPath(PathBuf::from("elaine.yaml")))]
    }
    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
        let Some(rel_path) = ctx.matches.get("elaine_manifest").and_then(|paths| paths.first()) else {
            return Ok(());
        };
        ctx.set_message(format!("[{}] Running elaine checks...", ctx.repo.name));
        let manifest = File::open(ctx.root.join(rel_path))
            .ok()
            .and_then(|f| serde_saphyr::from_reader::<_, ElaineManifest>(BufReader::new(f)).ok());
        match manifest {
            Some(manifest) => {
                stats.manifest = Some(manifest);
                stats.record_check(ScannerKind::Elaine, "manifest", CheckStatus::Ok);
            }
            None => {
                stats.manifest = None;
                ctx.report_failure("elaine", &"Failed to parse elaine.yaml".to_string());
                stats.record_check(ScannerKind::Elaine, "manifest", CheckStatus::Failed);
            }
        }
        Ok(())
    }
}
