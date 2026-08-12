use crate::scanners::pathcollector::Pattern;
use crate::scanners::{CheckStatus, RepoStats, ScanContext, Scanner, ScannerKind};
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
        let manifest = File::open(ctx.root.join(rel_path))
            .ok()
            .and_then(|f| serde_saphyr::from_reader::<_, pinch::schema::PinchManifest>(BufReader::new(f)).ok());
        match manifest {
            Some(manifest) => {
                let audit = manifest.audit();
                stats.audit = Some(audit.project);
                stats.add_containers(audit.containers);
                stats.record_check(ScannerKind::Pinch, "manifest", CheckStatus::Ok);
            }
            None => {
                stats.audit = None;
                stats.checked_for_containers();
                ctx.report_error(format!("[{}] 🔥 Failed to parse pinch.yaml", ctx.repo.name));
                stats.record_check(ScannerKind::Pinch, "manifest", CheckStatus::Failed);
            }
        }
        Ok(())
    }
}
