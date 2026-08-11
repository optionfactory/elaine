use crate::scanners::pathcollector::Pattern;
use crate::scanners::{RepoStats, ScanContext, Scanner};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

pub struct PinchScanner;
impl Scanner for PinchScanner {
    fn patterns(&self) -> Vec<(&'static str, Pattern)> {
        vec![("pinch_manifest", Pattern::ExactPath(PathBuf::from("pinch.yaml")))]
    }

    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
        let pinch_audit = ctx
            .matches
            .get("pinch_manifest")
            .and_then(|paths| paths.first())
            .and_then(|rel_path| File::open(ctx.root.join(rel_path)).ok())
            .map(BufReader::new)
            .and_then(|reader| serde_saphyr::from_reader::<_, pinch::schema::PinchManifest>(reader).ok())
            .map(|manifest| manifest.audit());

        match pinch_audit {
            Some(audit) => {
                stats.audit = Some(audit.project);
                stats.add_containers(audit.containers);
            }
            None => {
                stats.audit = None;
                stats.checked_for_containers();
            }
        }
        Ok(())
    }
}
