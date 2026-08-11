use crate::scanners::pathcollector::Pattern;
use crate::scanners::{RepoStats, ScanContext, Scanner};

pub struct LegopfaScanner;
impl Scanner for LegopfaScanner {
    fn patterns(&self) -> Vec<(&'static str, Pattern)> {
        vec![(
            "legopfa_confs",
            Pattern::FileNamePattern(Box::new(|name| name.starts_with("legopfa") && name.ends_with(".json"))),
        )]
    }
    fn interested_in_archived(&self) -> bool {
        false
    }

    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
        if let Some(files) = ctx.matches.get("legopfa_confs") {
            stats.legopfa_confs = files.clone();
        }
        Ok(())
    }
}
