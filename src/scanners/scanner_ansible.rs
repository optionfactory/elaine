use crate::scanners::pathcollector::Pattern;
use crate::scanners::{RepoStats, ScanContext, Scanner};

pub struct AnsibleScanner;
impl Scanner for AnsibleScanner {
    fn patterns(&self) -> Vec<(&'static str, Pattern)> {
        vec![("ansible_confs", Pattern::FileName("ansible.cfg".to_string()))]
    }

    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
        if let Some(files) = ctx.matches.get("ansible_confs") {
            stats.ansible_confs = files.clone();
        }
        Ok(())
    }
}
