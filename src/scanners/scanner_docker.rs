use crate::scanners::pathcollector::Pattern;
use crate::scanners::{RepoStats, ScanContext, Scanner};

pub struct DockerScanner;
impl Scanner for DockerScanner {
    fn patterns(&self) -> Vec<(&'static str, Pattern)> {
        vec![
            ("docker_files", Pattern::FileName("Dockerfile".to_string())),
            ("docker_compose_files", Pattern::FileName("docker-compose.yml".to_string())),
        ]
    }

    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
        if ctx.repo.archived || ctx.repo.fork || ctx.repo.disabled {
            return Ok(());
        }
        let mut all_docker = Vec::new();
        if let Some(files) = ctx.matches.get("docker_files") {
            all_docker.extend(files.iter().cloned());
        }
        if let Some(files) = ctx.matches.get("docker_compose_files") {
            all_docker.extend(files.iter().cloned());
        }
        stats.docker_files = all_docker;
        Ok(())
    }
}
