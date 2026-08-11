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
    fn interested_in_archived(&self) -> bool {
        false
    }

    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
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
