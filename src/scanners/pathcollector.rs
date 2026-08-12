use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub enum Pattern {
    /// Matches an exact relative path from repository root (e.g. "pinch.yaml")
    ExactPath(PathBuf),
    /// Matches exact file or directory name anywhere in the tree (e.g. "Dockerfile")
    FileName(String),
    /// Matches directory name specifically anywhere in the tree (e.g. "roles")
    DirName(String),
    /// Matches filename against a closure predicate (e.g. prefix + suffix check)
    FileNamePattern(Box<dyn Fn(&str) -> bool + Send + Sync>),
}

impl Pattern {
    pub fn matches(&self, rel_path: &Path, name: &str, is_dir: bool) -> bool {
        match self {
            Pattern::ExactPath(target) => rel_path == target,
            Pattern::FileName(target) => name == target,
            Pattern::DirName(target) => is_dir && name == target,
            Pattern::FileNamePattern(pred) => pred(name),
        }
    }
}

#[derive(Default)]
pub struct PathCollector {
    rules: HashMap<String, Pattern>,
}

impl PathCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a matcher rule under a result key
    pub fn register(mut self, key: impl Into<String>, pattern: Pattern) -> Self {
        self.rules.insert(key.into(), pattern);
        self
    }

    /// Helper for closure/predicate rules
    pub fn register_pattern<F>(self, key: impl Into<String>, predicate: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        self.register(key, Pattern::FileNamePattern(Box::new(predicate)))
    }

    /// Execute single pass scan across repository tree
    pub fn scan(&self, root: &Path) -> HashMap<String, Vec<PathBuf>> {
        let mut results: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for key in self.rules.keys() {
            results.insert(key.clone(), Vec::new());
        }

        for entry in walkdir::WalkDir::new(root)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_str().unwrap_or("");
                !matches!(name, ".git" | "node_modules" | "target" | "vendor" | ".venv")
            })
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            let rel_path = match path.strip_prefix(root) {
                Ok(p) if p != Path::new("") => p,
                _ => continue,
            };

            let name = entry.file_name().to_string_lossy();
            let is_dir = entry.file_type().is_dir();

            for (key, pattern) in &self.rules {
                if pattern.matches(rel_path, &name, is_dir)
                    && let Some(matched_paths) = results.get_mut(key)
                {
                    matched_paths.push(rel_path.to_path_buf());
                }
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Builds a small tree with a mix of files plus vendored/VCS noise that must be pruned.
    fn make_tree() -> TempDir {
        let dir = TempDir::new().unwrap();
        let root = dir.path();
        fs::write(root.join("pinch.yaml"), "name: x").unwrap();
        fs::write(root.join("Dockerfile"), "FROM x").unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub").join("Cargo.lock"), "[[package]]").unwrap();
        // noise that the exclusion filter should prune entirely
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git").join("config"), "[core]").unwrap();
        fs::create_dir_all(root.join("node_modules")).unwrap();
        fs::write(root.join("node_modules").join("pkg.json"), "{}").unwrap();
        dir
    }

    #[test]
    fn collects_by_file_name() {
        let dir = make_tree();
        let matches = PathCollector::new()
            .register("docker", Pattern::FileName("Dockerfile".to_string()))
            .scan(dir.path());
        let docker = matches.get("docker").unwrap();
        assert_eq!(docker, &vec![PathBuf::from("Dockerfile")]);
    }

    #[test]
    fn collects_by_exact_path_only_at_root() {
        let dir = make_tree();
        let matches = PathCollector::new()
            .register("pinch", Pattern::ExactPath(PathBuf::from("pinch.yaml")))
            .scan(dir.path());
        assert_eq!(matches.get("pinch").unwrap(), &vec![PathBuf::from("pinch.yaml")]);

        // A nested file with the same basename must NOT match an ExactPath rule scoped to root.
        let nested = PathCollector::new()
            .register("cargo", Pattern::ExactPath(PathBuf::from("Cargo.lock")))
            .scan(dir.path());
        assert!(nested.get("cargo").unwrap().is_empty());
    }

    #[test]
    fn prunes_vendored_and_vcs_directories() {
        let dir = make_tree();
        // match-everything predicate so we can observe exactly what was visited
        let matches = PathCollector::new()
            .register("all", Pattern::FileNamePattern(Box::new(|_| true)))
            .scan(dir.path());
        let visited: Vec<String> = matches["all"].iter().map(|p| p.to_string_lossy().into_owned()).collect();

        assert!(visited.iter().all(|p| !(p.starts_with(".git") || p.starts_with("node_modules"))),
            "VCS/vendored dirs leaked into results: {visited:?}");
        assert!(visited.iter().any(|p| p == "pinch.yaml"));
        assert!(visited.iter().any(|p| p == "Dockerfile"));
        assert!(visited.iter().any(|p| p == "sub/Cargo.lock"));
    }

    #[test]
    fn registered_key_always_present_even_with_no_matches() {
        let dir = make_tree();
        let matches = PathCollector::new()
            .register("none", Pattern::FileName("does-not-exist".to_string()))
            .scan(dir.path());
        assert!(matches.contains_key("none"));
        assert!(matches["none"].is_empty());
    }
}
