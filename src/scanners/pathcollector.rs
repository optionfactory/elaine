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
                if pattern.matches(rel_path, &name, is_dir) {
                    if let Some(matched_paths) = results.get_mut(key) {
                        matched_paths.push(rel_path.to_path_buf());
                    }
                }
            }
        }

        results
    }
}