use flate2::read::GzDecoder;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use tar::Archive;
use tempfile::TempDir;

pub struct TarballSandbox {
    _temp_dir: TempDir,
    project_root: PathBuf,
}

impl TarballSandbox {
    pub fn unpack<P: AsRef<Path>>(archive_path: P) -> anyhow::Result<Self> {
        let temp_dir = TempDir::new()?;
        let unpack_path = temp_dir.path();

        let file = File::open(archive_path)?;
        let mut archive = Archive::new(GzDecoder::new(file));
        archive.unpack(unpack_path)?;

        let entries: Vec<_> = fs::read_dir(unpack_path)?.filter_map(|e| e.ok()).collect();
        let project_root = if entries.len() == 1 && entries[0].file_type()?.is_dir() {
            entries[0].path()
        } else {
            unpack_path.to_path_buf()
        };

        Ok(Self {
            _temp_dir: temp_dir,
            project_root,
        })
    }

    pub fn path(&self) -> &Path {
        &self.project_root
    }
}
