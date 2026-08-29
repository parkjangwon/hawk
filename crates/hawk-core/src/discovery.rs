use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::scope::ScanTarget;

const DEFAULT_IGNORED_DIRECTORIES: &[&str] = &[".git", "node_modules", "target", "build", "dist"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    ReadDirectory { path: PathBuf, source: String },
    ReadMetadata { path: PathBuf, source: String },
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadDirectory { path, source } => {
                write!(
                    formatter,
                    "unable to read directory '{}': {source}",
                    path.display()
                )
            }
            Self::ReadMetadata { path, source } => {
                write!(
                    formatter,
                    "unable to read metadata for '{}': {source}",
                    path.display()
                )
            }
        }
    }
}

impl std::error::Error for DiscoveryError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    path: PathBuf,
}

impl FileEntry {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Discovers regular files from resolved scan targets.
///
/// Directory traversal is deterministic and skips common generated/dependency
/// directories by default. Symbolic links are not followed in this initial
/// implementation, preventing accidental traversal outside the requested scope
/// and symlink cycles.
pub fn discover(targets: &[ScanTarget]) -> Result<Vec<FileEntry>, DiscoveryError> {
    let mut files = Vec::new();

    for target in targets {
        match target {
            ScanTarget::File(path) => {
                if is_regular_file(path)? {
                    files.push(FileEntry::new(path.clone()));
                }
            }
            ScanTarget::Directory(path) => collect_directory(path, &mut files)?,
        }
    }

    Ok(files)
}

fn collect_directory(path: &Path, files: &mut Vec<FileEntry>) -> Result<(), DiscoveryError> {
    let mut entries = fs::read_dir(path)
        .map_err(|error| directory_error(path, error))?
        .collect::<Result<Vec<_>, io::Error>>()
        .map_err(|error| directory_error(path, error))?;

    entries.sort_by(|left, right| left.file_name().cmp(&right.file_name()));

    for entry in entries {
        let entry_path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| DiscoveryError::ReadMetadata {
                path: entry_path.clone(),
                source: error.to_string(),
            })?;

        if file_type.is_symlink() {
            continue;
        }

        if file_type.is_dir() {
            if is_ignored_directory(&entry_path) {
                continue;
            }
            collect_directory(&entry_path, files)?;
        } else if file_type.is_file() {
            files.push(FileEntry::new(entry_path));
        }
    }

    Ok(())
}

fn is_regular_file(path: &Path) -> Result<bool, DiscoveryError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| DiscoveryError::ReadMetadata {
        path: path.to_path_buf(),
        source: error.to_string(),
    })?;

    Ok(metadata.is_file())
}

fn is_ignored_directory(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| DEFAULT_IGNORED_DIRECTORIES.contains(&name))
}

fn directory_error(path: &Path, error: io::Error) -> DiscoveryError {
    DiscoveryError::ReadDirectory {
        path: path.to_path_buf(),
        source: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after UNIX_EPOCH")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("hawk-discovery-test-{suffix}"));
            fs::create_dir(&path).expect("temporary directory should be created");
            Self { path }
        }

        fn file(&self, relative: &str) -> PathBuf {
            let path = self.path.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("parent should be created");
            }
            fs::write(&path, "").expect("test file should be created");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn discovers_regular_files_recursively() {
        let temp = TempDir::new();
        let first = temp.file("src/First.java");
        let second = temp.file("src/internal/Second.java");

        let targets = vec![ScanTarget::Directory(temp.path.clone())];
        let files = discover(&targets).expect("discovery should succeed");

        assert_eq!(
            files.into_iter().map(|file| file.path).collect::<Vec<_>>(),
            vec![first, second]
        );
    }

    #[test]
    fn discovers_a_file_target_without_traversal() {
        let temp = TempDir::new();
        let file = temp.file("Example.java");

        let files = discover(&[ScanTarget::File(file.clone())]).expect("discovery should succeed");

        assert_eq!(files, vec![FileEntry::new(file)]);
    }

    #[test]
    fn skips_default_ignored_directories() {
        let temp = TempDir::new();
        let source = temp.file("src/Main.java");
        temp.file("target/generated.java");
        temp.file("node_modules/package.js");
        temp.file("dist/bundle.js");
        temp.file("build/output.js");
        temp.file(".git/config");

        let files = discover(&[ScanTarget::Directory(temp.path.clone())])
            .expect("discovery should succeed");

        assert_eq!(files, vec![FileEntry::new(source)]);
    }

    #[test]
    fn discovery_order_is_deterministic() {
        let temp = TempDir::new();
        let zulu = temp.file("z/Z.java");
        let alpha = temp.file("a/A.java");
        let middle = temp.file("m/M.java");

        let files = discover(&[ScanTarget::Directory(temp.path.clone())])
            .expect("discovery should succeed");

        assert_eq!(
            files.into_iter().map(|file| file.path).collect::<Vec<_>>(),
            vec![alpha, middle, zulu]
        );
    }
}
