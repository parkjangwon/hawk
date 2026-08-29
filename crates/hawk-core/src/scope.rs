use std::path::{Path, PathBuf};

/// A user-requested filesystem target for a Hawk scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanTarget {
    File(PathBuf),
    Directory(PathBuf),
}

impl ScanTarget {
    pub fn path(&self) -> &Path {
        match self {
            Self::File(path) | Self::Directory(path) => path,
        }
    }
}

/// Errors that can occur while resolving scan targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError {
    PathNotFound(PathBuf),
    MetadataUnavailable { path: PathBuf },
}

/// Resolves CLI path arguments into typed scan targets.
///
/// An empty argument list means the current directory (`.`).
pub fn resolve(paths: &[&Path]) -> Result<Vec<ScanTarget>, ScopeError> {
    let paths = if paths.is_empty() {
        vec![Path::new(".")]
    } else {
        paths.to_vec()
    };

    paths.into_iter().map(resolve_path).collect()
}

fn resolve_path(path: &Path) -> Result<ScanTarget, ScopeError> {
    let metadata = path
        .metadata()
        .map_err(|_| ScopeError::PathNotFound(path.to_path_buf()))?;

    if metadata.is_dir() {
        Ok(ScanTarget::Directory(path.to_path_buf()))
    } else if metadata.is_file() {
        Ok(ScanTarget::File(path.to_path_buf()))
    } else {
        Err(ScopeError::MetadataUnavailable {
            path: path.to_path_buf(),
        })
    }
}
