use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::scope::ScanTarget;

const DEFAULT_IGNORED_DIRECTORIES: &[&str] = &[
    // Version control and hawk's own state.
    ".git",
    ".hawk",
    // JavaScript/TypeScript.
    "node_modules",
    ".next",
    ".nuxt",
    "dist",
    "coverage",
    // Rust/C builds.
    "target",
    "build",
    // Python.
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    // Vendored dependencies (Go, PHP, …).
    "vendor",
    // Editor / tooling state.
    ".idea",
    ".gradle",
];

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
    discover_with_excludes(targets, &[])
}

pub fn discover_with_excludes(
    targets: &[ScanTarget],
    excludes: &[String],
) -> Result<Vec<FileEntry>, DiscoveryError> {
    let mut files = Vec::new();

    for target in targets {
        match target {
            ScanTarget::File(path) => {
                if is_regular_file(path)? {
                    files.push(FileEntry::new(path.clone()));
                }
            }
            ScanTarget::Directory(path) => collect_directory(path, &mut files, excludes)?,
        }
    }

    Ok(files)
}

fn collect_directory(
    path: &Path,
    files: &mut Vec<FileEntry>,
    excludes: &[String],
) -> Result<(), DiscoveryError> {
    let mut entries = fs::read_dir(path)
        .map_err(|error| directory_error(path, error))?
        .collect::<Result<Vec<_>, io::Error>>()
        .map_err(|error| directory_error(path, error))?;

    entries.sort_by_key(|entry| entry.file_name());

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
            if is_ignored_directory(&entry_path) || is_excluded(&entry_path, excludes) {
                continue;
            }
            collect_directory(&entry_path, files, excludes)?;
        } else if file_type.is_file() && !is_excluded(&entry_path, excludes) {
            files.push(FileEntry::new(entry_path));
        }
    }

    Ok(())
}

/// Config `exclude` semantics: a pattern matches when
/// - a single-segment pattern (`fixtures`, `*.min.js`) names some path
///   component anywhere in the path, or
/// - a multi-segment pattern (`src/generated`) matches a contiguous run of
///   path components at any depth.
///
/// `*` acts as a within-segment wildcard. Leading/trailing slashes and a
/// leading `./` are ignored, so the older `"/fixtures/"` style keeps working.
/// (Substring matching was deliberately rejected: `exclude = ["test"]` used
/// to exclude `src/contest/Main.java`.)
fn is_excluded(path: &Path, excludes: &[String]) -> bool {
    let normalized = path.to_string_lossy().replace('\\', "/");
    let normalized = normalized.strip_prefix("./").unwrap_or(&normalized);
    let components: Vec<&str> = normalized.split('/').filter(|c| !c.is_empty()).collect();
    excludes.iter().any(|pattern| {
        let pattern = pattern.trim();
        let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
        let pattern = pattern.trim_matches('/');
        if pattern.is_empty() {
            return false;
        }
        let segments: Vec<&str> = pattern.split('/').collect();
        if segments.len() == 1 {
            components
                .iter()
                .any(|component| glob_match(segments[0], component))
        } else {
            // Any contiguous run of path components at any depth (paths
            // arrive prefixed by the scan target, often absolute).
            components.len() >= segments.len()
                && components.windows(segments.len()).any(|window| {
                    segments
                        .iter()
                        .zip(window)
                        .all(|(pattern, component)| glob_match(pattern, component))
                })
        }
    })
}

/// Within-segment glob: only `*` (any run of characters) is supported.
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    // Two-pointer greedy `*` matching.
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut backtrack) = (None, 0usize);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == text[t] || pattern[p] == '?') {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            backtrack = t;
        } else if let Some(star_at) = star {
            p = star_at + 1;
            backtrack += 1;
            t = backtrack;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
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
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after UNIX_EPOCH")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "hawk-discovery-test-{}-{suffix}-{seq}",
                std::process::id()
            ));
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
        temp.file(".hawk/cache/graph.bin");

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

    #[test]
    fn excludes_are_component_glob_matches_not_substrings() {
        // Regression: excludes used raw substring matching, so `exclude =
        // ["test"]` excluded `src/contest/Main.java`.
        let temp = TempDir::new();
        let keep = temp.file("src/contest/Main.java");
        let drop = temp.file("src/test/Util.java");

        let files = discover_with_excludes(
            &[ScanTarget::Directory(temp.path.clone())],
            &["test".to_string()],
        )
        .expect("discovery should succeed");

        assert!(files.iter().any(|f| f.path == keep));
        assert!(!files.iter().any(|f| f.path == drop));
    }

    #[test]
    fn excludes_match_directories_anywhere_and_glob_within_a_segment() {
        let temp = TempDir::new();
        let nested = temp.file("a/b/fixtures/Data.java");
        let generated = temp.file("src/generated/Out.java");
        let source = temp.file("src/Main.java");
        let dotted = temp.file("app/keep.min.js");

        let files = discover_with_excludes(
            &[ScanTarget::Directory(temp.path.clone())],
            &[
                "/fixtures/".to_string(), // legacy spelling keeps working
                "src/generated".to_string(),
                "*.min.js".to_string(),
            ],
        )
        .expect("discovery should succeed");

        assert!(!files.iter().any(|f| f.path == nested));
        assert!(!files.iter().any(|f| f.path == generated));
        assert!(!files.iter().any(|f| f.path == dotted));
        assert!(files.iter().any(|f| f.path == source));
    }
}
