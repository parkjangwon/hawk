use std::fs;
use std::path::{Path, PathBuf};

use crate::{
    discovery::{discover, DiscoveryError},
    finding::Findings,
    language::Language,
    parser::{ParseError, ParserRegistry},
    rule::RuleRegistry,
    scope::{resolve, ScanTarget, ScopeError},
};

#[derive(Default)]
pub struct Scanner {
    parsers: ParserRegistry,
    rules: RuleRegistry,
}

impl Scanner {
    pub fn built_in() -> Self {
        Self {
            parsers: ParserRegistry::default(),
            rules: RuleRegistry::built_in(),
        }
    }

    pub fn scan_paths(&self, paths: &[&Path]) -> Result<ScanResult, ScanError> {
        let targets = resolve(paths).map_err(ScanError::Scope)?;
        self.scan_targets(&targets)
    }

    pub fn scan_targets(&self, targets: &[ScanTarget]) -> Result<ScanResult, ScanError> {
        let files = discover(targets).map_err(ScanError::Discovery)?;
        let mut result = ScanResult::new(files.len());

        for file in files {
            let path = file.path().to_path_buf();
            let source = match fs::read_to_string(&path) {
                Ok(source) => source,
                Err(source) => {
                    result.push_issue(FileIssueKind::Read, path.clone(), source.to_string());
                    continue;
                }
            };

            let language = Language::from_path(&path);
            let Some(parser) = self.parsers.parser_for(language) else {
                result.skipped_files += 1;
                continue;
            };

            let tree = match parser.parse(&source) {
                Ok(tree) => tree,
                Err(source) => {
                    result.push_issue(FileIssueKind::Parse, path.clone(), source.to_string());
                    continue;
                }
            };

            if tree.has_error() {
                // Analysis of a partially-parsed tree is incomplete; run rules anyway
                // but surface the issue so a degraded result can never look likea clean one.
                result.push_issue(
                    FileIssueKind::Parse,
                    path.clone(),
                    "syntax tree contains errors; analysis is incomplete".to_string(),
                );
            }

            for rule in self.rules.iter() {
                if rule.languages().contains(&language) {
                    result
                        .findings
                        .extend(rule.check(tree.root(), &source, &path));
                }
            }
        }

        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileIssueKind {
    Read,
    Parse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIssue {
    pub kind: FileIssueKind,
    pub path: PathBuf,
    pub message: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub discovered_files: usize,
    pub skipped_files: usize,
    pub issues: Vec<FileIssue>,
    pub findings: Findings,
}

impl ScanResult {
    fn new(discovered_files: usize) -> Self {
        Self {
            discovered_files,
            ..Self::default()
        }
    }

    fn push_issue(&mut self, kind: FileIssueKind, path: PathBuf, message: String) {
        self.issues.push(FileIssue {
            kind,
            path,
            message,
        });
    }

    /// A scan is degraded when any file could not be fully analyzed; incomplete results
    /// must never be presented as authoritative. See ADR-0001.
    pub fn degraded(&self) -> bool {
        !self.issues.is_empty()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    Scope(ScopeError),
    Discovery(DiscoveryError),
    ReadSource { path: PathBuf, source: String },
    Parse { path: PathBuf, source: ParseError },
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Scope(error) => match error {
                ScopeError::PathNotFound(path) => write!(f, "path not found: {}", path.display()),
                ScopeError::MetadataUnavailable { path } => {
                    write!(f, "unable to determine path type: {}", path.display())
                }
            },
            Self::Discovery(error) => error.fmt(f),
            Self::ReadSource { path, source } => {
                write!(f, "unable to read source '{}': {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(f, "unable to parse '{}': {source}", path.display())
            }
        }
    }
}

impl std::error::Error for ScanError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static SEQ: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "hawk-scan-test-{}-{suffix}-{seq}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn write(&self, name: &str, source: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, source).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn scanner_runs_discovery_parse_rule_and_collects_findings() {
        let temp = TempDir::new();
        let path = temp.write(
            "Example.java",
            "class Example { void run(String input) { Runtime.getRuntime().exec(input); } }",
        );

        let result = Scanner::built_in().scan_paths(&[path.as_path()]).unwrap();

        assert_eq!(result.discovered_files, 1);
        assert_eq!(result.skipped_files, 0);
        assert!(result.issues.is_empty());
        assert!(!result.degraded());
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn unsupported_language_is_skipped_without_error() {
        let temp = TempDir::new();
        let path = temp.write("README.md", "Runtime.getRuntime().exec(input);");

        let result = Scanner::built_in().scan_paths(&[path.as_path()]).unwrap();

        assert_eq!(result.discovered_files, 1);
        assert_eq!(result.skipped_files, 1);
        assert!(result.issues.is_empty());
        assert!(!result.degraded());
        assert!(result.findings.is_empty());
    }

    #[test]
    fn unparseable_file_is_isolated_and_reported_as_degraded() {
        let temp = TempDir::new();
        let path = temp.write("Broken.java", "class Example {");

        let result = Scanner::built_in().scan_paths(&[path.as_path()]).unwrap();

        assert_eq!(result.discovered_files, 1);
        assert_eq!(result.issues.len(), 1);
        assert_eq!(result.issues[0].kind, FileIssueKind::Parse);
        assert_eq!(result.issues[0].path, path);
        assert!(result.degraded());
    }

    #[test]
    fn scan_pipeline_error_is_fatal_only_for_scope_and_discovery() {
        // Scope errors abort the whole scan: a missing path cannot be scanned.
        let err = Scanner::built_in()
            .scan_paths(&[std::path::Path::new("definitely-missing-path")])
            .unwrap_err();

        assert!(matches!(err, ScanError::Scope(_)));
    }
}
