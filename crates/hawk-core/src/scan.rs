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

#[derive(Debug, Default)]
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
            let source = fs::read_to_string(&path).map_err(|source| ScanError::ReadSource {
                path: path.clone(),
                source: source.to_string(),
            })?;

            let language = Language::from_path(&path);
            let Some(parser) = self.parsers.parser_for(language) else {
                result.skipped_files += 1;
                continue;
            };

            let tree = parser.parse(&source).map_err(|source| ScanError::Parse {
                path: path.clone(),
                source,
            })?;

            if tree.has_error() {
                result.parse_errors += 1;
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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub discovered_files: usize,
    pub skipped_files: usize,
    pub parse_errors: usize,
    pub findings: Findings,
}

impl ScanResult {
    fn new(discovered_files: usize) -> Self {
        Self {
            discovered_files,
            ..Self::default()
        }
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
            Self::Scope(error) => error.fmt(f),
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
        time::{SystemTime, UNIX_EPOCH},
    };

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let suffix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!("hawk-scan-test-{suffix}"));
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
        assert_eq!(result.parse_errors, 0);
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn unsupported_language_is_skipped_without_error() {
        let temp = TempDir::new();
        let path = temp.write("README.md", "Runtime.getRuntime().exec(input);");

        let result = Scanner::built_in().scan_paths(&[path.as_path()]).unwrap();

        assert_eq!(result.discovered_files, 1);
        assert_eq!(result.skipped_files, 1);
        assert!(result.findings.is_empty());
    }
}
