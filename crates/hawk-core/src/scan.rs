use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{
    cache::{self, Cache},
    discovery::{discover_with_excludes, DiscoveryError},
    finding::Findings,
    language::Language,
    pack::{PackError, PackRegistry},
    parser::{ParseError, ParserRegistry},
    scope::{resolve, ScanTarget, ScopeError},
};

#[derive(Default)]
pub struct Scanner {
    parsers: ParserRegistry,
    packs: PackRegistry,
    cache: Option<Cache>,
    excludes: Vec<String>,
}

impl Scanner {
    pub fn built_in() -> Result<Self, ScanError> {
        let packs = PackRegistry::with_built_in().map_err(ScanError::Pack)?;
        Ok(Self {
            parsers: ParserRegistry::default(),
            packs,
            cache: None,
            excludes: Vec::new(),
        })
    }

    /// Enables the incremental cache rooted at the given directory
    /// (the `.hawk/cache` path). The cache is best-effort: a full scan is
    /// always correct if reads or writes fail.
    pub fn with_cache(mut self, root: PathBuf) -> Self {
        let namespace = self.packs.cache_namespace();
        self.cache = Some(Cache::new(root).with_namespace(namespace));
        self
    }

    pub fn with_excludes(mut self, excludes: Vec<String>) -> Self {
        self.excludes = excludes;
        self
    }

    pub fn scan_paths(&self, paths: &[&Path]) -> Result<ScanResult, ScanError> {
        let targets = resolve(paths).map_err(ScanError::Scope)?;
        self.scan_targets(&targets)
    }

    pub fn scan_targets(&self, targets: &[ScanTarget]) -> Result<ScanResult, ScanError> {
        let files =
            discover_with_excludes(targets, &self.excludes).map_err(ScanError::Discovery)?;
        // Phase 1: hash + cache-check every file in parallel. Cache hits (files
        // unchanged since the last scan) are not read or parsed here; cache
        // misses are read and parsed for the rule phase.
        let mut parsed: Vec<ParsedFile> = files
            .par_iter()
            .map(|file| Scanner::prepare_one(&self.parsers, &self.cache, file.path()))
            .collect();
        // Phase 2: project-wide architecture index (symbols + call edges).
        // When every file's hash matches the persisted snapshot, the graph is
        // restored without parsing or re-indexing; otherwise the snapshot is
        // rebuilt from the parsed trees (cache-hit files are parsed here —
        // the graph needs every file's symbols for cross-file analysis).
        let snapshot = self
            .cache
            .as_ref()
            .and_then(|cache| cache.load_graph_snapshot());
        let graph = if snapshot.as_ref().is_some_and(|snapshot| {
            snapshot.matches(
                &parsed
                    .iter()
                    .map(|file| (file.path.as_path(), file.source_hash.as_deref()))
                    .collect::<Vec<_>>(),
            )
        }) {
            crate::code_graph::CodeGraph::from_snapshot(snapshot.as_ref().expect("checked above"))
        } else {
            parsed.par_iter_mut().for_each(|file| {
                if file.tree.is_none() && !file.skipped && file.issues.is_empty() {
                    Scanner::parse_tree(&self.parsers, file);
                }
            });
            let graph = crate::code_graph::CodeGraph::build(
                parsed.iter().filter_map(ParsedFile::indexed).collect(),
            );
            if let Some(cache) = &self.cache {
                let files = parsed
                    .iter()
                    .filter_map(|file| {
                        file.source_hash
                            .as_ref()
                            .map(|hash| crate::code_graph::GraphFileMeta {
                                path: file.path.clone(),
                                hash: hash.clone(),
                            })
                    })
                    .collect();
                let _ = cache.save_graph_snapshot(graph.snapshot_with(files));
            }
            graph
        };
        // Phase 3: run rules per file with cross-file callee resolution
        // (parallel; the graph is read-only and shared).
        let per_file: Vec<ScanResult> = parsed
            .par_iter()
            .map(|file| Scanner::scan_parsed(&self.packs, &graph, &self.cache, file))
            .collect();

        let mut result = ScanResult::new(files.len());
        result.rule_count = self.packs.count();
        result.pack_names = self.packs.pack_names();
        for file_result in per_file {
            result.scanned_files += file_result.scanned_files;
            result.skipped_files += file_result.skipped_files;
            result.issues.extend(file_result.issues);
            for finding in file_result.findings.iter() {
                result.findings.push(finding.clone());
            }
        }
        Ok(result)
    }

    /// Restricts the loaded packs to the named ones (see `--pack`).
    pub fn select_packs(&mut self, wanted: &[String]) {
        self.packs.select_packs(wanted);
    }

    pub fn load_pack_dirs(&mut self, dirs: &[PathBuf]) -> Result<(), ScanError> {
        self.packs.load_dirs(dirs).map_err(ScanError::Pack)
    }

    /// Whether the scanner carries any loaded rules at all.
    pub fn has_rules(&self) -> bool {
        self.packs.count() > 0
    }

    /// Phase 1a: hashes the file and checks the findings cache. Cache hits
    /// (unchanged files) return without reading or parsing the source; cache
    /// misses are read and parsed immediately. The hash is kept so the graph
    /// snapshot can be matched/rebuilt without a second read. Files with an
    /// unsupported language are skipped without reading their content (a
    /// binary file must never surface a read error or degrade the scan).
    fn prepare_one(
        parsers: &ParserRegistry,
        cache: &Option<cache::Cache>,
        path: &Path,
    ) -> ParsedFile {
        let mut file = ParsedFile {
            path: path.to_path_buf(),
            language: Language::Unknown,
            source: None,
            tree: None,
            cached_findings: Vec::new(),
            cache_hit: false,
            skipped: false,
            source_hash: None,
            issues: Vec::new(),
        };

        // Resource guard: gigantic single files can exhaust memory during
        // regex/AST analysis. Skip them explicitly (observable, never silent).
        const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
        if let Ok(metadata) = fs::metadata(path) {
            if metadata.len() > MAX_SOURCE_BYTES {
                file.issues.push((
                    FileIssueKind::Read,
                    format!(
                        "file exceeds {} byte(s) limit ({} bytes); skipped for safety",
                        MAX_SOURCE_BYTES,
                        metadata.len()
                    ),
                ));
                return file;
            }
        }

        let language = Language::from_path(path);
        file.language = language;
        if parsers.parser_for(language).is_none() {
            // Unsupported extension: skipped, but hashed so the graph snapshot
            // can still be matched (identity is per file, not per language).
            if cache.is_some() {
                file.source_hash = cache::source_hash_of_file(path).ok();
            }
            file.skipped = true;
            return file;
        }

        // Cache fast path: unchanged files reuse previous findings.
        if let Some(cache) = cache {
            if let Ok(hash) = cache::source_hash_of_file(path) {
                file.source_hash = Some(hash.clone());
                if let Some(cached) = cache.get(path, &hash) {
                    file.cached_findings = cached;
                    file.cache_hit = true;
                    return file;
                }
            }
        }

        Scanner::parse_tree_into(parsers, &mut file);
        file
    }

    /// Phase 1b: parses a prepared file whose source is not loaded yet (cache
    /// hits that the graph needs, when the snapshot does not match).
    fn parse_tree(parsers: &ParserRegistry, file: &mut ParsedFile) {
        Scanner::parse_tree_into(parsers, file);
    }

    fn parse_tree_into(parsers: &ParserRegistry, file: &mut ParsedFile) {
        let source = match fs::read_to_string(&file.path) {
            Ok(source) => source,
            Err(source) => {
                file.issues.push((FileIssueKind::Read, source.to_string()));
                return;
            }
        };
        let language = Language::from_path(&file.path);
        let Some(parser) = parsers.parser_for(language) else {
            file.skipped = true;
            return;
        };
        let tree = match parser.parse(&source) {
            Ok(tree) => tree,
            Err(source) => {
                file.issues.push((FileIssueKind::Parse, source.to_string()));
                return;
            }
        };
        file.language = language;
        file.source = Some(source);
        file.tree = Some(tree);
    }

    /// Phase 3: runs the loaded rules against one parsed file. Cached files
    /// replay their stored findings; everything else is analyzed with the
    /// project-wide code graph for cross-file taint resolution.
    fn scan_parsed(
        packs: &PackRegistry,
        graph: &crate::code_graph::CodeGraph,
        cache: &Option<cache::Cache>,
        file: &ParsedFile,
    ) -> ScanResult {
        let mut result = ScanResult::new(1);

        if file.cache_hit {
            result.scanned_files = 1;
            for finding in &file.cached_findings {
                result.findings.push(finding.clone());
            }
            return result;
        }
        if file.skipped {
            result.skipped_files += 1;
            return result;
        }
        for (kind, message) in &file.issues {
            result.push_issue(kind.clone(), file.path.clone(), message.clone());
        }
        let (Some(tree), Some(source)) = (&file.tree, &file.source) else {
            return result;
        };

        result.scanned_files = 1;
        if tree.has_error() {
            // Analysis of a partially-parsed tree is incomplete; run rules anyway
            // but surface the issue so a degraded result can never look likea clean one.
            result.push_issue(
                FileIssueKind::Parse,
                file.path.clone(),
                "syntax tree contains errors; analysis is incomplete".to_string(),
            );
        }

        let scanned: Vec<_> = {
            let mut findings = Vec::new();
            for rule in packs.iter() {
                if rule.languages().contains(&file.language) {
                    findings.extend(rule.check_parsed_with_graph(
                        tree,
                        source,
                        &file.path,
                        Some(graph),
                    ));
                }
            }
            findings
        };
        for finding in &scanned {
            result.findings.push(finding.clone());
        }

        if let Some(cache) = cache {
            // Reuse the phase-1 hash; if the file changed mid-scan the entry
            // simply misses on the next scan and is re-analyzed.
            if let Some(hash) = file.source_hash.clone() {
                let mut findings = Findings::new();
                for f in scanned {
                    findings.push(f);
                }
                let _ = cache.put(&file.path, &hash, &findings);
            }
        }
        result
    }
}

/// A file carried between the parse phase and the rule-execution phase.
struct ParsedFile {
    path: PathBuf,
    language: Language,
    source: Option<String>,
    tree: Option<crate::parser::SyntaxTree>,
    cached_findings: Vec<crate::finding::Finding>,
    cache_hit: bool,
    skipped: bool,
    /// Content hash computed in phase 1; drives both the findings cache and
    /// the graph-snapshot match.
    source_hash: Option<String>,
    issues: Vec<(FileIssueKind, String)>,
}

impl ParsedFile {
    /// The parsed content as an indexable unit for the code graph, when the
    /// file parsed successfully.
    fn indexed(&self) -> Option<crate::code_graph::IndexedFile> {
        Some(crate::code_graph::IndexedFile {
            path: self.path.clone(),
            language: self.language,
            tree: self.tree.clone()?,
            source: self.source.clone()?,
        })
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
    pub scanned_files: usize,
    pub skipped_files: usize,
    pub issues: Vec<FileIssue>,
    pub findings: Findings,
    pub rule_count: usize,
    pub pack_names: Vec<String>,
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
    Pack(PackError),
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
            Self::Pack(error) => write!(f, "rule pack error: {error}"),
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

        let result = Scanner::built_in()
            .unwrap()
            .scan_paths(&[path.as_path()])
            .unwrap();

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

        let result = Scanner::built_in()
            .unwrap()
            .scan_paths(&[path.as_path()])
            .unwrap();

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

        let result = Scanner::built_in()
            .unwrap()
            .scan_paths(&[path.as_path()])
            .unwrap();

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
            .unwrap()
            .scan_paths(&[std::path::Path::new("definitely-missing-path")])
            .unwrap_err();

        assert!(matches!(err, ScanError::Scope(_)));
    }

    #[test]
    fn unchanged_scan_restores_the_graph_snapshot() {
        let temp = TempDir::new();
        let cache_dir = temp.0.join("cache");
        let path = temp.write(
            "Example.java",
            "class Example { void run(String input) { Runtime.getRuntime().exec(input); } }",
        );
        let scanner = || Scanner::built_in().unwrap().with_cache(cache_dir.clone());

        // First scan: full build, snapshot persisted.
        let first = scanner().scan_paths(&[path.as_path()]).unwrap();
        assert_eq!(first.findings.len(), 1);
        let snapshot_files: Vec<_> = fs::read_dir(&cache_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("graph."))
            .collect();
        assert_eq!(snapshot_files.len(), 1, "snapshot must be persisted");

        // Second scan: every hash matches, so the graph is restored and the
        // findings are replayed from the per-file cache.
        let second = scanner().scan_paths(&[path.as_path()]).unwrap();
        assert_eq!(second.findings.len(), 1, "replayed findings must match");
        assert_eq!(
            second.findings.iter().next().unwrap().rule_id,
            first.findings.iter().next().unwrap().rule_id
        );

        // A content change invalidates the snapshot and re-analyzes.
        temp.write(
            "Example.java",
            "class Example { void run(String input) { String safe = \"ok\"; } }",
        );
        let third = scanner().scan_paths(&[path.as_path()]).unwrap();
        assert_eq!(
            third.findings.len(),
            0,
            "changed content must be re-analyzed against a rebuilt graph"
        );
    }

    #[test]
    fn restored_snapshot_analyzes_cache_misses_via_lazy_parse() {
        // The findings cache is cleared but the snapshot survives: files are
        // cache misses, so they are analyzed against the restored graph,
        // whose trees are re-parsed on demand (cross-file callee resolution
        // must still work and must not crash).
        let temp = TempDir::new();
        let cache_dir = temp.0.join("cache");
        let controller = temp.write(
            "Controller.java",
            r#"
class Controller {
    void handle(UserService service, java.sql.Statement st, javax.servlet.http.HttpServletRequest req) {
        service.deleteUser(req.getParameter("id"), st);
    }
}
"#,
        );
        let service = temp.write(
            "UserService.java",
            r#"
class UserService {
    void deleteUser(String userId, java.sql.Statement st) {
        st.executeQuery("DELETE FROM users WHERE id='" + userId + "'");
    }
}
"#,
        );
        let scanner = || Scanner::built_in().unwrap().with_cache(cache_dir.clone());

        let first = scanner()
            .scan_paths(&[controller.as_path(), service.as_path()])
            .unwrap();
        assert_eq!(first.findings.len(), 1, "cross-file flow detected");

        // Wipe only the per-file findings cache.
        for entry in fs::read_dir(&cache_dir).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("graph.") {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
        let second = scanner()
            .scan_paths(&[controller.as_path(), service.as_path()])
            .unwrap();
        assert_eq!(
            second.findings.len(),
            1,
            "restored graph must re-resolve cross-file callees via lazy parse"
        );
    }
}
