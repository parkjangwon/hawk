//! File-based incrementality cache (Phase 5).
//!
//! The cache lives in the local data directory (`.hawk/cache/`, see ADR-0003)
//! and stores, per source file, the hash of its content together with the
//! findings emitted for it. On a later scan, unchanged files reuse the cached
//! findings instead of re-analyzing — a big win for large trees. The cache
//! key includes a "schema" string (Hawk version + rule-pack versions) so
//! results are never reused across incompatible rule sets.
//!
//! Besides per-file findings, the cache stores the project-wide architecture
//! graph as a snapshot (see `code_graph::GraphSnapshot`): when every file's
//! content hash matches the snapshot, a scan skips parsing and re-indexing
//! entirely.

use std::path::{Path, PathBuf};

use crate::code_graph::GraphSnapshot;
use crate::finding::{Finding, Findings};

/// The schema discriminator. Bump when the finding model or analysis changes
/// in a way that invalidates all cached results.
pub const CACHE_SCHEMA: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheError {
    pub message: String,
}

impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CacheError {}

/// A simple sequential hash for file identity (fast, deterministic; not used
/// for security).
pub fn hash_bytes(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(1099511628211);
    }
    let mut out = String::with_capacity(16);
    let _ = write!(out, "{h:016x}");
    out
}

/// Content-addressable entry: schema + file hash -> findings.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CacheEntry {
    pub schema: String,
    pub source_hash: String,
    pub source_path: String,
    pub findings: Vec<Finding>,
}

/// Opens a cache rooted at `base` (e.g. `.hawk/cache`). Paths within the cache
/// are content-addressed so concurrent writers never collide.
#[derive(Debug, Clone)]
pub struct Cache {
    root: PathBuf,
    namespace: String,
}

impl Cache {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            namespace: CACHE_SCHEMA.to_string(),
        }
    }

    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace.into();
        self
    }

    fn path_for(&self, cache_key: &str) -> PathBuf {
        // Two-segment shard keeps the directory flat and fast.
        self.root
            .join(&cache_key[..2])
            .join(format!("{}.cache.json", cache_key))
    }

    pub fn get(
        &self,
        scope_id: &str,
        source_path: &Path,
        source_hash: &str,
    ) -> Option<Vec<Finding>> {
        let cache_key = cache_key(&self.namespace, scope_id, source_path, source_hash);
        let path = self.path_for(&cache_key);
        let content = std::fs::read_to_string(&path).ok()?;
        let entry: CacheEntry = serde_json::from_str(&content).ok()?;
        if entry.schema != self.namespace
            || entry.source_hash != source_hash
            || entry.source_path != source_path.to_string_lossy()
        {
            return None;
        }
        Some(entry.findings)
    }

    pub fn put(
        &self,
        scope_id: &str,
        source_path: &Path,
        source_hash: &str,
        findings: &Findings,
    ) -> Result<(), CacheError> {
        let entry = CacheEntry {
            schema: self.namespace.clone(),
            source_hash: source_hash.to_string(),
            source_path: source_path.to_string_lossy().into_owned(),
            findings: findings.iter().cloned().collect(),
        };
        let cache_key = cache_key(&self.namespace, scope_id, source_path, source_hash);
        let path = self.path_for(&cache_key);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| CacheError {
                message: format!("unable to create cache dir: {e}"),
            })?;
        }
        let content = serde_json::to_string(&entry).map_err(|e| CacheError {
            message: format!("unable to serialize cache: {e}"),
        })?;
        std::fs::write(&path, content).map_err(|e| CacheError {
            message: format!("unable to write cache: {e}"),
        })
    }

    /// Path of the project-wide graph snapshot for this cache namespace.
    fn graph_snapshot_path(&self) -> PathBuf {
        self.root.join(format!(
            "graph.{}.bin",
            hash_bytes(self.namespace.as_bytes())
        ))
    }

    /// Loads the persisted architecture-graph snapshot, rejecting snapshots
    /// from an incompatible schema. Best-effort: corrupt or missing files
    /// yield `None` and the caller rebuilds.
    pub fn load_graph_snapshot(&self) -> Option<GraphSnapshot> {
        let path = self.graph_snapshot_path();
        let bytes = std::fs::read(path).ok()?;
        let snapshot: GraphSnapshot = bincode::deserialize(&bytes).ok()?;
        if snapshot.schema != self.namespace {
            return None;
        }
        Some(snapshot)
    }

    /// Persists the architecture-graph snapshot for this cache namespace.
    pub fn save_graph_snapshot(&self, mut snapshot: GraphSnapshot) -> Result<(), CacheError> {
        snapshot.schema = self.namespace.clone();
        let path = self.graph_snapshot_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| CacheError {
                message: format!("unable to create cache dir: {e}"),
            })?;
        }
        let bytes = bincode::serialize(&snapshot).map_err(|e| CacheError {
            message: format!("unable to serialize graph snapshot: {e}"),
        })?;
        std::fs::write(&path, bytes).map_err(|e| CacheError {
            message: format!("unable to write graph snapshot: {e}"),
        })
    }

    /// Removes per-file cache entries older than `max_age`. The cache used to
    /// grow without bound — every historical version of every edited file
    /// left an entry behind. Best-effort pruning keyed on the entry's write
    /// time; a pruned hot entry simply costs one re-analysis. Returns how
    /// many entries were removed.
    pub fn prune_older_than(&self, max_age: std::time::Duration) -> usize {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|now| now.saturating_sub(max_age))
            .unwrap_or_default();
        let mut removed = 0usize;
        let Ok(shards) = std::fs::read_dir(&self.root) else {
            return 0;
        };
        for shard in shards.flatten() {
            if !shard.path().is_dir() {
                continue;
            }
            let Ok(entries) = std::fs::read_dir(shard.path()) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let is_entry = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".cache.json"));
                if !is_entry {
                    continue;
                }
                let stale = entry
                    .metadata()
                    .and_then(|meta| meta.modified())
                    .ok()
                    .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
                    .is_some_and(|age| age < cutoff);
                if stale && std::fs::remove_file(&path).is_ok() {
                    removed += 1;
                }
            }
        }
        removed
    }
}

/// The cache key binds to (schema, scope, file, content). `scope_id` is the
/// hash of the whole scanned file set: cross-file analysis makes a file's
/// findings depend on other files, so a cached result must never be replayed
/// against a different or changed scope.
fn cache_key(namespace: &str, scope_id: &str, path: &Path, source_hash: &str) -> String {
    hash_bytes(
        format!(
            "{}\\0{}\\0{}\\0{}",
            namespace,
            scope_id,
            path.to_string_lossy(),
            source_hash
        )
        .as_bytes(),
    )
}

pub fn source_hash_of_file(path: &Path) -> Result<String, CacheError> {
    let content = std::fs::read(path).map_err(|e| CacheError {
        message: format!("unable to read '{}': {e}", path.display()),
    })?;
    Ok(hash_bytes(&content))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Severity, SourceLocation};
    use std::time::{SystemTime, UNIX_EPOCH};

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn temp_root() -> PathBuf {
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "hawk-cache-test-{}-{}-{seq}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn sample_finding() -> Finding {
        Finding::new(
            "rule.a",
            Severity::High,
            "msg",
            SourceLocation {
                path: "A.java".into(),
                start_byte: 0,
                end_byte: 4,
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 5,
            },
        )
    }

    #[test]
    fn cache_round_trips_findings_for_same_hash() {
        let root = temp_root();
        let cache = Cache::new(root.clone());
        let mut findings = Findings::new();
        findings.push(sample_finding());
        let h = hash_bytes(b"class A {}");

        let path = Path::new("A.java");
        cache
            .put("scope", path, &h, &findings)
            .expect("put should succeed");
        let got = cache
            .get("scope", path, &h)
            .expect("same hash should hit cache");

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].rule_id, "rule.a");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn identical_content_at_different_paths_has_separate_entries() {
        let root = temp_root();
        let cache = Cache::new(root.clone());
        let mut findings = Findings::new();
        findings.push(sample_finding());
        let hash = hash_bytes(b"same source");

        cache
            .put("scope", Path::new("A.java"), &hash, &findings)
            .expect("first put should succeed");
        assert!(cache.get("scope", Path::new("A.java"), &hash).is_some());
        assert!(cache.get("scope", Path::new("B.java"), &hash).is_none());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn different_hash_misses() {
        let root = temp_root();
        let cache = Cache::new(root.clone());
        let mut findings = Findings::new();
        findings.push(sample_finding());
        let path = Path::new("A.java");
        cache
            .put("scope", path, &hash_bytes(b"old"), &findings)
            .expect("put should succeed");

        assert!(cache.get("scope", path, &hash_bytes(b"new")).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn hash_is_stable_and_content_sensitive() {
        assert_eq!(hash_bytes(b"abc"), hash_bytes(b"abc"));
        assert_ne!(hash_bytes(b"abc"), hash_bytes(b"abd"));
    }
    #[test]
    fn prune_removes_only_stale_entries() {
        use std::time::Duration;
        let root = temp_root();
        let cache = Cache::new(root.clone());
        let mut findings = Findings::new();
        findings.push(sample_finding());
        let path = Path::new("A.java");

        cache
            .put("scope", path, &hash_bytes(b"v1"), &findings)
            .unwrap();
        // Zero max-age prunes everything that has a modification time in the
        // past; the entry just written qualifies.
        assert_eq!(cache.prune_older_than(Duration::ZERO), 1);
        assert!(cache.get("scope", path, &hash_bytes(b"v1")).is_none());

        // A generous max-age keeps fresh entries.
        cache
            .put("scope", path, &hash_bytes(b"v2"), &findings)
            .unwrap();
        assert_eq!(cache.prune_older_than(Duration::from_secs(3600)), 0);
        assert!(cache.get("scope", path, &hash_bytes(b"v2")).is_some());

        let _ = std::fs::remove_dir_all(&root);
    }
    #[test]
    fn a_different_scope_never_hits() {
        // Regression: cross-file analysis makes a file's findings depend on
        // the whole scanned file set. The cache used to key on (path, hash)
        // only, so cached "no findings" from a single-file scan was replayed
        // when the same file was scanned together with its callee.
        let root = temp_root();
        let cache = Cache::new(root.clone());
        let path = Path::new("A.java");
        let h = hash_bytes(b"class A {}");

        cache.put("scope:one", path, &h, &Findings::new()).unwrap();
        assert!(cache.get("scope:one", path, &h).is_some());
        assert!(cache.get("scope:two", path, &h).is_none());

        let _ = std::fs::remove_dir_all(root);
    }
}
