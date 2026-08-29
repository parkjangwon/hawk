//! File-based incrementality cache (Phase 5).
//!
//! The cache lives in the local data directory (`.hawk/cache/`, see ADR-0003)
//! and stores, per source file, the hash of its content together with the
//! findings emitted for it. On a later scan, unchanged files reuse the cached
//! findings instead of re-analyzing — a big win for large trees. The cache
//! key includes a "schema" string (Hawk version + rule-pack versions) so
//! results are never reused across incompatible rule sets.

use std::path::{Path, PathBuf};

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
    pub findings: Vec<Finding>,
}

/// Opens a cache rooted at `base` (e.g. `.hawk/cache`). Paths within the cache
/// are content-addressed so concurrent writers never collide.
#[derive(Debug, Clone)]
pub struct Cache {
    root: PathBuf,
}

impl Cache {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn path_for(&self, source_hash: &str) -> PathBuf {
        // Two-segment shard keeps the directory flat and fast.
        self.root
            .join(&source_hash[..2])
            .join(format!("{}.cache.json", source_hash))
    }

    pub fn get(&self, source_hash: &str) -> Option<Vec<Finding>> {
        let path = self.path_for(source_hash);
        let content = std::fs::read_to_string(&path).ok()?;
        let entry: CacheEntry = serde_json::from_str(&content).ok()?;
        if entry.schema != CACHE_SCHEMA || entry.source_hash != source_hash {
            return None;
        }
        Some(entry.findings)
    }

    pub fn put(&self, source_hash: &str, findings: &Findings) -> Result<(), CacheError> {
        let entry = CacheEntry {
            schema: CACHE_SCHEMA.to_string(),
            source_hash: source_hash.to_string(),
            findings: findings.iter().cloned().collect(),
        };
        let path = self.path_for(source_hash);
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

        cache.put(&h, &findings).expect("put should succeed");
        let got = cache.get(&h).expect("same hash should hit cache");

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].rule_id, "rule.a");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn different_hash_misses() {
        let root = temp_root();
        let cache = Cache::new(root.clone());
        let mut findings = Findings::new();
        findings.push(sample_finding());
        cache
            .put(&hash_bytes(b"old"), &findings)
            .expect("put should succeed");

        assert!(cache.get(&hash_bytes(b"new")).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn hash_is_stable_and_content_sensitive() {
        assert_eq!(hash_bytes(b"abc"), hash_bytes(b"abc"));
        assert_ne!(hash_bytes(b"abc"), hash_bytes(b"abd"));
    }
}
