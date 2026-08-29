use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use hawk_core::scope::{resolve, ScanTarget, ScopeError};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after UNIX_EPOCH")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hawk-scope-test-{}-{suffix}-{seq}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("temporary directory should be created");
        Self { path }
    }

    fn create_file(&self, name: &str) -> std::path::PathBuf {
        let path = self.path.join(name);
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
fn no_arguments_scan_current_directory() {
    let targets = resolve(&[]).expect("current directory should be a valid scope");

    assert_eq!(targets.len(), 1);
    assert!(matches!(targets[0], ScanTarget::Directory(_)));
    assert_eq!(targets[0].path(), Path::new("."));
}

#[test]
fn directory_argument_resolves_to_directory_target() {
    let temp = TempDir::new();

    let targets = resolve(&[temp.path.as_path()]).expect("directory should resolve");

    assert_eq!(targets, vec![ScanTarget::Directory(temp.path.clone())]);
}

#[test]
fn file_argument_resolves_to_file_target() {
    let temp = TempDir::new();
    let file = temp.create_file("Example.java");

    let targets = resolve(&[file.as_path()]).expect("file should resolve");

    assert_eq!(targets, vec![ScanTarget::File(file)]);
}

#[test]
fn multiple_arguments_are_preserved_in_order() {
    let temp = TempDir::new();
    let first = temp.create_file("First.java");
    let second = temp.create_file("Second.java");

    let targets = resolve(&[first.as_path(), second.as_path()]).expect("targets should resolve");

    assert_eq!(
        targets,
        vec![ScanTarget::File(first), ScanTarget::File(second)]
    );
}

#[test]
fn missing_path_returns_a_specific_error() {
    let temp = TempDir::new();
    let missing = temp.path.join("does-not-exist");

    let error = resolve(&[missing.as_path()]).expect_err("missing path must fail");

    assert_eq!(error, ScopeError::PathNotFound(missing));
}
