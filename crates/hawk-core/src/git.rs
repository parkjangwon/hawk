//! Git-aware scanning helpers (Phase 5).
//!
//! `--changed` and `--staged` let Hawk scan exactly the files a developer just
//! touched, which keeps everyday scans fast without a database. Git is invoked
//! as a subprocess (`git diff ... --name-only -z`) because Hawk must not assume
//! libgit2; the tool stays a single lean binary. When git is unavailable,
//! commands fail explicitly rather than silently scanning nothing.

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitError {
    Unavailable(String),
    NonZero(String),
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(message) => write!(f, "git unavailable: {message}"),
            Self::NonZero(message) => write!(f, "git failed: {message}"),
        }
    }
}

impl std::error::Error for GitError {}

/// Scope of a git-aware scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitScope {
    /// Working-tree changes vs the index (unstaged).
    Changed,
    /// Changes already staged for commit.
    Staged,
}

/// Runs `git diff [--cached] --name-only -z` in `dir` and returns changed paths
/// joined to `dir`. Names are NUL-delimited, so paths with newlines are handled.
pub fn changed_files(dir: &Path, scope: GitScope) -> Result<Vec<PathBuf>, GitError> {
    let mut command = Command::new("git");
    command.arg("diff");
    if scope == GitScope::Staged {
        command.arg("--cached");
    }
    command.args(["--name-only", "-z"]);

    let output = command
        .current_dir(dir)
        .output()
        .map_err(|error| GitError::Unavailable(error.to_string()))?;
    if !output.status.success() {
        return Err(GitError::NonZero(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    let mut paths = Vec::new();
    let mut rest = output.stdout.as_slice();
    while !rest.is_empty() {
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        if end > 0 {
            let name = String::from_utf8_lossy(&rest[..end]).to_string();
            paths.push(dir.join(name));
        }
        if end == rest.len() {
            break;
        }
        rest = &rest[end + 1..];
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn git_repo() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hawk-git-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        let status = Command::new("git")
            .args(["init", "-q"])
            .current_dir(&dir)
            .status()
            .expect("git should be available in test env");
        assert!(status.success(), "git init failed");
        for (key, value) in [("user.email", "t@t"), ("user.name", "t")] {
            Command::new("git")
                .args(["config", key, value])
                .current_dir(&dir)
                .status()
                .unwrap();
        }
        dir
    }

    #[test]
    fn changed_files_reports_working_tree_changes() {
        let dir = git_repo();
        fs::write(dir.join("A.java"), "class A {}\n").unwrap();
        Command::new("git")
            .arg("add")
            .arg("A.java")
            .current_dir(&dir)
            .status()
            .unwrap();
        Command::new("git")
            .arg("commit")
            .args(["-q", "-m", "init"])
            .current_dir(&dir)
            .status()
            .unwrap();
        fs::write(dir.join("A.java"), "class A { int x; }\n").unwrap();

        let paths = changed_files(&dir, GitScope::Changed).expect("git should run");

        assert!(
            paths.iter().any(|p| p.ends_with("A.java")),
            "expected A.java in {:?}",
            paths
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn staged_changes_require_git_add() {
        let dir = git_repo();
        fs::write(dir.join("B.java"), "class B {}\n").unwrap();
        Command::new("git")
            .arg("add")
            .arg("B.java")
            .current_dir(&dir)
            .status()
            .unwrap();
        Command::new("git")
            .arg("commit")
            .args(["-q", "-m", "init"])
            .current_dir(&dir)
            .status()
            .unwrap();
        fs::write(dir.join("B.java"), "class B { int y; }\n").unwrap();

        // unstaged change should NOT appear in a staged diff
        let staged = changed_files(&dir, GitScope::Staged).unwrap();
        assert!(
            !staged.iter().any(|p| p.ends_with("B.java")),
            "unstaged file must not appear in staged diff"
        );

        Command::new("git")
            .arg("add")
            .arg("B.java")
            .current_dir(&dir)
            .status()
            .unwrap();
        let staged_after = changed_files(&dir, GitScope::Staged).unwrap();
        assert!(staged_after.iter().any(|p| p.ends_with("B.java")));

        let _ = fs::remove_dir_all(&dir);
    }
}
