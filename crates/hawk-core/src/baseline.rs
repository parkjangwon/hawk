//! File-based baseline (Phase 6, ROADMAP).
//!
//! A baseline records the fingerprints of known findings. On a later scan,
//! findings whose fingerprints are in the baseline are "existing" and can be
//! suppressed; new fingerprints become "new". When a baseline fingerprint no
//! longer appears, the finding is considered fixed (helpful for regression
//! tracking). The baseline is stored as JSON in the local data directory
//! (`.hawk/baseline.json`, see ADR-0003).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::finding::Finding;

#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Baseline {
    pub fingerprints: Vec<String>,
}

impl Baseline {
    pub fn load(path: &Path) -> Result<Self, BaselineError> {
        let content = std::fs::read_to_string(path).map_err(|e| BaselineError::Read {
            path: path.to_path_buf(),
            source: e.to_string(),
        })?;
        let baseline: Baseline =
            serde_json::from_str(&content).map_err(|e| BaselineError::Parse {
                path: path.to_path_buf(),
                source: e.to_string(),
            })?;
        Ok(baseline)
    }

    pub fn save(&self, path: &Path) -> Result<(), BaselineError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| BaselineError::Write {
                path: parent.to_path_buf(),
                source: e.to_string(),
            })?;
        }
        let content = serde_json::to_string_pretty(self).map_err(|e| BaselineError::Write {
            path: path.to_path_buf(),
            source: e.to_string(),
        })?;
        std::fs::write(path, content).map_err(|e| BaselineError::Write {
            path: path.to_path_buf(),
            source: e.to_string(),
        })
    }

    pub fn contains(&self, fingerprint: &str) -> bool {
        self.fingerprints.iter().any(|f| f == fingerprint)
    }

    pub fn set_of(&self) -> HashSet<&str> {
        self.fingerprints.iter().map(String::as_str).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineError {
    Read { path: PathBuf, source: String },
    Parse { path: PathBuf, source: String },
    Write { path: PathBuf, source: String },
}

impl std::fmt::Display for BaselineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "unable to read baseline '{}': {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(f, "unable to parse baseline '{}': {source}", path.display())
            }
            Self::Write { path, source } => {
                write!(f, "unable to write baseline '{}': {source}", path.display())
            }
        }
    }
}

impl std::error::Error for BaselineError {}

/// Classifies scan findings against a baseline.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BaselineStatus {
    /// Fingerprints present in the baseline but not found in this scan (fixed).
    pub fixed: Vec<String>,
    /// Findings in this scan that are not in the baseline.
    pub new: Vec<Finding>,
    /// Findings in this scan whose fingerprints are in the baseline (existing).
    pub existing: Vec<Finding>,
}

/// Returns the baseline path for a project root (`.hawk/baseline.json`).
pub fn baseline_path(root: &Path) -> PathBuf {
    root.join(".hawk").join("baseline.json")
}

/// Classifies the findings of a run against `baseline`.
pub fn classify(baseline: &Baseline, findings: &[Finding]) -> BaselineStatus {
    let known: HashSet<&str> = baseline.set_of();
    let mut status = BaselineStatus::default();
    for finding in findings {
        if known.contains(finding.fingerprint.as_str()) {
            status.existing.push(finding.clone());
        } else {
            status.new.push(finding.clone());
        }
    }
    let present: HashSet<&str> = findings.iter().map(|f| f.fingerprint.as_str()).collect();
    for fp in known {
        if !present.contains(fp) {
            status.fixed.push(fp.to_string());
        }
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Severity, SourceLocation};

    fn finding(rule_id: &str, line: usize) -> Finding {
        Finding::new(
            rule_id,
            Severity::High,
            "msg",
            SourceLocation {
                path: "A.java".into(),
                start_byte: 0,
                end_byte: 1,
                start_line: line,
                start_column: 1,
                end_line: line,
                end_column: 2,
            },
        )
    }

    #[test]
    fn classify_marks_new_existing_and_fixed() {
        let baseline = Baseline {
            fingerprints: vec![
                finding("rule.a", 1).fingerprint.clone(),
                "ghost".to_string(),
            ],
        };
        let findings = vec![
            finding("rule.a", 1), // existing
            finding("rule.b", 2), // new
        ];

        let status = classify(&baseline, &findings);

        assert_eq!(status.existing.len(), 1);
        assert_eq!(status.existing[0].rule_id, "rule.a");
        assert_eq!(status.new.len(), 1);
        assert_eq!(status.new[0].rule_id, "rule.b");
        assert_eq!(status.fixed, vec!["ghost".to_string()]);
    }

    #[test]
    fn baseline_round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!(
            "hawk-baseline-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("baseline.json");
        let baseline = Baseline {
            fingerprints: vec!["abc".to_string()],
        };
        baseline.save(&path).expect("save should work");
        let loaded = Baseline::load(&path).expect("load should work");
        assert_eq!(loaded, baseline);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
