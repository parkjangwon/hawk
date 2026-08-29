//! Semgrep-style rule fixture testing (fixtures carry inline annotations).
//!
//! Inspired by Semgrep's `--test`: fixture files annotate expected findings
//! with comments, so the test suite doubles as documentation and regression
//! protection without a separate expectations file.
//!
//! Syntax (language-agnostic comment text):
//!   `ruleid: <rule-id>` on the line above an offending line → a finding MUST
//!       be reported at that line (false-negative guard).
//!   `ok: <rule-id>` on the line above a safe line → NO finding may be
//!       reported there (false-positive guard).
//!
//! The annotation is matched against finding start-lines L and L+1 (like
//! Semgrep, which tolerates comment-above-code placement). Unknown rule ids in
//! annotations are reported so typos surface during testing.

use crate::finding::Finding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnnotationKind {
    RuleId, // a finding is expected
    Ok,     // no finding may appear
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Annotation {
    pub kind: AnnotationKind,
    pub rule_id: String,
    pub line: usize, // 1-based line of the comment
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestVerdict {
    Pass,
    /// Expected finding that was not reported.
    Expected {
        rule_id: String,
        line: usize,
    },
    /// Reported finding that annotation said must not exist.
    Unexpected {
        rule_id: String,
        line: usize,
    },
    /// Fixture references a rule id not run.
    UnknownRule {
        rule_id: String,
    },
}

/// Extracts annotations from fixture source text.
pub fn parse_annotations(source: &str) -> Vec<Annotation> {
    let mut annotations = Vec::new();
    for (idx, raw_line) in source.lines().enumerate() {
        let line = idx + 1;
        for (marker, kind) in [
            ("ruleid:", AnnotationKind::RuleId),
            ("ok:", AnnotationKind::Ok),
        ] {
            if let Some(pos) = raw_line.find(marker) {
                let after = raw_line[pos + marker.len()..].trim();
                let rule_id = after
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                if !rule_id.is_empty() {
                    annotations.push(Annotation {
                        kind,
                        rule_id,
                        line,
                    });
                }
            }
        }
    }
    annotations
}

/// Checks `findings` against the fixture annotations. Returns the failing
/// verdicts in annotation order (empty = pass). `known_rule` is used to flag
/// annotations referencing rules the fixture cannot match.
pub fn evaluate(
    annotations: &[Annotation],
    findings: &[Finding],
    known_rule: impl Fn(&str) -> bool,
) -> Vec<TestVerdict> {
    let mut verdicts = Vec::new();
    for ann in annotations {
        let relevant: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.rule_id == ann.rule_id
                    && (f.location.start_line == ann.line || f.location.start_line == ann.line + 1)
            })
            .collect();
        match ann.kind {
            AnnotationKind::RuleId => {
                if relevant.is_empty() {
                    verdicts.push(TestVerdict::Expected {
                        rule_id: ann.rule_id.clone(),
                        line: ann.line,
                    });
                }
            }
            AnnotationKind::Ok => {
                for f in relevant {
                    verdicts.push(TestVerdict::Unexpected {
                        rule_id: ann.rule_id.clone(),
                        line: f.location.start_line,
                    });
                }
            }
        }
        if !known_rule(&ann.rule_id) {
            verdicts.push(TestVerdict::UnknownRule {
                rule_id: ann.rule_id.clone(),
            });
        }
    }
    verdicts
}

/// Compact summary of a fixture run (dash-line per verdict, for CLI output).
pub fn verdict_line(verdict: &TestVerdict) -> String {
    match verdict {
        TestVerdict::Pass => "pass".to_string(),
        TestVerdict::Expected { rule_id, line } => {
            format!("- expected finding '{rule_id}' at line {line} but none reported")
        }
        TestVerdict::Unexpected { rule_id, line } => {
            format!("+ unexpected finding '{rule_id}' at line {line} (annotated ok)")
        }
        TestVerdict::UnknownRule { rule_id } => {
            format!("? annotation references unknown rule '{rule_id}'")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Severity, SourceLocation};

    fn finding_at(rule_id: &str, line: usize) -> Finding {
        Finding::new(
            rule_id,
            Severity::High,
            "m",
            SourceLocation {
                path: "f.java".into(),
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
    fn parses_ruleid_and_ok_annotations() {
        let src = "// ruleid: rule.a\nx = 1;\n// ok: rule.b\ny = 2;\n";
        let annotations = parse_annotations(src);
        assert_eq!(annotations.len(), 2);
        assert_eq!(annotations[0].kind, AnnotationKind::RuleId);
        assert_eq!(annotations[0].rule_id, "rule.a");
        assert_eq!(annotations[1].kind, AnnotationKind::Ok);
        assert_eq!(annotations[1].rule_id, "rule.b");
    }

    #[test]
    fn ruleid_expectation_fails_when_missing() {
        let annotations = parse_annotations("// ruleid: rule.a\nbad();\n");
        let verdicts = evaluate(&annotations, &[], |_| true);
        assert!(matches!(verdicts[0], TestVerdict::Expected { line: 1, .. }));
    }

    #[test]
    fn ruleid_satisfied_by_finding_on_next_line() {
        let annotations = parse_annotations("// ruleid: rule.a\nbad();\n");
        let findings = vec![finding_at("rule.a", 2)];
        let verdicts = evaluate(&annotations, &findings, |_| true);
        assert!(verdicts.is_empty());
    }

    #[test]
    fn ok_guards_against_false_positives() {
        let annotations = parse_annotations("// ok: rule.a\ngood();\n");
        let findings = vec![finding_at("rule.a", 2)];
        let verdicts = evaluate(&annotations, &findings, |_| true);
        assert!(matches!(verdicts[0], TestVerdict::Unexpected { .. }));
    }

    #[test]
    fn unknown_rule_annotations_are_surfaced() {
        let annotations = parse_annotations("// ruleid: nope\nx();\n");
        let verdicts = evaluate(&annotations, &[], |id| id != "nope");
        assert!(verdicts
            .iter()
            .any(|v| matches!(v, TestVerdict::UnknownRule { .. })));
    }
}
