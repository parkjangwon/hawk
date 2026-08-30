use std::fmt::Write;

use crate::{
    finding::Finding,
    scan::{FileIssueKind, ScanResult},
};

/// Renders a scan result as a compact, human-readable terminal report..
#[derive(Debug, Default)]
pub struct TerminalReporter;

impl TerminalReporter {
    pub fn render(&self, result: &ScanResult) -> String {
        let mut output = String::new();

        for issue in &result.issues {
            let kind = match issue.kind {
                FileIssueKind::Read => "read error",
                FileIssueKind::Parse => "parse error",
            };
            let _ = writeln!(
                output,
                "warning: {kind} in {}: {}",
                issue.path.display(),
                issue.message
            );
        }

        for finding in result.findings.iter() {
            render_finding(&mut output, finding);
        }

        let count = result.findings.len();
        let noun = if count == 1 { "finding" } else { "findings" };
        let degraded = if result.degraded() {
            " (degraded: results are incomplete)"
        } else {
            ""
        };
        let _ = writeln!(
            output,
            "{count} {noun} in {} file(s){degraded}",
            result.discovered_files
        );
        let _ = writeln!(
            output,
            "{} file(s) skipped ({} issue(s) resolved by ignoring them",
            result.skipped_files,
            result.issues.len()
        );

        output
    }
}

fn render_finding(output: &mut String, finding: &Finding) {
    let _ = writeln!(
        output,
        "{} {}:{}:{}",
        finding.severity,
        finding.location.path.display(),
        finding.location.start_line,
        finding.location.start_column
    );
    let _ = writeln!(output, "  {}", finding.rule_id);
    let _ = writeln!(output, "  {}", finding.message);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        finding::{Findings, Severity, SourceLocation},
        scan::FileIssue,
    };

    fn finding(rule_id: &str, severity: Severity, message: &str) -> Finding {
        Finding::new(
            rule_id,
            severity,
            message,
            SourceLocation {
                path: "Example.java".into(),
                start_byte: 0,
                end_byte: 10,
                start_line: 4,
                start_column: 9,
                end_line: 4,
                end_column: 19,
            },
        )
    }

    fn result_with(issues: Vec<FileIssue>, findings: Findings) -> ScanResult {
        ScanResult {
            discovered_files: 1,
            skipped_files: 0,
            issues,
            findings,
            scanned_files: 1,
            rule_count: 0,
            pack_names: Vec::new(),
        }
    }

    #[test]
    fn renders_finding_details_and_summary() {
        let mut findings = Findings::new();
        findings.push(finding(
            "java.security.runtime-exec",
            Severity::High,
            "Detects Runtime.exec calls that may execute operating-system commands.",
        ));

        let output = TerminalReporter.render(&result_with(vec![], findings));

        assert!(output.contains("HIGH Example.java:4:9"));
        assert!(output.contains("java.security.runtime-exec"));
        assert!(output.contains("Detects Runtime.exec calls"));
        assert!(output.contains("1 finding in 1 file(s)"));
    }

    #[test]
    fn renders_issues_before_findings_and_marks_degraded_scan() {
        let mut findings = Findings::new();
        findings.push(finding("rule.a", Severity::Low, "first"));
        let issues = vec![FileIssue {
            kind: FileIssueKind::Parse,
            path: "Broken.java".into(),
            message: "syntax tree contains errors; analysis is incomplete".into(),
        }];

        let output = TerminalReporter.render(&result_with(issues, findings));

        assert!(output.starts_with("warning: parse error in Broken.java"));
        assert!(output.contains("degraded: results are incomplete"));
    }

    #[test]
    fn empty_result_render_only_the_summary() {
        let output = TerminalReporter.render(&result_with(vec![], Findings::new()));
        assert_eq!(
            output,
            "0 findings in 1 file(s)\n0 file(s) skipped (0 issue(s) resolved by ignoring them\n"
        );
    }

    #[test]
    fn summary_uses_plural_for_multiple_findings() {
        let mut findings = Findings::new();
        findings.push(finding("rule.a", Severity::Low, "first"));
        findings.push(finding("rule.b", Severity::Medium, "second"));

        let output = TerminalReporter.render(&result_with(vec![], findings));

        assert!(output.contains("2 findings in 1 file(s)\n"));
    }
}
