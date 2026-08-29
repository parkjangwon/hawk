use std::fmt::Write;

use crate::finding::{Finding, Findings};

/// Renders findings as a compact, human-readable terminal report.
#[derive(Debug, Default)]
pub struct TerminalReporter;

impl TerminalReporter {
    pub fn render(&self, findings: &Findings) -> String {
        let mut output = String::new();

        for finding in findings.iter() {
            render_finding(&mut output, finding);
        }

        render_summary(&mut output, findings);
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

fn render_summary(output: &mut String, findings: &Findings) {
    let count = findings.len();
    let noun = if count == 1 { "finding" } else { "findings" };
    let _ = writeln!(output, "{count} {noun}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Severity, SourceLocation};

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

    #[test]
    fn renders_finding_details_and_summary() {
        let mut findings = Findings::new();
        findings.push(finding(
            "java.security.runtime-exec",
            Severity::High,
            "Detects Runtime.exec calls that may execute operating-system commands.",
        ));

        let output = TerminalReporter.render(&findings);

        assert!(output.contains("HIGH Example.java:4:9"));
        assert!(output.contains("java.security.runtime-exec"));
        assert!(output.contains("Detects Runtime.exec calls"));
        assert!(output.contains("1 finding"));
    }

    #[test]
    fn empty_findings_render_only_the_summary() {
        let output = TerminalReporter.render(&Findings::new());
        assert_eq!(output, "0 findings\n");
    }

    #[test]
    fn summary_uses_plural_for_multiple_findings() {
        let mut findings = Findings::new();
        findings.push(finding("rule.a", Severity::Low, "first"));
        findings.push(finding("rule.b", Severity::Medium, "second"));

        let output = TerminalReporter.render(&findings);
        assert!(output.ends_with("2 findings\n"));
    }
}
