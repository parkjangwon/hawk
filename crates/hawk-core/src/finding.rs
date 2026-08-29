use std::{fmt, path::PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceLocation {
    pub path: PathBuf,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub message: String,
    pub location: SourceLocation,
}

impl Finding {
    pub fn new(
        rule_id: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
        location: SourceLocation,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            severity,
            message: message.into(),
            location,
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Findings {
    findings: Vec<Finding>,
}

impl Findings {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn len(&self) -> usize {
        self.findings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn location() -> SourceLocation {
        SourceLocation {
            path: PathBuf::from("Example.java"),
            start_byte: 10,
            end_byte: 20,
            start_line: 2,
            start_column: 4,
            end_line: 2,
            end_column: 14,
        }
    }

    #[test]
    fn finding_preserves_rule_metadata_and_location() {
        let finding = Finding::new(
            "java.security.command-execution",
            Severity::High,
            "Command execution uses untrusted input.",
            location(),
        );

        assert_eq!(finding.rule_id, "java.security.command-execution");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.location.start_line, 2);
    }

    #[test]
    fn findings_preserve_insertion_order() {
        let mut findings = Findings::new();
        findings.push(Finding::new("rule.b", Severity::Low, "second", location()));
        findings.push(Finding::new("rule.a", Severity::High, "first", location()));

        let ids: Vec<_> = findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();
        assert_eq!(ids, ["rule.b", "rule.a"]);
    }

    #[test]
    fn empty_findings_are_reported_as_empty() {
        let findings = Findings::new();
        assert!(findings.is_empty());
        assert_eq!(findings.len(), 0);
    }

    #[test]
    fn severity_has_stable_display_values() {
        assert_eq!(Severity::Info.to_string(), "INFO");
        assert_eq!(Severity::Low.to_string(), "LOW");
        assert_eq!(Severity::Medium.to_string(), "MEDIUM");
        assert_eq!(Severity::High.to_string(), "HIGH");
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
    }
}
