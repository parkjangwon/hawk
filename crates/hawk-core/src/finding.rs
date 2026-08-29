use std::{fmt, path::PathBuf};

use crate::language::Language;

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

/// How certain the analyzer is that the reported issue endangers the programby default.
/// Orthogonal to severity: severity describes impact, confidence describes certainty..
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Confidence {
    Low,
    #[default]
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
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

/// A normalized security finding.. See ADR-1002 for the field contract and the fingerprint
/// algorithm..
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    pub description: Option<String>,
    pub recommendation: Option<String>,
    pub category: Option<String>,
    pub language: Option<Language>,
    pub framework: Option<String>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub code_snippet: Option<String>,
    pub fingerprint: String,
    pub location: SourceLocation,
}

impl Finding {
    /// Creates a finding from the minimal attributes; richer fields default per ADR-1002
    /// and its fingerprint is computed immediately..
    pub fn new(
        rule_id: impl Into<String>,
        severity: Severity,
        message: impl Into<String>,
        location: SourceLocation,
    ) -> Self {
        let rule_id = rule_id.into();
        let message = message.into();
        let fingerprint = fingerprint_of(&rule_id, &location);
        Self {
            rule_name: rule_id.clone(),
            confidence: Confidence::default(),
            description: None,
            recommendation: None,
            category: None,
            language: None,
            framework: None,
            cwe: None,
            owasp: None,
            code_snippet: None,
            fingerprint,
            severity,
            message,
            location,
            rule_id,
        }
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_rule_name(mut self, rule_name: impl Into<String>) -> Self {
        self.rule_name = rule_name.into();
        self
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_recommendation(mut self, recommendation: impl Into<String>) -> Self {
        self.recommendation = Some(recommendation.into());
        self
    }

    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    pub fn with_language(mut self, language: Language) -> Self {
        self.language = Some(language);
        self
    }

    pub fn with_framework(mut self, framework: impl Into<String>) -> Self {
        self.framework = Some(framework.into());
        self
    }

    pub fn with_cwe(mut self, cwe: impl Into<String>) -> Self {
        self.cwe = Some(cwe.into());
        self
    }

    pub fn with_owasp(mut self, owasp: impl Into<String>) -> Self {
        self.owasp = Some(owasp.into());
        self
    }

    pub fn with_code_snippet(mut self, snippet: impl Into<String>) -> Self {
        self.code_snippet = Some(snippet.into());
        self
    }
}

/// FNV-1a 64-bit fingerprint over `rule_id\0path\0line\0column`,lowercase-hex..
/// Stable per ADR-1002: no crypto, deterministic, sensitive to exactly the identifying attributes..
fn fingerprint_of(rule_id: &str, location: &SourceLocation) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in rule_id
        .bytes()
        .chain([0])
        .chain(location.path.to_string_lossy().bytes())
        .chain([0])
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(1099511628211);
    }
    // Line/column always cross the file-bounds check; serialize with a unit separator to
    // prefix-collision-proof the numeric fields..
    for value in [location.start_line as u64, location.start_column as u64] {
        hash ^= 31; // unit separator
        hash = hash.wrapping_mul(1099511628211);
        for byte in value.to_string().bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(1099511628211);
        }
    }
    format!("{hash:016x}")
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

    pub fn extend(&mut self, findings: Findings) {
        self.findings.extend(findings.findings);
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
            "Command execution uses untrusted input();",
            location(),
        );

        assert_eq!(finding.rule_id, "java.security.command-execution");
        assert_eq!(finding.rule_name, "java.security.command-execution");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.location.start_line, 2);
    }

    #[test]
    fn finding_defaults_are_sane() {
        let finding = Finding::new("rule.a", Severity::Medium, "msg", location());

        assert_eq!(finding.confidence, Confidence::Medium);
        assert_eq!(finding.language, None);
        assert_eq!(finding.framework, None);
        assert_eq!(finding.cwe, None);
        assert_eq!(finding.owasp, None);
        assert!(finding.description.is_none());
        assert!(finding.recommendation.is_none());
    }

    #[test]
    fn builder_methods_enrich_a_finding() {
        let finding = Finding::new("rule.a", Severity::High, "msg", location())
            .with_confidence(Confidence::High)
            .with_rule_name("Rule A")
            .with_description("why it matters")
            .with_recommendation("how to fix it")
            .with_category("command-injection")
            .with_language(Language::Java)
            .with_framework("Spring")
            .with_cwe("CWE-78")
            .with_owasp("A03:2021")
            .with_code_snippet("Runtime.getRuntime().exec(input();");

        assert_eq!(finding.confidence, Confidence::High);
        assert_eq!(finding.rule_name, "Rule A");
        assert_eq!(finding.description.as_deref(), Some("why it matters"));
        assert_eq!(finding.recommendation.as_deref(), Some("how to fix it"));
        assert_eq!(finding.category.as_deref(), Some("command-injection"));
        assert_eq!(finding.language, Some(Language::Java));
        assert_eq!(finding.framework.as_deref(), Some("Spring"));
        assert_eq!(finding.cwe.as_deref(), Some("CWE-78"));
        assert_eq!(finding.owasp.as_deref(), Some("A03:2021"));
        assert_eq!(
            finding.code_snippet.as_deref(),
            Some("Runtime.getRuntime().exec(input();")
        );
    }

    #[test]
    fn fingerprint_is_stable_and_sensitive_to_location() {
        let base = Finding::new("rule.a", Severity::High, "msg", location());
        let same = Finding::new("rule.a", Severity::High, "msg", location());

        assert_eq!(base.fingerprint, same.fingerprint);

        let mut loc = location();
        loc.start_line += 1;
        let moved = Finding::new("rule.a", Severity::High, "msg", loc);
        assert_ne!(base.fingerprint, moved.fingerprint);

        let other_rule = Finding::new("rule.b", Severity::High, "msg", location());
        assert_ne!(base.fingerprint, other_rule.fingerprint);

        let other_path = Finding::new(
            "rule.a",
            Severity::High,
            "msg",
            SourceLocation {
                path: PathBuf::from("Other.java"),
                ..location()
            },
        );
        assert_ne!(base.fingerprint, other_path.fingerprint);
    }

    #[test]
    fn fingerprint_is_a_lowercase_16_char_hex_string() {
        let finding = Finding::new("rule.a", Severity::Low, "msg", location());

        assert!(finding.fingerprint.bytes().all(|b| b.is_ascii_hexdigit()));
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
    }

    #[test]
    fn severity_has_stable_display_values() {
        assert_eq!(Severity::Info.to_string(), "INFO");
        assert_eq!(Severity::Low.to_string(), "LOW");
        assert_eq!(Severity::Medium.to_string(), "MEDIUM");
        assert_eq!(Severity::High.to_string(), "HIGH");
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn confidence_has_stable_display_and_ordering() {
        assert_eq!(Confidence::Low.to_string(), "LOW");
        assert_eq!(Confidence::Medium.to_string(), "MEDIUM");
        assert!(Confidence::Low < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::High);
        assert!(Confidence::Medium < Confidence::High);
    }
}
