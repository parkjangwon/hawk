//! Structured reporters (JSON, SARIF 2.1.0, HTML) for Phase 6.
//!
//! These reporters consume a normalized `ScanResult` and produce machine- or
//! human-readable artifacts. They never perform analysis themselves.

use std::fmt::Write as _;

use crate::{
    finding::Finding,
    scan::{FileIssueKind, ScanResult},
};

// ---------------------------------------------------------------------------
// Shared view + metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReportMetadata {
    pub hawk_version: String,
    pub timestamp: String,
    pub rule_packs: Vec<String>,
    pub rule_count: usize,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub duration_ms: u128,
}

impl ReportMetadata {
    fn from_scan(result: &ScanResult, duration_ms: u128) -> Self {
        Self {
            hawk_version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: now_rfc3339(),
            rule_packs: result.pack_names.clone(),
            rule_count: result.rule_count,
            files_scanned: result.scanned_files,
            files_skipped: result.skipped_files,
            duration_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FindingView {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub confidence: String,
    pub message: String,
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub fingerprint: String,
    pub category: Option<String>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub code_snippet: Option<String>,
}

impl FindingView {
    pub fn from_finding(finding: &Finding) -> Self {
        let location = &finding.location;
        Self {
            rule_id: finding.rule_id.clone(),
            rule_name: finding.rule_name.clone(),
            severity: finding.severity.to_string(),
            confidence: finding.confidence.to_string(),
            message: finding.message.clone(),
            file: location.path.display().to_string(),
            line: location.start_line,
            column: location.start_column,
            fingerprint: finding.fingerprint.clone(),
            category: finding.category.clone(),
            cwe: finding.cwe.clone(),
            owasp: finding.owasp.clone(),
            code_snippet: finding.code_snippet.clone(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct SeveritySummary {
    pub info: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

impl SeveritySummary {
    pub fn count(&mut self, severity: &str) {
        match severity {
            "INFO" => self.info += 1,
            "LOW" => self.low += 1,
            "MEDIUM" => self.medium += 1,
            "HIGH" => self.high += 1,
            "CRITICAL" => self.critical += 1,
            _ => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IssueView {
    pub kind: String,
    pub file: String,
    pub message: String,
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct JsonReport {
    pub version: String,
    pub severity_summary: SeveritySummary,
    pub findings: Vec<FindingView>,
    pub issues: Vec<IssueView>,
    pub metadata: ReportMetadata,
}

#[derive(Debug, Default)]
pub struct JsonReporter;

impl JsonReporter {
    pub fn render(&self, result: &ScanResult, duration_ms: u128) -> String {
        let mut summary = SeveritySummary::default();
        let views: Vec<FindingView> = result
            .findings
            .iter()
            .map(|f| {
                summary.count(&f.severity.to_string());
                FindingView::from_finding(f)
            })
            .collect();
        let issues = result
            .issues
            .iter()
            .map(|issue| IssueView {
                kind: match issue.kind {
                    FileIssueKind::Read => "read".into(),
                    FileIssueKind::Parse => "parse".into(),
                },
                file: issue.path.display().to_string(),
                message: issue.message.clone(),
            })
            .collect();

        let report = JsonReport {
            version: "1.0".into(),
            severity_summary: summary,
            findings: views,
            issues,
            metadata: ReportMetadata::from_scan(result, duration_ms),
        };
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
    }
}

// ---------------------------------------------------------------------------
// SARIF 2.1.0
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct SarifReporter;

#[derive(Debug, serde::Serialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Debug, serde::Serialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResultItem>,
}

#[derive(Debug, serde::Serialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Debug, serde::Serialize)]
pub struct SarifDriver {
    pub name: String,
    pub semantic_version: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Debug, serde::Serialize)]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
}

#[derive(Debug, serde::Serialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Debug, serde::Serialize)]
pub struct SarifResultItem {
    pub rule_id: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
}

#[derive(Debug, serde::Serialize)]
pub struct SarifLocation {
    pub physical_location: SarifPhysical,
}

#[derive(Debug, serde::Serialize)]
pub struct SarifPhysical {
    pub artifact_location: SarifArtifact,
    pub region: SarifRegion,
}

#[derive(Debug, serde::Serialize)]
pub struct SarifArtifact {
    pub uri: String,
}

#[derive(Debug, serde::Serialize)]
pub struct SarifRegion {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

impl SarifReporter {
    pub fn render(&self, result: &ScanResult, _duration_ms: u128) -> String {
        let mut rules: Vec<SarifRule> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for finding in result.findings.iter() {
            if seen.insert(finding.rule_id.clone()) {
                rules.push(SarifRule {
                    id: finding.rule_id.clone(),
                    name: finding.rule_name.clone(),
                    short_description: SarifMessage {
                        text: finding.description.clone().unwrap_or_default(),
                    },
                });
            }
        }

        let results = result
            .findings
            .iter()
            .map(|f| SarifResultItem {
                rule_id: f.rule_id.clone(),
                level: sarif_level(&f.severity.to_string()),
                message: SarifMessage {
                    text: f.message.clone(),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysical {
                        artifact_location: SarifArtifact {
                            uri: f.location.path.display().to_string(),
                        },
                        region: SarifRegion {
                            start_line: f.location.start_line,
                            start_column: f.location.start_column,
                            end_line: f.location.end_line,
                            end_column: f.location.end_column,
                        },
                    },
                }],
            })
            .collect();

        let report = SarifLog {
            schema: "https://json.schemastore.org/sarif-2.1.0.json".into(),
            version: "2.1.0".into(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "hawk".into(),
                        semantic_version: env!("CARGO_PKG_VERSION").into(),
                        rules,
                    },
                },
                results,
            }],
        };
        serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
    }
}

fn sarif_level(severity: &str) -> String {
    match severity {
        "CRITICAL" | "HIGH" => "error".into(),
        "MEDIUM" => "warning".into(),
        _ => "note".into(),
    }
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct HtmlReporter;

impl HtmlReporter {
    pub fn render(&self, result: &ScanResult, duration_ms: u128) -> String {
        let mut summary = SeveritySummary::default();
        let views: Vec<FindingView> = result
            .findings
            .iter()
            .map(|f| {
                summary.count(&f.severity.to_string());
                FindingView::from_finding(f)
            })
            .collect();

        let mut body = String::new();
        for view in &views {
            let snippet = view
                .code_snippet
                .as_deref()
                .map(html_escape)
                .unwrap_or_default();
            let _ = writeln!(
                body,
                "<tr><td>{sev}</td><td><code>{rule}</code></td><td>{msg}<br><code>{snippet}</code></td><td><code>{file}:{line}:{col}</code></td><td>{name}</td></tr>",
                sev = view.severity,
                rule = view.rule_id,
                msg = html_escape(&view.message),
                snippet = snippet,
                file = html_escape(&view.file),
                line = view.line,
                col = view.column,
                name = html_escape(&view.rule_name),
            );
        }

        let mut out = String::new();
        let _ = writeln!(out, "<!DOCTYPE html>");
        let _ = writeln!(out, "<html lang='en'>");
        let _ = writeln!(out, "<head><meta charset='utf-8'>");
        let _ = writeln!(out, "<title>Hawk Security Assessment Report</title>");
        let _ = writeln!(
            out,
            "<style>body{{font-family:system-ui,sans-serif;margin:2rem}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:.5rem;text-align:left}}th{{background:#f2f2f2}}</style>"
        );
        let _ = writeln!(out, "</head><body>");
        let _ = writeln!(out, "<h1>Hawk Security Assessment Report</h1>");
        let _ = writeln!(
            out,
            "<p>Hawk {} &middot; {} file(s) scanned, {} skipped &middot; {} ms &middot; {}</p>",
            env!("CARGO_PKG_VERSION"),
            result.discovered_files,
            result.skipped_files,
            duration_ms,
            now_rfc3339(),
        );
        let _ = writeln!(out, "<h2>Summary</h2><ul>");
        for (label, value) in [
            ("Critical", summary.critical),
            ("High", summary.high),
            ("Medium", summary.medium),
            ("Low", summary.low),
            ("Info", summary.info),
        ] {
            let _ = writeln!(out, "<li>{label}: {value}</li>");
        }
        let _ = writeln!(out, "</ul>");
        let _ = writeln!(out, "<h2>Findings ({})</h2>", views.len());
        let _ = writeln!(
            out,
            "<table><thead><tr><th>Severity</th><th>Rule</th><th>Message</th><th>Location</th><th>Name</th></tr></thead><tbody>"
        );
        let _ = writeln!(out, "{}", body);
        let _ = writeln!(out, "</tbody></table><hr>");
        let _ = writeln!(
            out,
            "<p><em>Generated by Hawk &mdash; local-first static security analysis.</em></p>"
        );
        let _ = writeln!(out, "</body></html>");
        out
    }
}

/// Current UTC timestamp in RFC3339 form (`YYYY-MM-DDTHH:MM:SSZ`).
/// Implemented without a date-time dependency to keep the local binary lean.
fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_rfc3339_utc(secs)
}

fn format_rfc3339_utc(unix_seconds: u64) -> String {
    const SECS_PER_DAY: u64 = 86_400;
    let days = unix_seconds / SECS_PER_DAY;
    let day_seconds = unix_seconds % SECS_PER_DAY;
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;

    // Howard Hinnant's civil-from-days conversion (proleptic Gregorian).
    let z = days as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };

    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z",
        year = year,
        month = month,
        day = day,
        hour = hour,
        minute = minute,
        second = second,
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Findings, Severity, SourceLocation};
    use crate::scan::FileIssue;

    fn finding(rule_id: &str, severity: Severity) -> Finding {
        Finding::new(
            rule_id,
            severity,
            "message text",
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

    fn result() -> ScanResult {
        let mut findings = Findings::new();
        findings.push(finding("rule.a", Severity::High));
        ScanResult {
            discovered_files: 1,
            skipped_files: 0,
            issues: vec![FileIssue {
                kind: FileIssueKind::Parse,
                path: "Broken.java".into(),
                message: "parse failed".into(),
            }],
            findings,
            scanned_files: 1,
            rule_count: 1,
            pack_names: vec!["test".into()],
        }
    }

    #[test]
    fn json_report_contains_findings_and_metadata() {
        let json = JsonReporter.render(&result(), 12);
        assert!(json.contains("\"rule_id\": \"rule.a\""));
        assert!(json.contains("\"severity_summary\""));
        assert!(json.contains("\"high\": 1"));
        assert!(json.contains("\"files_scanned\": 1"));
        assert!(json.contains("\"issues\""));
    }

    #[test]
    fn sarif_report_is_shaped_to_2_1_0() {
        let sarif = SarifReporter.render(&result(), 1);
        assert!(sarif.contains("\"version\": \"2.1.0\""));
        assert!(sarif.contains("\"runs\""));
        assert!(sarif.contains("\"rule.a\""));
        assert!(sarif.contains("\"level\": \"error\""));
    }

    #[test]
    fn html_report_is_self_contained() {
        let html = HtmlReporter.render(&result(), 5);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Hawk Security Assessment Report"));
        assert!(html.contains("<table>"));
        assert!(html.contains("High: 1"));
    }

    #[test]
    fn timestamp_format_is_rfc3339() {
        // Epoch: 1970-01-01T00:00:00Z
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
        // 2024-02-29 (leap day) = 1_709_164_800
        assert_eq!(format_rfc3339_utc(1_709_164_800), "2024-02-29T00:00:00Z");
        // Known boundary: 2000-01-01T00:00:00Z = 946_684_800
        assert_eq!(format_rfc3339_utc(946_684_800), "2000-01-01T00:00:00Z");
        // Time-of-day check: 2023-01-01T01:02:03Z = 1_672_534_023
        assert_eq!(format_rfc3339_utc(1_672_534_923), "2023-01-01T01:02:03Z");
        let current = now_rfc3339();
        assert_eq!(current.len(), 20);
        assert!(current.ends_with('Z'));
        assert!(current.contains('T'));
    }

    #[test]
    fn html_escapes_finding_text() {
        let mut findings = Findings::new();
        findings.push(Finding::new(
            "rule.x",
            Severity::Low,
            "<script>alert(1)</script>",
            SourceLocation {
                path: "x.js".into(),
                start_byte: 0,
                end_byte: 1,
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 2,
            },
        ));
        let result = ScanResult {
            discovered_files: 1,
            skipped_files: 0,
            issues: vec![],
            findings,
            scanned_files: 1,
            rule_count: 1,
            pack_names: vec!["test".into()],
        };
        let html = HtmlReporter.render(&result, 1);
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>alert"));
    }
}
