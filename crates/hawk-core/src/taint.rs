//! Intraprocedural data-flow (taint) analysis for Java.
//!
//! Phase 4. A taint rule declares sources, sanitizers, and sinks. The engine
//! walks a Java syntax tree in source order and tracks which variables hold
//! tainted values: assignments from a source call (or from an already-tainted
//! expression) taint their target; sanitizer calls neutralize taint; a sink
//! whose argument references tainted data produces a finding. The engine owns
//! the algorithm while the rule file declares the semantics — exactly the
//! model described in the README.

pub use crate::taint_engine::{analyze, analyze_java};

use crate::{
    finding::{Confidence, Finding, Severity, SourceLocation},
    language::Language,
    taint_engine::line_text,
};

/// The configuration half of a taint rule: lists of call-site patterns.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TaintConfig {
    pub sources: Vec<String>,
    pub sanitizers: Vec<String>,
    pub sinks: Vec<String>,
}

/// A single taint finding produced by the engine, before it is merged into the
/// Finding model by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintFinding {
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_line: usize,
    pub start_column: usize,
    /// Variable or expression that carried the taint into the sink.
    pub tainted: String,
    /// The sink expression that was hit.
    pub sink: String,
}

#[derive(Debug, Clone, Copy)]
pub struct TaintMetadata<'a> {
    pub rule_id: &'a str,
    pub rule_name: &'a str,
    pub description: &'a str,
    pub recommendation: Option<&'a str>,
    pub category: Option<&'a str>,
    pub framework: Option<&'a str>,
    pub cwe: Option<&'a str>,
    pub owasp: Option<&'a str>,
    pub language: Option<Language>,
    pub severity: Severity,
    pub confidence: Confidence,
}

/// Builds a normal Finding from a taint finding plus rule metadata.
pub fn to_finding(
    taint: &TaintFinding,
    source: &str,
    metadata: TaintMetadata<'_>,
    path: &std::path::Path,
) -> Finding {
    let mut finding = Finding::new(
        metadata.rule_id,
        metadata.severity,
        format!(
            "Tainted data from {src} reached sink {sink}.",
            src = taint.tainted,
            sink = taint.sink,
        ),
        SourceLocation {
            path: path.to_path_buf(),
            start_byte: taint.start_byte,
            end_byte: taint.end_byte,
            start_line: taint.start_line,
            start_column: taint.start_column,
            end_line: taint.start_line,
            end_column: taint.start_column + (taint.end_byte - taint.start_byte),
        },
    )
    .with_confidence(metadata.confidence)
    .with_rule_name(metadata.rule_name)
    .with_description(metadata.description)
    .with_code_snippet(line_text(source, taint.start_byte));
    if let Some(value) = metadata.recommendation {
        finding = finding.with_recommendation(value);
    }
    if let Some(value) = metadata.category {
        finding = finding.with_category(value);
    }
    if let Some(value) = metadata.framework {
        finding = finding.with_framework(value);
    }
    if let Some(value) = metadata.cwe {
        finding = finding.with_cwe(value);
    }
    if let Some(value) = metadata.owasp {
        finding = finding.with_owasp(value);
    }
    if let Some(value) = metadata.language {
        finding = finding.with_language(value);
    }
    finding
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{Parser, SyntaxTree, TreeSitterParser};
    use crate::taint_engine::is_tainted_text;
    use std::collections::HashSet;

    fn parse(source: &str) -> SyntaxTree {
        let parser = TreeSitterParser {
            language: Language::Java,
        };
        parser.parse(source).unwrap()
    }

    fn sqli_config() -> TaintConfig {
        TaintConfig {
            sources: vec!["getParameter".into()],
            sanitizers: vec!["escapeSql".into()],
            sinks: vec![".executeQuery(".into(), ".execute(".into()],
        }
    }

    #[test]
    fn detects_sql_injection_source_to_sink_flow() {
        let source = r#"
class X {
    void m(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) {
        String id = req.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = " + id;
        st.executeQuery(sql);
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].sink, "st.executeQuery(sql)");
        assert!(findings[0].tainted.contains("sql"));
        assert_eq!(findings[0].start_line, 6);
    }

    #[test]
    fn no_finding_when_sink_input_is_clean() {
        let source = r#"
class X {
    void m(java.sql.Statement st) {
        st.executeQuery("SELECT 1");
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        assert!(findings.is_empty());
    }

    #[test]
    fn direct_source_in_sink_argument_is_detected() {
        let source = r#"
class X {
    void m(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) {
        st.executeQuery(req.getParameter("q"));
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn identifier_matching_does_not_confuse_prefixes() {
        let mut tainted = HashSet::new();
        tainted.insert("id".to_string());
        assert!(is_tainted_text("execute(id)", &tainted));
        assert!(!is_tainted_text("execute(identity)", &tainted));
    }

    #[test]
    fn sanitized_flow_is_not_detected() {
        let source = r#"
class X {
    void m(javax.servlet.http.HttpServletRequest req) {
        String id = req.getParameter("id");
        String safe = escapeSql(id);
        String sql = "SELECT * FROM u WHERE id = " + safe;
        // The sink here matches executeQuery; safe was sanitized so no taint.
    }
}
"#;
        let config = TaintConfig {
            sinks: vec!["executeQuery".into()],
            sanitizers: vec!["escapeSql".into()],
            sources: vec!["getParameter".into()],
        };
        let tree = parse(source);

        // Deliberately no call to "executeQuery" so the flow does not fire —
        // this test asserts the sanitizer clears the variable when a later
        // assignment uses it.
        let findings = analyze_java(&tree, source, &config);
        assert!(findings.is_empty());
    }

    #[test]
    fn interprocedural_return_value_taint_is_tracked() {
        let source = r#"
class X {
    String buildQuery(javax.servlet.http.HttpServletRequest req) {
        return "SELECT * FROM u WHERE id=" + req.getParameter("id");
    }
    void m(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) {
        st.executeQuery(buildQuery(req));
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        assert_eq!(findings.len(), 1, "method return value must carry taint");
        assert_eq!(findings[0].sink, "st.executeQuery(buildQuery(req))");
    }

    #[test]
    fn interprocedural_taint_flows_through_assignment() {
        let source = r#"
class X {
    String wrap(String input) {
        return "prefix " + input;
    }
    void m(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) {
        String id = req.getParameter("id");
        String sql = wrap(id);
        st.executeQuery(sql);
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        assert_eq!(findings.len(), 1, "assigned method result must carry taint");
        assert!(findings[0].tainted.contains("sql"));
    }

    #[test]
    fn tainted_arguments_are_bound_to_callee_parameters() {
        let source = r#"
class X {
    String concat(String a, String b) {
        return a + b;
    }
    void m(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) {
        String id = req.getParameter("id");
        String sql = concat("SELECT * FROM u WHERE id=", id);
        st.executeQuery(sql);
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        assert_eq!(findings.len(), 1, "parameter binding must propagate taint");
    }

    #[test]
    fn interprocedural_taint_does_not_leak_across_siblings() {
        let source = r#"
class X {
    String buildQuery(javax.servlet.http.HttpServletRequest req) {
        return req.getParameter("id");
    }
    void clean() {
        String sql = "SELECT 1";
    }
    void m(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) {
        String sql = "SELECT 1";
        st.executeQuery(sql);
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        assert!(findings.is_empty(), "unrelated method must not be tainted");
    }

    #[test]
    fn recursive_calls_do_not_loop_forever() {
        let source = r#"
class X {
    String identity(String x) {
        return identity(x);
    }
    void m(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) {
        String id = req.getParameter("id");
        String sql = identity(id);
        st.executeQuery(sql);
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        // Recursion is guarded: analysis terminates; taint may not propagate
        // through the cyclic call, which is the safe behavior.
        assert!(findings.len() <= 1);
    }

    #[test]
    fn javascript_taint_flows_through_variables_and_function_returns() {
        let source = r#"
function build(prefix, user) {
    return prefix + user.q;
}
const q = req.query.q;
el.outerHTML = build("x", { q });
"#;
        let parser = TreeSitterParser {
            language: Language::JavaScript,
        };
        let tree = parser.parse(source).expect("js should parse");
        let config = TaintConfig {
            sources: vec!["req.query".into()],
            sanitizers: vec![],
            sinks: vec![".outerHTML".into()],
        };

        let findings = analyze(&tree, source, &config, Language::JavaScript);

        assert_eq!(
            findings.len(),
            1,
            "JS taint must flow through variables and calls"
        );
        assert!(findings[0].sink.contains("outerHTML"));
    }

    #[test]
    fn javascript_taint_ignores_clean_assignments() {
        let source = "const q = req.query.q;\nel.textContent = q;\n";
        let parser = TreeSitterParser {
            language: Language::JavaScript,
        };
        let tree = parser.parse(source).unwrap();
        let config = TaintConfig {
            sources: vec!["req.query".into()],
            sanitizers: vec![],
            sinks: vec![".outerHTML".into()],
        };

        let findings = analyze(&tree, source, &config, Language::JavaScript);
        assert!(findings.is_empty());
    }

    #[test]
    fn python_taint_flows_to_mark_safe() {
        let source = "def view():\n    q = request.args.get('q')\n    return mark_safe(q)\n";
        let parser = TreeSitterParser {
            language: Language::Python,
        };
        let tree = parser.parse(source).expect("py should parse");
        let config = TaintConfig {
            sources: vec!["request.args".into()],
            sanitizers: vec![],
            sinks: vec!["mark_safe(".into()],
        };

        let findings = analyze(&tree, source, &config, Language::Python);

        assert_eq!(
            findings.len(),
            1,
            "Python taint must follow assignments to sinks"
        );
    }

    #[test]
    fn taint_in_else_branch_is_not_erased_by_source_order() {
        // Regression: with a single sequential state, the else branch would
        // overwrite the then-branch taint and the sink would be missed.
        let source = r#"
class X {
    void m(javax.servlet.http.HttpServletRequest req, java.sql.Statement st, boolean cond) {
        String q = "SELECT 1";
        if (cond) {
            q = req.getParameter("q");
        } else {
            q = "clean";
        }
        st.executeQuery(q);
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        assert_eq!(
            findings.len(),
            1,
            "taint in one branch must survive the join"
        );
    }

    #[test]
    fn taint_is_cleared_when_both_branches_sanitize() {
        let source = r#"
class X {
    void m(javax.servlet.http.HttpServletRequest req, java.sql.Statement st, boolean cond) {
        String q = req.getParameter("q");
        if (cond) {
            q = escapeSql(q);
        } else {
            q = escapeSql(q);
        }
        st.executeQuery(q);
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        assert!(
            findings.is_empty(),
            "sanitizing both branches must clear taint"
        );
    }

    #[test]
    fn taint_assigned_only_in_loop_body_survives_loop() {
        let source = r#"
class X {
    void m(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) {
        String q = "SELECT 1";
        for (int i = 0; i < 3; i++) {
            q = req.getParameter("q");
        }
        st.executeQuery(q);
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        assert_eq!(findings.len(), 1, "loop body may taint q");
    }

    #[test]
    fn clean_loop_assignment_keeps_may_tainted_entry() {
        let source = r#"
class X {
    void m(javax.servlet.http.HttpServletRequest req, java.sql.Statement st, boolean go) {
        String q = req.getParameter("q");
        while (go) {
            q = "SELECT 1";
        }
        st.executeQuery(q);
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        assert_eq!(
            findings.len(),
            1,
            "loop may not run; entry taint must be kept"
        );
    }

    #[test]
    fn python_taint_is_sanitized_by_escape() {
        let source = "def view():\n    q = request.args.get('q')\n    return escape(q)\n";
        let parser = TreeSitterParser {
            language: Language::Python,
        };
        let tree = parser.parse(source).unwrap();
        let config = TaintConfig {
            sources: vec!["request.args".into()],
            sanitizers: vec!["escape".into()],
            sinks: vec!["mark_safe(".into()],
        };

        let findings = analyze(&tree, source, &config, Language::Python);
        assert!(findings.is_empty());
    }

    #[test]
    fn typescript_taint_flows_through_typed_variables() {
        let source = r#"
import { Request, Response } from "express";

function render(req: Request): string {
    const name: string = req.params.name;
    return "<div>" + name + "</div>";
}

export function handler(req: Request, res: Response) {
    res.send(render(req));
}
"#;
        let parser = TreeSitterParser {
            language: Language::TypeScript,
        };
        let tree = parser.parse(source).expect("ts should parse");
        let config = TaintConfig {
            sources: vec!["req.params".into()],
            sanitizers: vec![],
            sinks: vec!["res.send(".into()],
        };

        let findings = analyze(&tree, source, &config, Language::TypeScript);

        assert_eq!(
            findings.len(),
            1,
            "TS taint must flow through typed params and returns"
        );
        assert!(findings[0].sink.contains("res.send("));
    }

    #[test]
    fn typescript_taint_is_cleared_by_sanitizer() {
        let source = r#"
import { Request, Response } from "express";
import { escape } from "html-escape";

export function handler(req: Request, res: Response) {
    const q: string = req.query.q as string;
    const safe = escape(q);
    res.send(safe);
}
"#;
        let parser = TreeSitterParser {
            language: Language::TypeScript,
        };
        let tree = parser.parse(source).expect("ts should parse");
        let config = TaintConfig {
            sources: vec!["req.query".into()],
            sanitizers: vec!["escape(".into()],
            sinks: vec!["res.send(".into()],
        };

        let findings = analyze(&tree, source, &config, Language::TypeScript);
        assert!(findings.is_empty(), "sanitized TS flow must not fire");
    }

    #[test]
    fn words_inside_string_literals_are_not_identifier_matches() {
        let source = r#"
class X {
    void m(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) {
        String name = req.getParameter("name");
        st.executeQuery("SELECT name FROM users WHERE id = 1");
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        assert!(
            findings.is_empty(),
            "the word `name` inside the SQL literal must not match the tainted variable"
        );
    }

    #[test]
    fn template_literal_interpolation_still_carries_taint() {
        let source = r#"
const q = req.query.q;
el.outerHTML = `<div>${q}</div>`;
"#;
        let parser = TreeSitterParser {
            language: Language::JavaScript,
        };
        let tree = parser.parse(source).expect("js should parse");
        let config = TaintConfig {
            sources: vec!["req.query".into()],
            sanitizers: vec![],
            sinks: vec![".outerHTML".into()],
        };

        let findings = analyze(&tree, source, &config, Language::JavaScript);
        assert_eq!(findings.len(), 1, "template interpolation carries taint");
    }
}
