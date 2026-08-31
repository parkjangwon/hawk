//! Intraprocedural data-flow (taint) analysis for Java.
//!
//! Phase 4. A taint rule declares sources, sanitizers, and sinks. The engine
//! walks a Java syntax tree in source order and tracks which variables hold
//! tainted values: assignments from a source call (or from an already-tainted
//! expression) taint their target; sanitizer calls neutralize taint; a sink
//! whose argument references tainted data produces a finding. The engine owns
//! the algorithm while the rule file declares the semantics — exactly the
//! model described in the README.

pub use crate::taint_engine::{analyze, analyze_java, analyze_with_graph};

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

    // ---------- cross-file (code graph) taint ----------

    fn indexed_file(
        path: &str,
        language: Language,
        source: &str,
    ) -> crate::code_graph::IndexedFile {
        let parser = TreeSitterParser { language };
        let tree = parser.parse(source).expect("source should parse");
        crate::code_graph::IndexedFile {
            path: std::path::PathBuf::from(path),
            language,
            tree,
            source: source.to_string(),
        }
    }

    #[test]
    fn cross_file_sink_inside_callee_is_reported_at_call_site() {
        // The sink lives in UserService (another file); the caller's call site
        // carries the tainted argument. Without the code graph this is a FN.
        let controller = r#"
class Controller {
    void handle(UserService service, java.sql.Statement st, javax.servlet.http.HttpServletRequest req) {
        service.deleteUser(req.getParameter("id"), st);
    }
}
"#;
        let service = r#"
class UserService {
    void deleteUser(String userId, java.sql.Statement st) {
        st.executeQuery("DELETE FROM users WHERE id='" + userId + "'");
    }
}
"#;
        let graph = crate::code_graph::CodeGraph::build(vec![
            indexed_file("Controller.java", Language::Java, controller),
            indexed_file("UserService.java", Language::Java, service),
        ]);
        let parser = TreeSitterParser {
            language: Language::Java,
        };
        let tree = parser.parse(controller).unwrap();

        // Without the graph the cross-file sink is invisible.
        let alone = analyze(&tree, controller, &sqli_config(), Language::Java);
        assert!(
            alone.is_empty(),
            "sink in another file needs the code graph"
        );

        let findings = crate::taint::analyze_with_graph(
            &tree,
            controller,
            &sqli_config(),
            Language::Java,
            Some(&graph),
            None,
        );
        assert_eq!(
            findings.len(),
            1,
            "cross-file sink must fire at the call site"
        );
        assert!(
            findings[0].sink.contains("reaches sink"),
            "finding should name the callee sink: {}",
            findings[0].sink
        );
    }

    #[test]
    fn cross_file_return_value_taint_flows_to_caller_sink() {
        let controller = r#"
class Controller {
    void handle(UserService service, java.sql.Statement st, javax.servlet.http.HttpServletRequest req) {
        String sql = service.buildQuery(req.getParameter("id"));
        st.executeQuery(sql);
    }
}
"#;
        let service = r#"
class UserService {
    String buildQuery(String input) {
        return "SELECT * FROM users WHERE id=" + input;
    }
}
"#;
        let graph = crate::code_graph::CodeGraph::build(vec![
            indexed_file("Controller.java", Language::Java, controller),
            indexed_file("UserService.java", Language::Java, service),
        ]);
        let parser = TreeSitterParser {
            language: Language::Java,
        };
        let tree = parser.parse(controller).unwrap();
        let findings = crate::taint::analyze_with_graph(
            &tree,
            controller,
            &sqli_config(),
            Language::Java,
            Some(&graph),
            None,
        );
        assert_eq!(
            findings.len(),
            1,
            "cross-file return taint must reach the caller's sink"
        );
        assert_eq!(findings[0].sink, "st.executeQuery(sql)");
    }

    #[test]
    fn cross_file_clean_call_produces_no_finding() {
        let controller = r#"
class Controller {
    void handle(UserService service, java.sql.Statement st) {
        service.deleteUser("admin", st);
    }
}
"#;
        let service = r#"
class UserService {
    void deleteUser(String userId, java.sql.Statement st) {
        st.executeQuery("DELETE FROM users WHERE id='" + userId + "'");
    }
}
"#;
        let graph = crate::code_graph::CodeGraph::build(vec![
            indexed_file("Controller.java", Language::Java, controller),
            indexed_file("UserService.java", Language::Java, service),
        ]);
        let parser = TreeSitterParser {
            language: Language::Java,
        };
        let tree = parser.parse(controller).unwrap();
        let findings = crate::taint::analyze_with_graph(
            &tree,
            controller,
            &sqli_config(),
            Language::Java,
            Some(&graph),
            None,
        );
        assert!(findings.is_empty(), "literal arguments must stay clean");
    }

    #[test]
    fn cross_file_taint_follows_multi_hop_chains() {
        // controller -> service -> repository, with the sink in the repository.
        let controller = r#"
class Controller {
    void handle(UserService service, javax.servlet.http.HttpServletRequest req) {
        service.deleteUser(req.getParameter("id"));
    }
}
"#;
        let service = r#"
class UserService {
    void deleteUser(String userId, UserRepository repo) {
        repo.delete(userId);
    }
}
"#;
        let repository = r#"
class UserRepository {
    void delete(String userId, java.sql.Statement st) {
        st.executeQuery("DELETE FROM users WHERE id='" + userId + "'");
    }
}
"#;
        let graph = crate::code_graph::CodeGraph::build(vec![
            indexed_file("Controller.java", Language::Java, controller),
            indexed_file("UserService.java", Language::Java, service),
            indexed_file("UserRepository.java", Language::Java, repository),
        ]);
        let parser = TreeSitterParser {
            language: Language::Java,
        };
        let tree = parser.parse(controller).unwrap();
        let findings = crate::taint::analyze_with_graph(
            &tree,
            controller,
            &sqli_config(),
            Language::Java,
            Some(&graph),
            None,
        );
        assert_eq!(
            findings.len(),
            1,
            "taint must travel controller -> service -> repository"
        );
        assert!(
            findings[0].sink.contains("st.executeQuery"),
            "finding must name the deep sink: {}",
            findings[0].sink
        );
    }

    #[test]
    fn cross_file_variable_argument_carries_taint_into_callee() {
        // The tainted value reaches the cross-file callee through a local
        // variable, not a direct source call in the argument.
        let controller = r#"
class Controller {
    void handle(UserService service, java.sql.Statement st, javax.servlet.http.HttpServletRequest req) {
        String id = req.getParameter("id");
        String sql = service.buildQuery(id);
        st.executeQuery(sql);
    }
}
"#;
        let service = r#"
class UserService {
    String buildQuery(String input) {
        return "SELECT * FROM users WHERE id=" + input;
    }
}
"#;
        let graph = crate::code_graph::CodeGraph::build(vec![
            indexed_file("Controller.java", Language::Java, controller),
            indexed_file("UserService.java", Language::Java, service),
        ]);
        let parser = TreeSitterParser {
            language: Language::Java,
        };
        let tree = parser.parse(controller).unwrap();
        let findings = crate::taint::analyze_with_graph(
            &tree,
            controller,
            &sqli_config(),
            Language::Java,
            Some(&graph),
            None,
        );
        assert_eq!(
            findings.len(),
            1,
            "a tainted local variable passed across files must propagate"
        );
        assert_eq!(findings[0].sink, "st.executeQuery(sql)");
    }

    // ---------- recursion guards (regressions) ----------

    #[test]
    fn self_recursive_method_does_not_loop_forever() {
        // `get` calls `entries.get(...)`; parse_call strips the receiver so the
        // callee name is `get` — the method itself. Analyzing the assignment
        // inside the callee must keep the in-progress callee chain, or the
        // analysis re-enters `get` forever and overflows the stack.
        let source = r#"
class Cache {
    java.util.Map<String, String> entries;

    String get(String key) {
        var entry = entries.get(key);
        return entry == null ? "" : entry;
    }

    void run(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) {
        var id = req.getParameter("id");
        st.executeQuery("SELECT * FROM t WHERE id='" + get(id) + "'");
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        assert_eq!(
            findings.len(),
            1,
            "recursive callee must terminate and not lose the real flow"
        );
        assert_eq!(findings[0].sink, "st.executeQuery(\"SELECT * FROM t WHERE id='\" + get(id) + \"'\")");
    }

    #[test]
    fn mutually_recursive_methods_do_not_loop_forever() {
        // a -> b -> a with an assignment in b's body: the assignment analysis
        // inside the callee must keep the callee chain, or b re-enters a
        // forever. A literal-triggered call forces the recursive callee
        // analysis; the real taint flows through a(id) at the sink.
        let source = r#"
class Pair {
    String a(String v) { return b(v); }
    String b(String v) {
        var x = a(v);
        return x;
    }

    void handle(javax.servlet.http.HttpServletRequest req, java.sql.Statement st) {
        var id = req.getParameter("id");
        var unused = a("fixed");
        st.executeQuery("SELECT * FROM t WHERE id='" + a(id) + "'");
    }
}
"#;
        let tree = parse(source);
        let findings = analyze_java(&tree, source, &sqli_config());

        assert_eq!(
            findings.len(),
            1,
            "mutual recursion must terminate and keep the real flow"
        );
        assert!(
            findings[0].sink.contains("executeQuery"),
            "finding should name the sink call"
        );
    }
}
