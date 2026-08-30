//! Project-wide architecture index: symbols (functions/methods) and the call
//! edges between them, built from the parsed files of a scan.
//!
//! The graph answers structural questions a single-file scan cannot: which
//! functions are actually reachable from callers, where a callee is defined,
//! and — via the taint engine's `analyze_with_graph` — whether tainted data
//! crosses file boundaries along real call chains (handler → service →
//! repository → sink).

use std::path::PathBuf;

use serde::Serialize;

use crate::{
    ast::AstNode,
    language::Language,
    parser::SyntaxTree,
    taint_engine::{call_kinds, method_like_kinds, parse_call},
};

/// A parsed source file that participates in the architecture index.
#[derive(Debug)]
pub struct IndexedFile {
    pub path: PathBuf,
    pub language: Language,
    pub tree: SyntaxTree,
    pub source: String,
}

impl IndexedFile {
    /// The method-like node whose declaration starts at `line` (1-based),
    /// used to re-locate cross-file callees during taint analysis.
    pub fn method_node_at(&self, line: usize) -> Option<AstNode<'_>> {
        fn visit<'tree>(
            node: AstNode<'tree>,
            line: usize,
            kinds: &'static [&'static str],
        ) -> Option<AstNode<'tree>> {
            if kinds.contains(&node.kind()) && node.start_position().row + 1 == line {
                return Some(node);
            }
            if node.end_position().row + 1 < line {
                return None; // subtree ends before the target line
            }
            for child in node.children() {
                if let Some(found) = visit(child, line, kinds) {
                    return Some(found);
                }
            }
            None
        }
        visit(self.tree.root(), line, method_like_kinds(self.language))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SymbolKind {
    Function,
    Method,
    Constructor,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphSymbol {
    pub name: String,
    /// `Class.method` when an enclosing class is visible; `method` otherwise.
    pub qualified_name: String,
    pub kind: SymbolKind,
    pub file: PathBuf,
    /// Index into `CodeGraph::files`.
    pub file_index: usize,
    pub line: usize,
    pub language: Language,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallEdge {
    /// Symbol index of the caller.
    pub caller: usize,
    /// The callee as written at the call site (e.g. `AuthService.authenticate`).
    pub callee_text: String,
    /// Symbol index of the resolved callee, when a definition was found.
    pub callee: Option<usize>,
    pub line: usize,
}

/// A call site recorded before the caller's symbol index is known; resolved
/// into a `CallEdge` once all symbols are collected.
struct PendingCall {
    caller_file: PathBuf,
    caller_name: String,
    caller_line: usize,
    callee_text: String,
    line: usize,
}

/// The architecture index of a scan: every symbol plus every call edge, with
/// callee resolution against the project's own definitions.
#[derive(Debug, Default)]
pub struct CodeGraph {
    pub files: Vec<IndexedFile>,
    pub symbols: Vec<GraphSymbol>,
    pub edges: Vec<CallEdge>,
}

impl CodeGraph {
    /// Indexes the given files: extracts symbols and call edges, then resolves
    /// callers and callees against the project's symbols (same file preferred).
    pub fn build(files: Vec<IndexedFile>) -> Self {
        let mut graph = Self {
            files,
            symbols: Vec::new(),
            edges: Vec::new(),
        };
        for (file_index, file) in graph.files.iter().enumerate() {
            collect_symbols(file.tree.root(), file, file_index, &mut graph.symbols);
        }
        let mut pending = Vec::new();
        for file in &graph.files {
            collect_edges(file.tree.root(), file, &mut pending);
        }
        for call in pending {
            // Map the caller back to its symbol via (file, line, name).
            let caller = graph
                .symbols
                .iter()
                .enumerate()
                .find(|(_, symbol)| {
                    symbol.file == call.caller_file
                        && symbol.line == call.caller_line
                        && symbol.name == call.caller_name
                })
                .map(|(index, _)| index);
            let Some(caller) = caller else { continue };
            graph.edges.push(CallEdge {
                caller,
                callee_text: call.callee_text,
                callee: None,
                line: call.line,
            });
        }
        graph.resolve_callees();
        graph
    }

    /// Resolves every edge's callee against the project's symbols: a dotted
    /// callee is matched against qualified names first, then simple names,
    /// preferring same-file definitions.
    fn resolve_callees(&mut self) {
        for edge in &mut self.edges {
            let caller_file = self.symbols[edge.caller].file.clone();
            // Receiver-style calls (`service.deleteUser`) resolve by their
            // final segment; `st.executeQuery` stays unresolved (library).
            let simple = edge
                .callee_text
                .rsplit('.')
                .next()
                .unwrap_or(&edge.callee_text);
            let mut same_file = None;
            let mut any = None;
            for (index, symbol) in self.symbols.iter().enumerate() {
                let matches = symbol.qualified_name == edge.callee_text
                    || symbol.name == edge.callee_text
                    || symbol
                        .qualified_name
                        .ends_with(&format!(".{}", edge.callee_text))
                    || symbol.name == simple;
                if !matches {
                    continue;
                }
                if same_file.is_none() && symbol.file == caller_file {
                    same_file = Some(index);
                }
                if any.is_none() {
                    any = Some(index);
                }
            }
            edge.callee = same_file.or(any);
        }
    }

    /// (file index, declaration line) of every symbol whose simple or
    /// qualified name matches `name` (used for cross-file callee lookup).
    pub fn symbol_locations(&self, name: &str) -> Vec<(usize, usize)> {
        let suffix = format!(".{}", name);
        self.symbols
            .iter()
            .filter(|symbol| {
                symbol.name == name
                    || symbol.qualified_name == name
                    || symbol.qualified_name.ends_with(&suffix)
            })
            .map(|symbol| (symbol.file_index, symbol.line))
            .collect()
    }

    /// Symbols with no incoming call edges within the scanned code. Includes
    /// genuine entry points (main, handlers), so the list is advisory.
    pub fn unused(&self) -> Vec<&GraphSymbol> {
        let called: std::collections::HashSet<usize> =
            self.edges.iter().filter_map(|edge| edge.callee).collect();
        self.symbols
            .iter()
            .enumerate()
            .filter(|(index, _)| !called.contains(index))
            .map(|(_, symbol)| symbol)
            .collect()
    }

    /// Human-readable architecture listing.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Architecture graph: {} file(s), {} symbols, {} call edge(s)\n\n",
            self.files.len(),
            self.symbols.len(),
            self.edges.len()
        ));
        let mut by_file: Vec<&PathBuf> = self.files.iter().map(|file| &file.path).collect();
        by_file.sort();
        for path in by_file {
            out.push_str(&format!("{}\n", path.display()));
            for (index, symbol) in self
                .symbols
                .iter()
                .enumerate()
                .filter(|(_, symbol)| &symbol.file == path)
            {
                out.push_str(&format!(
                    "  {} {}() :{}\n",
                    symbol.kind_label(),
                    symbol.qualified_name,
                    symbol.line
                ));
                for edge in self.edges.iter().filter(|edge| edge.caller == index) {
                    out.push_str(&format!(
                        "    -> {} {}\n",
                        edge.callee_text,
                        match edge.callee {
                            Some(index) => format!(
                                "({}:{})",
                                self.symbols[index].file.display(),
                                self.symbols[index].line
                            ),
                            None => "(unresolved: external or dynamic)".into(),
                        }
                    ));
                }
            }
        }
        let unused = self.unused();
        if !unused.is_empty() {
            out.push_str(&format!(
                "\nNo callers within scanned code ({}):\n",
                unused.len()
            ));
            for symbol in unused {
                out.push_str(&format!(
                    "  {}:{} {}\n",
                    symbol.file.display(),
                    symbol.line,
                    symbol.qualified_name
                ));
            }
        }
        out
    }

    /// Mermaid flowchart source for rendering/visualization.
    pub fn to_mermaid(&self) -> String {
        let mut out = String::from("graph TD\n");
        for (index, symbol) in self.symbols.iter().enumerate() {
            let label = format!(
                "{}()<br/><small>{}</small>",
                symbol.qualified_name,
                symbol
                    .file
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            );
            out.push_str(&format!("  n{index}[\"{}\"]\n", label.replace('"', "'")));
        }
        let mut external_id = 0usize;
        for edge in &self.edges {
            if let Some(callee) = edge.callee {
                out.push_str(&format!("  n{} --> n{}\n", edge.caller, callee));
            } else {
                external_id += 1;
                out.push_str(&format!(
                    "  n{} --> n_ext{external_id}[\"external: {}\"]\n",
                    edge.caller, edge.callee_text
                ));
            }
        }
        out
    }

    /// JSON serialization of the graph (paths, symbols, edges, unused list).
    pub fn to_json(&self) -> String {
        let file_paths: Vec<String> = self
            .files
            .iter()
            .map(|file| file.path.to_string_lossy().to_string())
            .collect();
        let unused: Vec<String> = self
            .unused()
            .iter()
            .map(|symbol| {
                format!(
                    "{}:{} {}",
                    symbol.file.display(),
                    symbol.line,
                    symbol.qualified_name
                )
            })
            .collect();
        serde_json::json!({
            "files": file_paths,
            "symbols": self.symbols,
            "edges": self.edges,
            "unused": unused,
        })
        .to_string()
    }
}

impl GraphSymbol {
    fn kind_label(&self) -> &'static str {
        match self.kind {
            SymbolKind::Function => "fn",
            SymbolKind::Method => "method",
            SymbolKind::Constructor => "ctor",
        }
    }
}

fn collect_symbols(
    root: AstNode<'_>,
    file: &IndexedFile,
    file_index: usize,
    out: &mut Vec<GraphSymbol>,
) {
    fn visit(node: AstNode<'_>, file: &IndexedFile, file_index: usize, out: &mut Vec<GraphSymbol>) {
        if method_like_kinds(file.language).contains(&node.kind()) {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|name| name.text(&file.source))
                .map(String::from)
            {
                let kind = match node.kind() {
                    "constructor_declaration" => SymbolKind::Constructor,
                    "method_declaration" | "method_definition" => SymbolKind::Method,
                    _ => SymbolKind::Function,
                };
                out.push(GraphSymbol {
                    qualified_name: qualify(node, &name, &file.source),
                    name,
                    kind,
                    file: file.path.clone(),
                    file_index,
                    line: node.start_position().row + 1,
                    language: file.language,
                });
            }
            return; // do not descend into nested functions for symbols
        }
        for child in node.children() {
            visit(child, file, file_index, out);
        }
    }
    visit(root, file, file_index, out);
}

/// Best-effort `Class.method` qualification by walking enclosing type nodes.
fn qualify(node: AstNode<'_>, name: &str, source: &str) -> String {
    let mut classes = Vec::new();
    let mut current = node.parent();
    while let Some(parent) = current {
        if matches!(
            parent.kind(),
            "class_declaration"
                | "interface_declaration"
                | "enum_declaration"
                | "annotation_type_declaration"
                | "class"
                | "interface"
        ) {
            if let Some(class_name) = parent
                .child_by_field_name("name")
                .and_then(|name| name.text(source))
                .map(String::from)
            {
                classes.push(class_name);
            }
        }
        current = parent.parent();
    }
    if classes.is_empty() {
        name.to_string()
    } else {
        classes.reverse();
        classes.push(name.to_string());
        classes.join(".")
    }
}

fn collect_edges(root: AstNode<'_>, file: &IndexedFile, out: &mut Vec<PendingCall>) {
    fn visit(
        node: AstNode<'_>,
        file: &IndexedFile,
        enclosing: Option<(PathBuf, String, usize)>,
        out: &mut Vec<PendingCall>,
    ) {
        if method_like_kinds(file.language).contains(&node.kind()) {
            let enclosing = node
                .child_by_field_name("name")
                .and_then(|name| name.text(&file.source))
                .map(|name| {
                    (
                        file.path.clone(),
                        name.to_string(),
                        node.start_position().row + 1,
                    )
                });
            for child in node.children() {
                visit(child, file, enclosing.clone(), out);
            }
            return;
        }
        if call_kinds(file.language).contains(&node.kind()) {
            if let Some(text) = node.text(&file.source).map(String::from) {
                if let Some((name, _)) = parse_call(&text) {
                    let head = text
                        .find('(')
                        .map(|index| text[..index].trim().to_string())
                        .unwrap_or_else(|| name.clone());
                    if let Some((caller_file, caller_name, caller_line)) = &enclosing {
                        out.push(PendingCall {
                            caller_file: caller_file.clone(),
                            caller_name: caller_name.clone(),
                            caller_line: *caller_line,
                            callee_text: head,
                            line: node.start_position().row + 1,
                        });
                    }
                }
            }
        }
        for child in node.children() {
            visit(child, file, enclosing.clone(), out);
        }
    }
    visit(root, file, None, out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{Parser, TreeSitterParser};

    fn indexed(path: &str, language: Language, source: &str) -> IndexedFile {
        let parser = TreeSitterParser { language };
        let tree = parser.parse(source).expect("source should parse");
        IndexedFile {
            path: PathBuf::from(path),
            language,
            tree,
            source: source.to_string(),
        }
    }

    #[test]
    fn indexes_symbols_and_resolves_cross_file_calls() {
        let graph = CodeGraph::build(vec![
            indexed(
                "Controller.java",
                Language::Java,
                r#"
class Controller {
    void handle(Service service) {
        service.deleteUser("x");
        st.executeQuery("SELECT 1");
    }
}
"#,
            ),
            indexed(
                "Service.java",
                Language::Java,
                r#"
class Service {
    void deleteUser(String id) {}
    String build() { return "x"; }
}
"#,
            ),
        ]);

        assert_eq!(graph.symbols.len(), 3);
        let controller = graph
            .symbols
            .iter()
            .find(|symbol| symbol.qualified_name == "Controller.handle")
            .expect("controller symbol");
        assert_eq!(controller.line, 3);
        let service = graph
            .symbols
            .iter()
            .find(|symbol| symbol.qualified_name == "Service.deleteUser")
            .expect("service symbol");

        let delete_edge = graph
            .edges
            .iter()
            .find(|edge| edge.callee_text == "service.deleteUser")
            .expect("delete edge");
        assert_eq!(
            graph.symbols[delete_edge.callee.unwrap()].qualified_name,
            "Service.deleteUser"
        );
        let external = graph
            .edges
            .iter()
            .find(|edge| edge.callee_text == "st.executeQuery")
            .expect("external edge");
        assert!(external.callee.is_none(), "library calls stay unresolved");
        let _ = service;
    }

    #[test]
    fn same_file_calls_prefer_local_definitions() {
        let graph = CodeGraph::build(vec![indexed(
            "App.java",
            Language::Java,
            r#"
class A {
    void run() { helper(); }
    void helper() {}
}
class B {
    void helper() {}
}
"#,
        )]);
        let edge = graph
            .edges
            .iter()
            .find(|e| e.callee_text == "helper")
            .unwrap();
        let callee = &graph.symbols[edge.callee.unwrap()];
        assert_eq!(callee.qualified_name, "A.helper");
    }

    #[test]
    fn unused_lists_symbols_without_callers() {
        let graph = CodeGraph::build(vec![indexed(
            "App.java",
            Language::Java,
            r#"
class A {
    void main() { used(); }
    void used() {}
    void dead() {}
}
"#,
        )]);
        let names: Vec<&str> = graph
            .unused()
            .iter()
            .map(|symbol| symbol.name.as_str())
            .collect();
        assert!(names.contains(&"dead"));
        assert!(!names.contains(&"used"));
    }

    #[test]
    fn renders_mermaid_and_json() {
        let graph = CodeGraph::build(vec![indexed(
            "App.java",
            Language::Java,
            "class A { void run() { helper(); } void helper() {} }",
        )]);
        let mermaid = graph.to_mermaid();
        assert!(mermaid.starts_with("graph TD"));
        assert!(mermaid.contains("n0 --> n1"));
        let json = graph.to_json();
        assert!(json.contains("\"qualified_name\":\"A.run\""));
    }
}
