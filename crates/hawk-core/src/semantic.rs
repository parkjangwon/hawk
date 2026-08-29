//! Lightweight semantic analysis: symbol collection and usage tracking.
//!
//! Phase 3 semantic support. This builds a per-file symbol table (types,
//! functions/methods, and variables) from the syntax tree, and exposes simple
//! query helpers. It is intentionally simple: enough to support the data-flow
//! phase (Phase 4) without pretending to be a full type system.

use crate::{ast::AstNode, parser::SyntaxTree};

/// Kinds of a symbol we track.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SymbolKind {
    Type,
    Function,
    Variable,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SymbolTable {
    pub symbols: Vec<Symbol>,
}

impl SymbolTable {
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Symbol> {
        self.symbols.iter()
    }

    pub fn by_name(&self, name: &str) -> Vec<&Symbol> {
        self.symbols.iter().filter(|s| s.name == name).collect()
    }

    pub fn contains_name(&self, name: &str) -> bool {
        !self.by_name(name).is_empty()
    }
}

/// Collects top-level and nested declarations from a parsed file into a
/// symbol table. The traversal is language-agnostic: it recognizes declaration
/// nodes by their tree-sitter kind and extracts the identifier text.
pub fn collect_symbols(tree: &SyntaxTree, source: &str) -> SymbolTable {
    let mut table = SymbolTable::default();
    let root = tree.root();
    collect(root, source, &mut table);
    table
}

fn collect(node: AstNode<'_>, source: &str, table: &mut SymbolTable) {
    match node.kind() {
        // Java
        "class_declaration" | "interface_declaration" | "enum_declaration" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.text(source))
            {
                push_symbol(table, SymbolKind::Type, name, &node);
            }
        }
        "method_declaration" | "constructor_declaration" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.text(source))
            {
                push_symbol(table, SymbolKind::Function, name, &node);
            }
        }
        "local_variable_declaration" => {
            if let Some(name) = node
                .child_by_field_name("declarator")
                .and_then(|d| d.child_by_field_name("name").and_then(|n| n.text(source)))
                .or_else(|| {
                    node.child_by_field_name("name").and_then(|n| {
                        n.text(source).or_else(|| {
                            // fall back: first identifier-looking child
                            node.children()
                                .find(|c| c.kind() == "identifier")
                                .and_then(|c| c.text(source))
                        })
                    })
                })
            {
                push_symbol(table, SymbolKind::Variable, name, &node);
            }
        }
        // Python
        "function_definition" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.text(source))
            {
                push_symbol(table, SymbolKind::Function, name, &node);
            }
        }
        "class_definition" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.text(source))
            {
                push_symbol(table, SymbolKind::Type, name, &node);
            }
        }
        // Go
        "function_declaration" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|n| n.text(source))
            {
                push_symbol(table, SymbolKind::Function, name, &node);
            }
        }
        "type_spec" => {
            // go: type Name struct { ... }
            if let Some(name) = node
                .children()
                .find(|c| c.kind() == "type_identifier")
                .and_then(|c| c.text(source))
            {
                push_symbol(table, SymbolKind::Type, name, &node);
            }
        }
        _ => {}
    }

    for child in node.children() {
        collect(child, source, table);
    }
}

fn push_symbol(table: &mut SymbolTable, kind: SymbolKind, name: &str, node: &AstNode<'_>) {
    let pos = node.start_position();
    table.symbols.push(Symbol {
        name: name.to_string(),
        kind,
        line: pos.row + 1,
        column: pos.column + 1,
    });
}

/// Whether the source declares the given identifier before the given line.
/// Returns (definition_found, first_definition_line).
pub fn declared_before(table: &SymbolTable, name: &str, line: usize) -> (bool, Option<usize>) {
    let defs = table.by_name(name);
    match defs.into_iter().find(|s| s.line <= line) {
        Some(def) => (true, Some(def.line)),
        None => (false, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language::Language;
    use crate::parser::{Parser, TreeSitterParser};

    fn parse(language: Language, source: &str) -> SyntaxTree {
        let parser = TreeSitterParser { language };
        parser.parse(source).expect("test source should parse")
    }

    #[test]
    fn java_symbols_include_classes_methods_and_variables() {
        let tree = parse(
            Language::Java,
            "class Foo { int x; void bar(String s) { int y = 1; } }",
        );
        let table = collect_symbols(
            &tree,
            "class Foo { int x; void bar(String s) { int y = 1; } }",
        );

        assert!(table
            .by_name("Foo")
            .iter()
            .any(|s| s.kind == SymbolKind::Type));
        assert!(table
            .by_name("bar")
            .iter()
            .any(|s| s.kind == SymbolKind::Function));
        // x is a field declaration (declarator); y is a local variable
        assert!(table
            .by_name("y")
            .iter()
            .any(|s| s.kind == SymbolKind::Variable));
    }

    #[test]
    fn python_symbols_include_functions_and_classes() {
        let tree = parse(
            Language::Python,
            "class A:\n    def m(self):\n        pass\n",
        );
        let table = collect_symbols(&tree, "class A:\n    def m(self):\n        pass\n");

        assert!(table
            .by_name("A")
            .iter()
            .any(|s| s.kind == SymbolKind::Type));
        assert!(table
            .by_name("m")
            .iter()
            .any(|s| s.kind == SymbolKind::Function));
    }

    #[test]
    fn go_symbols_include_functions_and_types() {
        let tree = parse(
            Language::Go,
            "package main\ntype T struct{}\nfunc main() {}\n",
        );
        let table = collect_symbols(&tree, "package main\ntype T struct{}\nfunc main() {}\n");

        assert!(table
            .by_name("T")
            .iter()
            .any(|s| s.kind == SymbolKind::Type));
        assert!(table
            .by_name("main")
            .iter()
            .any(|s| s.kind == SymbolKind::Function));
    }

    #[test]
    fn used_before_reports_definition_line() {
        let tree = parse(
            Language::Java,
            "class A { void m() { int x = 1; use(x); } }",
        );
        let source = "class A { void m() { int x = 1; use(x); } }";
        let table = collect_symbols(&tree, source);

        let (found, line) = declared_before(&table, "x", 1);
        assert!(found);
        assert!(line.is_some());
    }
}
