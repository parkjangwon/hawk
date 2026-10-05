//! Project-wide architecture index: symbols (functions/methods) and the call
//! edges between them, built from the parsed files of a scan.
//!
//! The graph answers structural questions a single-file scan cannot: which
//! functions are actually reachable from callers, where a callee is defined,
//! and — via the taint engine's `analyze_with_graph` — whether tainted data
//! crosses file boundaries along real call chains (handler → service →
//! repository → sink).

mod collect;
mod resolve;

#[cfg(test)]
mod tests;

use collect::*;
use resolve::*;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

use crate::{
    ast::AstNode,
    language::Language,
    parser::{ParserRegistry, SyntaxTree},
    taint_engine::method_like_kinds,
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

    /// The method-like node containing `byte` — O(depth) via the tree's
    /// descendant lookup, instead of scanning the whole tree for a line.
    pub fn method_node_at_byte(&self, byte: usize) -> Option<AstNode<'_>> {
        let kinds = method_like_kinds(self.language);
        let mut current = self
            .tree
            .raw_root_node()
            .descendant_for_byte_range(byte, byte)?;
        loop {
            if kinds.contains(&current.kind()) {
                return Some(AstNode::new(current));
            }
            current = current.parent()?;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SymbolKind {
    Function,
    Method,
    Constructor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSymbol {
    pub name: String,
    /// `Class.method` when an enclosing class is visible; `method` otherwise.
    pub qualified_name: String,
    pub kind: SymbolKind,
    pub file: PathBuf,
    /// Index into `CodeGraph::files`.
    pub file_index: usize,
    pub line: usize,
    /// Byte offset of the declaration node, for O(depth) re-location.
    pub start_byte: usize,
    pub language: Language,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// (file index, enclosing method line [0 = class scope], variable,
    /// declared type) — used to resolve `service.deleteUser` to the right
    /// `UserService.deleteUser` when several classes share a method name.
    var_types: Vec<(usize, usize, String, String)>,
    /// Class inheritance/implementation facts for type-guided resolution.
    hierarchy: Vec<ClassInfo>,
    /// (file index, local name, imported path, original imported name) for
    /// `import { a as b } from "p"` — the original name resolves the symbol.
    imports: Vec<(usize, String, String, String)>,
    /// (file index, namespace name, imported path) for `import * as ns`.
    namespaces: Vec<(usize, String, String)>,
    /// simple symbol name -> (file index, declaration byte); built once per
    /// scan and shared by every taint analysis instead of being recomputed
    /// per rule per file.
    name_locations: HashMap<String, Vec<(usize, usize)>>,
    /// (caller file index, simple callee name) -> resolved (file index, byte).
    resolved_by_file_name: HashMap<(usize, String), Vec<(usize, usize)>>,
    /// File path -> file index, for path-keyed lookups.
    file_index_by_path: HashMap<PathBuf, usize>,
    /// When the graph is restored from a snapshot, the files' trees are not
    /// loaded; `lazy_files` re-parses them on demand (append-only, so
    /// references into parsed entries stay valid for the graph's lifetime).
    lazy_files: Option<LazyFiles>,
}

/// `class X extends Y implements A, B` — superclass and interface facts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassInfo {
    pub file_index: usize,
    pub name: String,
    pub extends: Option<String>,
    pub implements: Vec<String>,
}

/// On-demand parsing for snapshot-restored graphs: file metadata plus a
/// per-file cache of parsed content, filled the first time a callee body in
/// that file is needed.
#[derive(Debug)]
struct LazyFiles {
    paths: Vec<PathBuf>,
    languages: Vec<Language>,
    parsed: Vec<OnceCell<Box<IndexedFile>>>,
    parsers: ParserRegistry,
}

impl LazyFiles {
    fn new(meta: &[GraphFileMeta]) -> Self {
        Self {
            paths: meta.iter().map(|file| file.path.clone()).collect(),
            languages: meta
                .iter()
                .map(|file| Language::from_path(&file.path))
                .collect(),
            parsed: (0..meta.len()).map(|_| OnceCell::new()).collect(),
            parsers: ParserRegistry::default(),
        }
    }

    fn get(&self, file_index: usize) -> Option<&IndexedFile> {
        let cell = self.parsed.get(file_index)?;
        if cell.get().is_none() {
            let path = self.paths.get(file_index)?;
            let language = *self.languages.get(file_index)?;
            let source = std::fs::read_to_string(path).ok()?;
            let tree = self.parsers.parser_for(language)?.parse(&source).ok()?;
            let _ = cell.set(Box::new(IndexedFile {
                path: path.clone(),
                language,
                tree,
                source,
            }));
        }
        cell.get().map(|file| &**file)
    }
}

impl CodeGraph {
    /// Indexes the given files: extracts symbols and call edges, then resolves
    /// callers and callees against the project's symbols (same file preferred).
    pub fn build(files: Vec<IndexedFile>) -> Self {
        let mut graph = Self {
            files,
            symbols: Vec::new(),
            edges: Vec::new(),
            var_types: Vec::new(),
            hierarchy: Vec::new(),
            imports: Vec::new(),
            namespaces: Vec::new(),
            name_locations: HashMap::new(),
            resolved_by_file_name: HashMap::new(),
            file_index_by_path: HashMap::new(),
            lazy_files: None,
        };
        for (file_index, file) in graph.files.iter().enumerate() {
            collect_symbols(
                file.tree.root(),
                file,
                file_index,
                &mut graph.symbols,
                &mut graph.var_types,
            );
        }
        for (file_index, file) in graph.files.iter().enumerate() {
            collect_hierarchy(file.tree.root(), file, file_index, &mut graph.hierarchy);
            collect_imports(
                file.tree.root(),
                file,
                file_index,
                &mut graph.imports,
                &mut graph.namespaces,
            );
        }
        let mut pending = Vec::new();
        for file in &graph.files {
            collect_edges(file.tree.root(), file, &mut pending);
        }
        // Map caller → symbol index once; a per-call linear scan over all
        // symbols made large projects quadratic in symbol/call counts.
        let mut caller_index: HashMap<(PathBuf, usize, String), usize> = HashMap::new();
        for (index, symbol) in graph.symbols.iter().enumerate() {
            caller_index.insert(
                (symbol.file.clone(), symbol.line, symbol.name.clone()),
                index,
            );
        }
        for call in pending {
            let caller = caller_index
                .get(&(
                    call.caller_file.clone(),
                    call.caller_line,
                    call.caller_name.clone(),
                ))
                .copied();
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

    /// Resolves every edge's callee against the project's symbols, from the
    /// most precise signal to the least: import bindings, namespace bindings,
    /// declared types (with superclass/interface fallback), then simple names
    /// (same file preferred). Resolution reads a snapshot of the index plus
    /// prebuilt lookup tables, so the edges can be mutated in place.
    fn resolve_callees(&mut self) {
        let mut symbols_by_name: HashMap<String, Vec<usize>> = HashMap::new();
        let mut qualified_index: HashMap<String, usize> = HashMap::new();
        let mut symbols_by_file: HashMap<PathBuf, Vec<usize>> = HashMap::new();
        for (index, symbol) in self.symbols.iter().enumerate() {
            symbols_by_name
                .entry(symbol.name.clone())
                .or_default()
                .push(index);
            qualified_index
                .entry(symbol.qualified_name.clone())
                .or_insert(index);
            symbols_by_file
                .entry(symbol.file.clone())
                .or_default()
                .push(index);
        }
        let mut imports_by_file_local: HashMap<(usize, String), (String, String)> = HashMap::new();
        for (file, local, path, original) in &self.imports {
            imports_by_file_local
                .entry((*file, local.clone()))
                .or_insert((path.clone(), original.clone()));
        }
        let mut namespaces_by_file: HashMap<(usize, String), String> = HashMap::new();
        for (file, ns, path) in &self.namespaces {
            namespaces_by_file
                .entry((*file, ns.clone()))
                .or_insert(path.clone());
        }
        let mut var_types_by_file_var: HashMap<(usize, String), Vec<(usize, String)>> =
            HashMap::new();
        for (file, line, variable, ty) in &self.var_types {
            var_types_by_file_var
                .entry((*file, variable.clone()))
                .or_default()
                .push((*line, ty.clone()));
        }
        let mut hierarchy_by_name: HashMap<String, Vec<usize>> = HashMap::new();
        let mut implements_by_name: HashMap<String, Vec<usize>> = HashMap::new();
        for (index, info) in self.hierarchy.iter().enumerate() {
            hierarchy_by_name
                .entry(info.name.clone())
                .or_default()
                .push(index);
            for interface in &info.implements {
                implements_by_name
                    .entry(interface.clone())
                    .or_default()
                    .push(index);
            }
        }
        let file_paths: HashSet<PathBuf> =
            self.files.iter().map(|file| file.path.clone()).collect();
        let mut files_by_parent: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
        for file in &self.files {
            if let Some(parent) = file.path.parent() {
                files_by_parent
                    .entry(parent.to_path_buf())
                    .or_default()
                    .push(file.path.clone());
            }
        }
        let ctx = ResolveCtx {
            symbols: self.symbols.clone(),
            files: &self.files,
            symbols_by_name,
            qualified_index,
            symbols_by_file,
            imports_by_file_local,
            namespaces_by_file,
            var_types_by_file_var,
            hierarchy: self.hierarchy.clone(),
            hierarchy_by_name,
            implements_by_name,
            file_paths,
            files_by_parent,
        };
        for edge in &mut self.edges {
            resolve_edge(edge, &ctx);
        }
        self.finalize_indices();
    }

    /// Builds the derived lookup tables shared by the taint engine: symbol
    /// name locations and resolved callees per (caller file, simple name).
    fn finalize_indices(&mut self) {
        let mut name_locations: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
        for symbol in &self.symbols {
            name_locations
                .entry(symbol.name.clone())
                .or_default()
                .push((symbol.file_index, symbol.start_byte));
        }
        let mut resolved_by_file_name: HashMap<(usize, String), Vec<(usize, usize)>> =
            HashMap::new();
        for edge in &self.edges {
            let caller = &self.symbols[edge.caller];
            let simple = edge
                .callee_text
                .rsplit('.')
                .next()
                .unwrap_or(&edge.callee_text);
            if let Some(callee) = edge.callee {
                let symbol = &self.symbols[callee];
                let entry = resolved_by_file_name
                    .entry((caller.file_index, simple.to_string()))
                    .or_default();
                if !entry.iter().any(|&(file_index, byte)| {
                    file_index == symbol.file_index && byte == symbol.start_byte
                }) {
                    entry.push((symbol.file_index, symbol.start_byte));
                }
            }
        }
        self.name_locations = name_locations;
        self.resolved_by_file_name = resolved_by_file_name;
        self.file_index_by_path = self
            .files
            .iter()
            .enumerate()
            .map(|(index, file)| (file.path.clone(), index))
            .collect();
    }

    /// (file index, declaration byte) of every callee resolved from a call in
    /// `path` — the taint engine's precise cross-file lookup, reusing the
    /// graph's import/type/hierarchy-aware resolution.
    pub fn resolved_callees_for_file(&self, path: &Path, name: &str) -> Vec<(usize, usize)> {
        let Some(&file_index) = self.file_index_by_path.get(path) else {
            return Vec::new();
        };
        self.resolved_by_file_name
            .get(&(file_index, name.to_string()))
            .cloned()
            .unwrap_or_default()
    }

    /// The prebuilt symbol name -> locations table, shared by taint analyses.
    pub fn name_locations(&self) -> &HashMap<String, Vec<(usize, usize)>> {
        &self.name_locations
    }

    /// The parsed file at `file_index`, re-parsing it on demand when the
    /// graph was restored from a snapshot (its trees are not loaded).
    pub fn indexed_file(&self, file_index: usize) -> Option<&IndexedFile> {
        match &self.lazy_files {
            None => self.files.get(file_index),
            Some(lazy) => lazy.get(file_index),
        }
    }
}

/// A serializable, tree-less representation of the architecture index plus the
/// file identity list it was built from. Saved after a full build and restored
/// on scans where every file's hash matches, skipping parsing and re-indexing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSnapshot {
    /// Cache namespace (schema + rule-pack identity); mismatches reject the
    /// snapshot at load time.
    pub schema: String,
    /// Every scanned file's path and content hash, in discovery order.
    pub files: Vec<GraphFileMeta>,
    pub symbols: Vec<GraphSymbol>,
    pub edges: Vec<CallEdge>,
    pub var_types: Vec<(usize, usize, String, String)>,
    pub hierarchy: Vec<ClassInfo>,
    pub imports: Vec<(usize, String, String, String)>,
    pub namespaces: Vec<(usize, String, String)>,
}

/// Identity of one scanned file inside a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphFileMeta {
    pub path: PathBuf,
    pub hash: String,
}

impl GraphSnapshot {
    /// Whether every hashable file in `files` (path + hash) matches this
    /// snapshot, and the snapshot has no extra files. Files without a hash
    /// (read errors, oversized) do not constrain the match — they cannot be
    /// represented in the snapshot and must not force a rebuild every scan.
    pub fn matches(&self, files: &[(&Path, Option<&str>)]) -> bool {
        let known: HashMap<String, &str> = self
            .files
            .iter()
            .map(|file| (file.path.to_string_lossy().into_owned(), file.hash.as_str()))
            .collect();
        let mut matched = 0usize;
        for (path, hash) in files {
            let Some(hash) = hash else { continue };
            let key = path.to_string_lossy().into_owned();
            match known.get(&key) {
                Some(known_hash) if *known_hash == *hash => matched += 1,
                _ => return false,
            }
        }
        matched == known.len()
    }
}

impl CodeGraph {
    /// Restores a graph from a snapshot: symbols/edges are taken as-is; file
    /// trees are not loaded and are re-parsed on demand by the taint engine.
    pub fn from_snapshot(snapshot: &GraphSnapshot) -> Self {
        let placeholder = SyntaxTree::placeholder();
        let files = snapshot
            .files
            .iter()
            .map(|file| IndexedFile {
                path: file.path.clone(),
                language: Language::from_path(&file.path),
                tree: placeholder.clone(),
                source: String::new(),
            })
            .collect();
        let mut graph = Self {
            files,
            symbols: snapshot.symbols.clone(),
            edges: snapshot.edges.clone(),
            var_types: snapshot.var_types.clone(),
            hierarchy: snapshot.hierarchy.clone(),
            imports: snapshot.imports.clone(),
            namespaces: snapshot.namespaces.clone(),
            name_locations: HashMap::new(),
            resolved_by_file_name: HashMap::new(),
            file_index_by_path: HashMap::new(),
            lazy_files: Some(LazyFiles::new(&snapshot.files)),
        };
        graph.finalize_indices();
        graph
    }

    /// The serializable index data with the scan's file identities attached
    /// (`schema` is set by the cache, which owns the namespace).
    pub fn snapshot_with(&self, files: Vec<GraphFileMeta>) -> GraphSnapshot {
        GraphSnapshot {
            schema: String::new(),
            files,
            symbols: self.symbols.clone(),
            edges: self.edges.clone(),
            var_types: self.var_types.clone(),
            hierarchy: self.hierarchy.clone(),
            imports: self.imports.clone(),
            namespaces: self.namespaces.clone(),
        }
    }
}
