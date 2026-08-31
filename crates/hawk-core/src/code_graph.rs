//! Project-wide architecture index: symbols (functions/methods) and the call
//! edges between them, built from the parsed files of a scan.
//!
//! The graph answers structural questions a single-file scan cannot: which
//! functions are actually reachable from callers, where a callee is defined,
//! and — via the taint engine's `analyze_with_graph` — whether tainted data
//! crosses file boundaries along real call chains (handler → service →
//! repository → sink).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

use crate::{
    ast::AstNode,
    language::Language,
    parser::{ParserRegistry, SyntaxTree},
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

/// Immutable snapshot of the index used during edge resolution, plus the
/// lookup tables that turn the O(E × symbols) scans into O(1) probes.
struct ResolveCtx<'a> {
    symbols: Vec<GraphSymbol>,
    files: &'a [IndexedFile],
    /// simple symbol name -> symbol indices (in symbol order)
    symbols_by_name: HashMap<String, Vec<usize>>,
    /// qualified name -> first symbol index
    qualified_index: HashMap<String, usize>,
    /// file -> symbol indices
    symbols_by_file: HashMap<PathBuf, Vec<usize>>,
    /// (file index, local name) -> (imported path, original name)
    imports_by_file_local: HashMap<(usize, String), (String, String)>,
    /// (file index, namespace) -> imported path
    namespaces_by_file: HashMap<(usize, String), String>,
    /// (file index, variable) -> [(declaration line, declared type)]
    var_types_by_file_var: HashMap<(usize, String), Vec<(usize, String)>>,
    hierarchy: Vec<ClassInfo>,
    /// class name -> hierarchy indices
    hierarchy_by_name: HashMap<String, Vec<usize>>,
    /// interface name -> hierarchy indices of implementing classes
    implements_by_name: HashMap<String, Vec<usize>>,
    file_paths: HashSet<PathBuf>,
    /// parent directory -> paths (for import stem fallback)
    files_by_parent: HashMap<PathBuf, Vec<PathBuf>>,
}

fn resolve_edge(edge: &mut CallEdge, ctx: &ResolveCtx<'_>) {
    let caller_symbol = &ctx.symbols[edge.caller];
    let caller_file = caller_symbol.file.clone();
    let caller_file_index = caller_symbol.file_index;
    let caller_line = caller_symbol.line;

    // 1) Import-guided: `deleteUser(x)` with
    //    `import { deleteUser } from "./UserService"`.
    if !edge.callee_text.contains('.') {
        if let Some((path, original)) = ctx
            .imports_by_file_local
            .get(&(caller_file_index, edge.callee_text.clone()))
        {
            if let Some(target_path) = resolve_import_target(ctx, &caller_file, path) {
                // The imported symbol keeps its original name when
                // aliased (`helper as h` binds the local `h`).
                if let Some(index) = symbol_in_file(ctx, target_path, original)
                    .or_else(|| symbol_in_file(ctx, target_path, &edge.callee_text))
                {
                    edge.callee = Some(index);
                    return;
                }
            }
        }
    }
    // 2) Namespace-guided: `ns.method(...)` with `import * as ns`.
    if let Some((namespace, method)) = edge.callee_text.split_once('.') {
        if let Some(path) = ctx
            .namespaces_by_file
            .get(&(caller_file_index, namespace.to_string()))
        {
            if let Some(target_path) = resolve_import_target(ctx, &caller_file, path) {
                if let Some(index) = symbol_in_file(ctx, target_path, method) {
                    edge.callee = Some(index);
                    return;
                }
            }
        }
    }
    // 3) Type-guided: `service.deleteUser` where `service` is typed
    //    `UserService` — exact, then superclass chain, then interface
    //    methods, then implementations of an interface-typed variable.
    if let Some((var, method)) = edge.callee_text.split_once('.') {
        let mut resolved = None;
        if let Some(typed) = ctx
            .var_types_by_file_var
            .get(&(caller_file_index, var.to_string()))
        {
            for (line, ty) in typed {
                if *line == caller_line || *line == 0 {
                    resolved = resolve_typed(ctx, ty, method, caller_file_index);
                    if resolved.is_some() {
                        break;
                    }
                }
            }
        }
        if let Some(index) = resolved {
            edge.callee = Some(index);
            return;
        }
    }
    // 4) Fallback: qualified-name and simple-name matching. A symbol can only
    //    match when its simple name is the callee's last segment, so the scan
    //    is bounded to that candidate set (same-file preferred, in symbol
    //    order — identical semantics to a full scan).
    let simple = edge
        .callee_text
        .rsplit('.')
        .next()
        .unwrap_or(&edge.callee_text);
    let mut same_file = None;
    let mut any = None;
    if let Some(candidates) = ctx.symbols_by_name.get(simple) {
        for &index in candidates {
            let symbol = &ctx.symbols[index];
            // `name == simple` deliberately matches every candidate: the
            // fallback resolves by the callee's last segment (loose by design,
            // same-file preferred), matching the pre-index behavior.
            let matches = symbol.qualified_name == edge.callee_text
                || symbol.name == edge.callee_text
                || symbol
                    .qualified_name
                    .ends_with(&format!(".{}", edge.callee_text))
                || symbol.name == *simple;
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
    }
    edge.callee = same_file.or(any);
}

/// Resolves `T.method` through the hierarchy: exact, then the extends chain,
/// then implemented interfaces, then — when `T` is an interface — classes
/// implementing it.
fn resolve_typed(
    ctx: &ResolveCtx<'_>,
    ty: &str,
    method: &str,
    caller_file: usize,
) -> Option<usize> {
    let exact = |name: &str| {
        ctx.qualified_index
            .get(&format!("{}.{}", name, method))
            .copied()
    };
    if let Some(index) = exact(ty) {
        // An interface/abstract declaration has no body; prefer a concrete
        // implementation so taint can follow the real code.
        if symbol_has_body(ctx, index) {
            return Some(index);
        }
    }
    let mut visited = std::collections::HashSet::new();
    let mut current = Some(ty.to_string());
    while let Some(class) = current {
        if !visited.insert(class.clone()) {
            break;
        }
        let info = ctx.hierarchy_by_name.get(&class).and_then(|indices| {
            indices.iter().find(|&&info_index| {
                let info = &ctx.hierarchy[info_index];
                info.file_index == caller_file
                    || !indices
                        .iter()
                        .any(|&other| ctx.hierarchy[other].file_index == caller_file)
            })
        });
        let Some(&info_index) = info else { break };
        let info = &ctx.hierarchy[info_index];
        if let Some(superclass) = &info.extends {
            if let Some(index) = exact(superclass) {
                return Some(index);
            }
            current = Some(superclass.clone());
        } else {
            current = None;
        }
        for interface in &info.implements {
            if let Some(index) = exact(interface) {
                return Some(index);
            }
        }
    }
    // Interface-typed receiver: any class implementing the interface.
    find_implementation(ctx, ty, method, &mut std::collections::HashSet::new())
}

/// First class implementing `interface` whose own hierarchy defines `method`
/// (directly or inherited).
fn find_implementation(
    ctx: &ResolveCtx<'_>,
    interface: &str,
    method: &str,
    visited: &mut std::collections::HashSet<String>,
) -> Option<usize> {
    if !visited.insert(interface.to_string()) {
        return None; // cyclic hierarchy guard
    }
    for &info_index in ctx.implements_by_name.get(interface).into_iter().flatten() {
        let info = &ctx.hierarchy[info_index];
        let direct = ctx
            .qualified_index
            .get(&format!("{}.{}", info.name, method))
            .copied();
        if direct.is_some() {
            return direct;
        }
        if let Some(superclass) = &info.extends {
            if let Some(index) = resolve_typed(ctx, superclass, method, info.file_index) {
                return Some(index);
            }
        }
    }
    None
}

/// Whether the symbol's declaration carries a body (interface/abstract
/// methods do not, and are not useful taint targets).
fn symbol_has_body(ctx: &ResolveCtx<'_>, index: usize) -> bool {
    let symbol = &ctx.symbols[index];
    let Some(file) = ctx.files.get(symbol.file_index) else {
        return false;
    };
    let Some(node) = file.method_node_at_byte(symbol.start_byte) else {
        return false;
    };
    node.children()
        .any(|child| matches!(child.kind(), "block" | "statement_block"))
}

/// The symbol with `name` declared in the file at `path` (prefers the
/// qualified form `Class.name` when the class is visible).
fn symbol_in_file(ctx: &ResolveCtx<'_>, path: &Path, name: &str) -> Option<usize> {
    let suffix = format!(".{}", name);
    ctx.symbols_by_file
        .get(path)
        .into_iter()
        .flatten()
        .copied()
        .find(|&index| {
            let symbol = &ctx.symbols[index];
            symbol.name == name || symbol.qualified_name.ends_with(&suffix)
        })
}

/// Maps an import path to a scanned file: exact relative path with common
/// extensions, index files, then a stem match within the caller directory.
fn resolve_import_target<'a>(
    ctx: &'a ResolveCtx<'_>,
    caller_path: &Path,
    import_path: &str,
) -> Option<&'a PathBuf> {
    let parent = caller_path.parent()?;
    let mut candidates = Vec::new();
    if Path::new(import_path).extension().is_some() {
        candidates.push(PathBuf::from(import_path));
    } else {
        for extension in [
            "ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs", "py", "pyw",
        ] {
            candidates.push(PathBuf::from(format!("{import_path}.{extension}")));
            candidates.push(PathBuf::from(format!("{import_path}/index.{extension}")));
        }
    }
    for candidate in candidates {
        let full = parent.join(candidate);
        if let Some(path) = ctx.file_paths.get(&full) {
            return Some(path);
        }
    }
    let stem = Path::new(import_path)
        .file_stem()?
        .to_string_lossy()
        .to_string();
    ctx.files_by_parent
        .get(parent)
        .into_iter()
        .flatten()
        .find(|path| {
            path.file_stem()
                .is_some_and(|candidate| candidate == stem.as_str())
        })
}

fn collect_symbols(
    root: AstNode<'_>,
    file: &IndexedFile,
    file_index: usize,
    out: &mut Vec<GraphSymbol>,
    var_types: &mut Vec<(usize, usize, String, String)>,
) {
    fn visit(
        node: AstNode<'_>,
        file: &IndexedFile,
        file_index: usize,
        out: &mut Vec<GraphSymbol>,
        var_types: &mut Vec<(usize, usize, String, String)>,
    ) {
        if method_like_kinds(file.language).contains(&node.kind()) {
            let line = node.start_position().row + 1;
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
                    line,
                    start_byte: node.start_byte(),
                    language: file.language,
                });
            }
            collect_typed_vars(node, file, file_index, line, var_types);
            return; // do not descend into nested functions for symbols
        }
        // Class-level fields are visible from every method of the class.
        if file.language == Language::Java && node.kind() == "field_declaration" {
            collect_typed_vars(node, file, file_index, 0, var_types);
        }
        for child in node.children() {
            visit(child, file, file_index, out, var_types);
        }
    }
    visit(root, file, file_index, out, var_types);
}

/// Records the declared types of parameters and local variables inside a
/// method (Java `UserService service`, TypeScript `service: UserService`),
/// scoped to the enclosing method line.
fn collect_typed_vars(
    method: AstNode<'_>,
    file: &IndexedFile,
    file_index: usize,
    line: usize,
    var_types: &mut Vec<(usize, usize, String, String)>,
) {
    if !matches!(file.language, Language::Java | Language::TypeScript) {
        return;
    }
    let mut push = |node: AstNode<'_>, source: &str| {
        let Some(ty) = node
            .child_by_field_name("type")
            .and_then(|ty| ty.text(source))
            .map(type_name)
        else {
            return;
        };
        let name = node
            .child_by_field_name("name")
            .or_else(|| {
                node.child_by_field_name("pattern")
                    .and_then(|pattern| pattern.child_by_field_name("name"))
            })
            .and_then(|name| name.text(source))
            .map(String::from);
        if let Some(name) = name {
            var_types.push((file_index, line, name, ty));
        }
    };
    // Parameters: formal_parameter (Java), typed_parameter (TypeScript).
    if let Some(parameters) = method.child_by_field_name("parameters") {
        for param in parameters.children() {
            if matches!(
                param.kind(),
                "formal_parameter"
                    | "typed_parameter"
                    | "typed_default_parameter"
                    | "required_parameter"
            ) {
                push(param, &file.source);
            }
        }
    }
    // Local declarations and (for Java) class fields: variable_declarator
    // exposes the `type` on its declaration/field parent.
    for child in method.children() {
        if matches!(
            child.kind(),
            "local_variable_declaration" | "field_declaration" | "variable_declaration"
        ) {
            push(child, &file.source);
        }
    }
}

/// `java.util.List<User>` → `List`; `UserService` stays as-is.
fn type_name(text: &str) -> String {
    let simple = text.rsplit('.').next().unwrap_or(text);
    simple
        .split('<')
        .next()
        .unwrap_or(simple)
        .trim()
        .to_string()
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

/// Records `class X extends Y implements A, B` facts (Java and TypeScript)
/// for type-guided callee resolution.
fn collect_hierarchy(
    root: AstNode<'_>,
    file: &IndexedFile,
    file_index: usize,
    out: &mut Vec<ClassInfo>,
) {
    fn visit(node: AstNode<'_>, file: &IndexedFile, file_index: usize, out: &mut Vec<ClassInfo>) {
        if node.kind() == "class_declaration" {
            let Some(name) = node
                .child_by_field_name("name")
                .and_then(|name| name.text(&file.source))
                .map(String::from)
            else {
                return;
            };
            let mut extends = None;
            let mut implements = Vec::new();
            match file.language {
                Language::Java => {
                    extends = node
                        .child_by_field_name("superclass")
                        .and_then(|superclass| superclass.text(&file.source))
                        .map(type_name);
                    if let Some(interfaces) = node.child_by_field_name("interfaces") {
                        for interface in interfaces.children() {
                            if let Some(text) = interface.text(&file.source).map(type_name) {
                                implements.push(text);
                            }
                        }
                    }
                }
                Language::TypeScript => {
                    if let Some(heritage) = node.child_by_field_name("class_heritage") {
                        for clause in heritage.children() {
                            match clause.kind() {
                                "extends_clause" => {
                                    extends = clause
                                        .children()
                                        .find_map(|child| child.text(&file.source).map(type_name));
                                }
                                "implements_clause" => {
                                    for child in clause.children() {
                                        if let Some(text) = child.text(&file.source).map(type_name)
                                        {
                                            implements.push(text);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
            out.push(ClassInfo {
                file_index,
                name,
                extends,
                implements,
            });
            return; // nested classes are not tracked
        }
        for child in node.children() {
            visit(child, file, file_index, out);
        }
    }
    visit(root, file, file_index, out);
}

/// Records import bindings: `import { a } from "p"` / `import a from "p"`
/// (JS/TS), `from p import a, b` (Python). Namespace imports
/// (`import * as ns`) and Python module imports (`import mod`) go to the
/// namespace list so `ns.func(...)` / `mod.func(...)` calls resolve.
fn collect_imports(
    root: AstNode<'_>,
    file: &IndexedFile,
    file_index: usize,
    imports: &mut Vec<(usize, String, String, String)>,
    namespaces: &mut Vec<(usize, String, String)>,
) {
    fn visit(
        node: AstNode<'_>,
        file: &IndexedFile,
        file_index: usize,
        imports: &mut Vec<(usize, String, String, String)>,
        namespaces: &mut Vec<(usize, String, String)>,
    ) {
        match file.language {
            Language::JavaScript | Language::TypeScript => {
                if node.kind() == "import_statement" {
                    let Some(source) = node
                        .child_by_field_name("source")
                        .and_then(|source| source.text(&file.source))
                        .map(|text| text.trim_matches('"').trim_matches('\'').to_string())
                    else {
                        return; // side-effect import
                    };
                    let clause = node.child_by_field_name("import_clause").or_else(|| {
                        node.children()
                            .find(|child| child.kind() == "import_clause")
                    });
                    if let Some(clause) = clause {
                        for child in clause.children() {
                            match child.kind() {
                                "identifier" => {
                                    if let Some(name) = child.text(&file.source) {
                                        imports.push((
                                            file_index,
                                            name.to_string(),
                                            source.clone(),
                                            name.to_string(),
                                        ));
                                    }
                                }
                                "namespace_import" => {
                                    if let Some(name) = child
                                        .children()
                                        .find(|c| c.kind() == "identifier")
                                        .and_then(|c| c.text(&file.source))
                                    {
                                        namespaces.push((
                                            file_index,
                                            name.to_string(),
                                            source.clone(),
                                        ));
                                    }
                                }
                                "named_imports" => {
                                    for specifier in child.children() {
                                        if specifier.kind() != "import_specifier" {
                                            continue;
                                        }
                                        let name = specifier
                                            .child_by_field_name("name")
                                            .and_then(|n| n.text(&file.source))
                                            .map(String::from);
                                        let alias = specifier
                                            .child_by_field_name("alias")
                                            .and_then(|n| n.text(&file.source))
                                            .map(String::from);
                                        if let Some(name) = name {
                                            let original = name.clone();
                                            imports.push((
                                                file_index,
                                                alias.unwrap_or(name),
                                                source.clone(),
                                                original,
                                            ));
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            Language::Python => match node.kind() {
                "import_from_statement" => {
                    let module = node
                        .child_by_field_name("module_name")
                        .and_then(|module| module.text(&file.source))
                        .map(|text| text.to_string());
                    let name = node.child_by_field_name("name");
                    let mut names = Vec::new();
                    if let Some(name) = name {
                        match name.kind() {
                            "import_list" => {
                                for child in name.children() {
                                    if child.kind() == "aliased_import" {
                                        if let Some(alias) = child
                                            .child_by_field_name("alias")
                                            .and_then(|a| a.text(&file.source))
                                        {
                                            names.push(alias.to_string());
                                        }
                                    } else if let Some(text) = child.text(&file.source) {
                                        names.push(text.to_string());
                                    }
                                }
                            }
                            "aliased_import" => {
                                if let Some(alias) = name
                                    .child_by_field_name("alias")
                                    .and_then(|a| a.text(&file.source))
                                {
                                    names.push(alias.to_string());
                                }
                            }
                            _ => {
                                if let Some(text) = name.text(&file.source) {
                                    names.push(text.to_string());
                                }
                            }
                        }
                    }
                    if let Some(module) = module {
                        for name in names {
                            let original = name.clone();
                            imports.push((file_index, name, module.clone(), original));
                        }
                    }
                }
                "import_statement" => {
                    if let Some(module) = node
                        .children()
                        .find(|child| child.kind() == "dotted_name")
                        .and_then(|child| child.text(&file.source))
                    {
                        // `import mod` → `mod.func(...)` resolves by module stem.
                        namespaces.push((file_index, module.to_string(), module.to_string()));
                    }
                }
                _ => {}
            },
            _ => {}
        }
        for child in node.children() {
            visit(child, file, file_index, imports, namespaces);
        }
    }
    visit(root, file, file_index, imports, namespaces);
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
    fn type_guided_resolution_distinguishes_same_named_methods() {
        let graph = CodeGraph::build(vec![indexed(
            "App.java",
            Language::Java,
            r#"
class A {
    void handle(B b, C c) {
        b.run();
        c.run();
    }
}
class B { void run() {} }
class C { void run() {} }
"#,
        )]);
        let b_edge = graph
            .edges
            .iter()
            .find(|edge| edge.callee_text == "b.run")
            .expect("b.run edge");
        assert_eq!(
            graph.symbols[b_edge.callee.unwrap()].qualified_name,
            "B.run",
            "parameter type B must guide resolution"
        );
        let c_edge = graph
            .edges
            .iter()
            .find(|edge| edge.callee_text == "c.run")
            .expect("c.run edge");
        assert_eq!(
            graph.symbols[c_edge.callee.unwrap()].qualified_name,
            "C.run",
            "parameter type C must guide resolution"
        );
    }

    #[test]
    fn hierarchy_resolution_finds_inherited_and_implemented_methods() {
        let graph = CodeGraph::build(vec![indexed(
            "App.java",
            Language::Java,
            r#"
class Base {
    void inherited() {}
}
class Impl extends Base implements Service {
    void own() {}
}
interface Service {
    void contract();
}
class ServiceImpl implements Service {
    void contract() {}
}
class User {
    void handle(Impl impl, Service svc) {
        impl.inherited();
        impl.own();
        svc.contract();
    }
}
"#,
        )]);
        let edge = |text: &str| {
            graph
                .edges
                .iter()
                .find(|edge| edge.callee_text == text)
                .expect(text)
        };
        // inherited via extends chain
        assert_eq!(
            graph.symbols[edge("impl.inherited").callee.unwrap()].qualified_name,
            "Base.inherited"
        );
        // own method stays direct
        assert_eq!(
            graph.symbols[edge("impl.own").callee.unwrap()].qualified_name,
            "Impl.own"
        );
        // interface-typed variable resolves to an implementing class
        assert_eq!(
            graph.symbols[edge("svc.contract").callee.unwrap()].qualified_name,
            "ServiceImpl.contract"
        );
    }

    #[test]
    fn import_resolution_binds_calls_to_imported_files() {
        let graph = CodeGraph::build(vec![
            indexed(
                "handler.ts",
                Language::TypeScript,
                r#"
import { deleteUser, helper as h } from "./UserService";
import * as api from "./Api";
export function handle(id: string) {
    deleteUser(id);
    h(id);
    api.lookup(id);
}
"#,
            ),
            indexed(
                "UserService.ts",
                Language::TypeScript,
                "export function deleteUser(id: string) {}
export function helper(id: string) {}
",
            ),
            indexed(
                "Api.ts",
                Language::TypeScript,
                "export function lookup(id: string) {}
",
            ),
        ]);
        let edge = |text: &str| {
            graph
                .edges
                .iter()
                .find(|edge| edge.callee_text == text)
                .expect(text)
        };
        assert_eq!(
            graph.symbols[edge("deleteUser").callee.unwrap()].qualified_name,
            "deleteUser"
        );
        assert_eq!(
            graph.symbols[edge("deleteUser").callee.unwrap()].file,
            PathBuf::from("UserService.ts")
        );
        // aliased import binds to the original name
        assert_eq!(
            graph.symbols[edge("h").callee.unwrap()].file,
            PathBuf::from("UserService.ts")
        );
        // namespace call resolves into the imported file
        assert_eq!(
            graph.symbols[edge("api.lookup").callee.unwrap()].file,
            PathBuf::from("Api.ts")
        );
    }

    #[test]
    fn python_from_import_resolves_cross_file_calls() {
        let graph = CodeGraph::build(vec![
            indexed(
                "views.py",
                Language::Python,
                "from user_service import delete_user

def view():
    delete_user(user_id)
",
            ),
            indexed(
                "user_service.py",
                Language::Python,
                "def delete_user(user_id):
    pass
",
            ),
        ]);
        let edge = graph
            .edges
            .iter()
            .find(|edge| edge.callee_text == "delete_user")
            .expect("delete_user edge");
        assert_eq!(
            graph.symbols[edge.callee.unwrap()].file,
            PathBuf::from("user_service.py")
        );
    }

    #[test]
    fn snapshot_round_trip_preserves_symbols_edges_and_resolution() {
        let files = vec![
            indexed(
                "Controller.java",
                Language::Java,
                r#"
class Controller {
    void handle(UserService service) {
        service.deleteUser("x");
    }
}
"#,
            ),
            indexed(
                "UserService.java",
                Language::Java,
                r#"
class UserService {
    void deleteUser(String id) {}
}
"#,
            ),
        ];
        let graph = CodeGraph::build(files);
        let snapshot = GraphSnapshot {
            schema: "test".into(),
            files: vec![
                GraphFileMeta {
                    path: PathBuf::from("Controller.java"),
                    hash: "h1".into(),
                },
                GraphFileMeta {
                    path: PathBuf::from("UserService.java"),
                    hash: "h2".into(),
                },
            ],
            symbols: graph.symbols.clone(),
            edges: graph.edges.clone(),
            var_types: graph.var_types.clone(),
            hierarchy: graph.hierarchy.clone(),
            imports: graph.imports.clone(),
            namespaces: graph.namespaces.clone(),
        };

        assert!(snapshot.matches(&[
            (Path::new("Controller.java"), Some("h1")),
            (Path::new("UserService.java"), Some("h2")),
        ]));
        assert!(!snapshot.matches(&[
            (Path::new("Controller.java"), Some("h1")),
            (Path::new("UserService.java"), Some("h2-changed")),
        ]));
        assert!(!snapshot.matches(&[(Path::new("Controller.java"), Some("h1"))]));

        let restored = CodeGraph::from_snapshot(&snapshot);
        assert_eq!(restored.symbols.len(), graph.symbols.len());
        assert_eq!(restored.edges.len(), graph.edges.len());
        assert_eq!(
            restored.resolved_callees_for_file(Path::new("Controller.java"), "deleteUser"),
            graph.resolved_callees_for_file(Path::new("Controller.java"), "deleteUser"),
        );
        // Placeholder files exist for display, but carry no tree.
        assert_eq!(restored.files.len(), 2);
    }

    #[test]
    fn snapshot_restore_reparses_callees_on_demand() {
        // Lazy parse: the restored graph has no trees; requesting a callee
        // body reads the file from disk and parses it on first use.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "hawk-graph-lazy-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let controller = dir.join("Controller.java");
        let service = dir.join("UserService.java");
        std::fs::write(
            &controller,
            "class Controller { void handle(UserService s) { s.deleteUser(); } }",
        )
        .unwrap();
        std::fs::write(&service, "class UserService { void deleteUser() {} }").unwrap();

        let graph = CodeGraph::build(vec![
            indexed(
                controller.to_str().unwrap(),
                Language::Java,
                "class Controller { void handle(UserService s) { s.deleteUser(); } }",
            ),
            indexed(
                service.to_str().unwrap(),
                Language::Java,
                "class UserService { void deleteUser() {} }",
            ),
        ]);
        let snapshot = GraphSnapshot {
            schema: "test".into(),
            files: vec![
                GraphFileMeta {
                    path: controller.clone(),
                    hash: "h1".into(),
                },
                GraphFileMeta {
                    path: service.clone(),
                    hash: "h2".into(),
                },
            ],
            symbols: graph.symbols.clone(),
            edges: graph.edges.clone(),
            var_types: graph.var_types.clone(),
            hierarchy: graph.hierarchy.clone(),
            imports: graph.imports.clone(),
            namespaces: graph.namespaces.clone(),
        };
        let restored = CodeGraph::from_snapshot(&snapshot);

        let delete_user = restored
            .symbols
            .iter()
            .find(|symbol| symbol.name == "deleteUser")
            .expect("deleteUser symbol");
        let file = restored
            .indexed_file(delete_user.file_index)
            .expect("lazy parse must load the file");
        assert_eq!(file.path, service);
        assert!(
            file.method_node_at_byte(delete_user.start_byte).is_some(),
            "callee must be re-located from the lazily parsed tree"
        );
        assert!(restored.indexed_file(99).is_none(), "out-of-range index");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
