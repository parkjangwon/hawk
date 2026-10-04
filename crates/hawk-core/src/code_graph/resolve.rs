use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use super::{CallEdge, ClassInfo, GraphSymbol, IndexedFile};

pub(crate) struct ResolveCtx<'a> {
    pub(crate) symbols: Vec<GraphSymbol>,
    pub(crate) files: &'a [IndexedFile],
    /// simple symbol name -> symbol indices (in symbol order)
    pub(crate) symbols_by_name: HashMap<String, Vec<usize>>,
    /// qualified name -> first symbol index
    pub(crate) qualified_index: HashMap<String, usize>,
    /// file -> symbol indices
    pub(crate) symbols_by_file: HashMap<PathBuf, Vec<usize>>,
    /// (file index, local name) -> (imported path, original name)
    pub(crate) imports_by_file_local: HashMap<(usize, String), (String, String)>,
    /// (file index, namespace) -> imported path
    pub(crate) namespaces_by_file: HashMap<(usize, String), String>,
    /// (file index, variable) -> [(declaration line, declared type)]
    pub(crate) var_types_by_file_var: HashMap<(usize, String), Vec<(usize, String)>>,
    pub(crate) hierarchy: Vec<ClassInfo>,
    /// class name -> hierarchy indices
    pub(crate) hierarchy_by_name: HashMap<String, Vec<usize>>,
    /// interface name -> hierarchy indices of implementing classes
    pub(crate) implements_by_name: HashMap<String, Vec<usize>>,
    pub(crate) file_paths: HashSet<PathBuf>,
    /// parent directory -> paths (for import stem fallback)
    pub(crate) files_by_parent: HashMap<PathBuf, Vec<PathBuf>>,
}

pub(crate) fn resolve_edge(edge: &mut CallEdge, ctx: &ResolveCtx<'_>) {
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
