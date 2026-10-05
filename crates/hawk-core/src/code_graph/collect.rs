use std::path::PathBuf;

use crate::{
    ast::AstNode,
    language::Language,
    taint_engine::{call_kinds, method_like_kinds, parse_call},
};

use super::{ClassInfo, GraphSymbol, IndexedFile, PendingCall, SymbolKind};

pub(crate) fn collect_symbols(
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
    if !matches!(
        file.language,
        Language::Java | Language::TypeScript | Language::Tsx
    ) {
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
pub(crate) fn collect_hierarchy(
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
                Language::TypeScript | Language::Tsx => {
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
pub(crate) fn collect_imports(
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
            Language::JavaScript | Language::TypeScript | Language::Tsx => {
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

pub(crate) fn collect_edges(root: AstNode<'_>, file: &IndexedFile, out: &mut Vec<PendingCall>) {
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
