//! Intraprocedural and intra-file interprocedural taint analysis for Java.
//!
//! The engine tracks tainted values from sources to sinks in source order,
//! binds caller arguments to callee parameters, and follows same-file method
//! return values. With a [`CodeGraph`], callee resolution extends across the
//! whole scanned project: a call into another file is analyzed against that
//! file's definition, and a tainted call whose callee body reaches a sink is
//! reported at the call site (handler → service → repository scenarios).
//! The public finding conversion lives in `taint.rs`.

use std::collections::{HashMap, HashSet};

use crate::{
    ast::AstNode,
    code_graph::CodeGraph,
    language::Language,
    parser::SyntaxTree,
    taint::{TaintConfig, TaintFinding},
};

/// Runs the engine over a syntax tree for the given language. Returns taint
/// findings in source order.
pub fn analyze(
    tree: &SyntaxTree,
    source: &str,
    config: &TaintConfig,
    language: Language,
) -> Vec<TaintFinding> {
    analyze_with_graph(tree, source, config, language, None, None)
}

/// `analyze`, with cross-file callee resolution via the project's code graph.
/// `path` is the analyzed file's path; it lets the engine reuse the graph's
/// import/type/hierarchy-aware edge resolution for calls in this file.
pub fn analyze_with_graph(
    tree: &SyntaxTree,
    source: &str,
    config: &TaintConfig,
    language: Language,
    graph: Option<&CodeGraph>,
    path: Option<&std::path::Path>,
) -> Vec<TaintFinding> {
    if config.sources.is_empty() || config.sinks.is_empty() {
        return Vec::new();
    }
    let mut state = State::new(source, config, language, graph, path);
    state.collect_methods(tree.root());
    state.walk(tree.root());
    // Nested sink calls (e.g. an outer router.get(...) whose arrow-function
    // argument contains an inner insertAdjacentHTML(...)) would both match the
    // sink text. Keep only the innermost finding for overlapping spans.
    let findings = state.findings.clone();
    state.findings.retain(|finding| {
        !findings.iter().any(|other| {
            other.start_byte >= finding.start_byte
                && other.end_byte <= finding.end_byte
                && (other.start_byte != finding.start_byte || other.end_byte != finding.end_byte)
        })
    });
    state.findings
}

/// Java entry point kept for compatibility with existing callers.
pub fn analyze_java(tree: &SyntaxTree, source: &str, config: &TaintConfig) -> Vec<TaintFinding> {
    analyze(tree, source, config, Language::Java)
}

pub(crate) fn method_like_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::Java => &["method_declaration", "constructor_declaration"],
        Language::JavaScript | Language::TypeScript => &[
            "function_declaration",
            "function_expression",
            "arrow_function",
            "method_definition",
        ],
        Language::Python => &["function_definition"],
        Language::Go => &["function_declaration", "method_declaration"],
        Language::Unknown => &[],
    }
}

fn declaration_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::JavaScript | Language::TypeScript => {
            &["lexical_declaration", "variable_declaration"]
        }
        Language::Go => &["var_spec"],
        _ => &["local_variable_declaration"],
    }
}

fn assignment_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::Python => &["assignment"],
        Language::Go => &["assignment_statement", "short_var_declaration"],
        _ => &["assignment_expression"],
    }
}

fn loop_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::Java => &[
            "while_statement",
            "do_statement",
            "for_statement",
            "enhanced_for_statement",
        ],
        Language::JavaScript | Language::TypeScript => &[
            "while_statement",
            "do_statement",
            "for_statement",
            "for_in_statement",
        ],
        Language::Python => &["while_statement", "for_statement"],
        Language::Go => &["for_statement"],
        Language::Unknown => &[],
    }
}

pub(crate) fn call_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::Java => &["method_invocation", "object_creation_expression"],
        Language::JavaScript | Language::TypeScript => &["call_expression"],
        Language::Python => &["call"],
        Language::Go => &["call_expression"],
        Language::Unknown => &[],
    }
}

/// A callee definition available to the engine: its declaration node plus the
/// source text of the file it lives in (needed for cross-file analysis).
type Callee<'a> = (AstNode<'a>, &'a str);

struct State<'a> {
    source: &'a str,
    config: &'a TaintConfig,
    language: Language,
    /// The project-wide code graph for cross-file callee resolution.
    graph: Option<&'a CodeGraph>,
    /// The analyzed file's path, for reusing graph edge resolution.
    path: Option<&'a std::path::Path>,
    /// callee name → declaration lines per file, from the graph's symbols.
    name_locations: HashMap<String, Vec<(usize, usize)>>,
    /// (file index, line) → re-located callee node, memoized per analysis.
    node_cache: HashMap<(usize, usize), Option<AstNode<'a>>>,
    tainted: HashSet<String>,
    /// Variables assigned since the current branch/loop scope began. Used by
    /// the branch join to distinguish "reassigned clean" from "never touched".
    touched: HashSet<String>,
    findings: Vec<TaintFinding>,
    /// Functions declared in the analyzed file, keyed by name. Enables
    /// intra-file interprocedural taint propagation of return values.
    methods: HashMap<String, Vec<Callee<'a>>>,
}

impl<'a> State<'a> {
    fn new(
        source: &'a str,
        config: &'a TaintConfig,
        language: Language,
        graph: Option<&'a CodeGraph>,
        path: Option<&'a std::path::Path>,
    ) -> Self {
        let mut name_locations: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
        if let Some(graph) = graph {
            for symbol in &graph.symbols {
                name_locations
                    .entry(symbol.name.clone())
                    .or_default()
                    .push((symbol.file_index, symbol.line));
            }
        }
        Self {
            source,
            config,
            language,
            graph,
            path,
            name_locations,
            node_cache: HashMap::new(),
            tainted: HashSet::new(),
            touched: HashSet::new(),
            findings: Vec::new(),
            methods: HashMap::new(),
        }
    }

    fn collect_methods(&mut self, root: AstNode<'a>) {
        fn visit<'a>(
            node: AstNode<'a>,
            source: &'a str,
            kinds: &'static [&'static str],
            methods: &mut HashMap<String, Vec<Callee<'a>>>,
        ) {
            if kinds.contains(&node.kind()) {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(|n| n.text(source))
                {
                    methods
                        .entry(name.to_string())
                        .or_default()
                        .push((node, source));
                }
                return;
            }
            for child in node.children() {
                visit(child, source, kinds, methods);
            }
        }
        let kinds = method_like_kinds(self.language);
        visit(root, self.source, kinds, &mut self.methods);
    }

    /// All definitions of `name`: same-file functions first, then cross-file
    /// definitions from the code graph (re-located by symbol line).
    fn resolve_callees(&mut self, name: &str) -> Vec<Callee<'a>> {
        let mut out = Vec::new();
        if let Some(same_file) = self.methods.get(name) {
            out.extend(same_file.iter().copied());
        }
        if let Some(graph) = self.graph {
            // Reuse the graph's precise edge resolution (import/type/hierarchy
            // aware) for calls in the analyzed file, when its path is known.
            if let Some(path) = self.path {
                for (file_index, line) in graph.resolved_callees_for_file(path, name) {
                    let Some(file) = graph.files.get(file_index) else {
                        continue;
                    };
                    let key = (file_index, line);
                    let node = match self.node_cache.get(&key) {
                        Some(cached) => *cached,
                        None => {
                            let found = file.method_node_at(line);
                            self.node_cache.insert(key, found);
                            found
                        }
                    };
                    if let Some(node) = node {
                        out.push((node, &file.source));
                    }
                }
            }
            if let Some(locations) = self.name_locations.get(name).cloned() {
                for (file_index, line) in locations {
                    let Some(file) = graph.files.get(file_index) else {
                        continue;
                    };
                    let key = (file_index, line);
                    let node = match self.node_cache.get(&key) {
                        Some(cached) => *cached,
                        None => {
                            let found = file.method_node_at(line);
                            self.node_cache.insert(key, found);
                            found
                        }
                    };
                    if let Some(node) = node {
                        out.push((node, &file.source));
                    }
                }
            }
        }
        // The current file may also appear in the graph; drop duplicate nodes.
        let mut seen = HashSet::new();
        out.retain(|(node, _)| seen.insert((node.start_byte(), node.end_byte())));
        out
    }

    fn walk(&mut self, node: AstNode<'_>) {
        // Taint is intraprocedural. Save and restore state around each function
        // so a tainted variable in one function cannot leak into a sibling.
        if method_like_kinds(self.language).contains(&node.kind()) {
            let saved = self.tainted.clone();
            for child in node.children() {
                self.walk(child);
            }
            self.tainted = saved;
            return;
        }

        match node.kind() {
            "if_statement" => {
                self.walk_if(node);
                return;
            }
            kind if loop_kinds(self.language).contains(&kind) => {
                self.walk_loop(node);
                return;
            }
            _ => {}
        }
        match node.kind() {
            kind if declaration_kinds(self.language).contains(&kind) => {
                self.handle_local_declaration(node, self.source, &mut Vec::new())
            }
            kind if assignment_kinds(self.language).contains(&kind) => {
                self.handle_assignment(node, self.source, &mut Vec::new())
            }
            kind if call_kinds(self.language).contains(&kind) => {
                self.handle_sink_expression(node, self.source)
            }
            _ => {}
        }
        for child in node.children() {
            self.walk(child);
        }
    }

    /// Path-sensitive branch handling: analyze the then/else branches from the
    /// pre-branch state and merge with a union at the join, so a variable
    /// tainted in one branch is not erased by the other branch (or by source
    /// order).
    fn walk_if(&mut self, node: AstNode<'_>) {
        let entry = self.tainted.clone();
        let consequence = node.child_by_field_name("consequence");
        let alternative = node.child_by_field_name("alternative");

        let mut then_state = entry.clone();
        let mut then_touched = HashSet::new();
        if let Some(child) = consequence {
            self.tainted = entry.clone();
            self.touched.clear();
            self.walk(child);
            then_state = self.tainted.clone();
            then_touched = std::mem::take(&mut self.touched);
        }
        let mut else_state = entry.clone();
        let mut else_touched = HashSet::new();
        if let Some(child) = alternative {
            self.tainted = entry.clone();
            self.touched.clear();
            self.walk(child);
            else_state = self.tainted.clone();
            else_touched = std::mem::take(&mut self.touched);
        }

        // Join: a variable that was reassigned in a branch takes that branch's
        // value; an untouched variable keeps its entry value. Across branches,
        // the variable is tainted if either executed branch leaves it tainted.
        let mut vars: HashSet<String> = entry.clone();
        vars.extend(then_state.iter().cloned());
        vars.extend(else_state.iter().cloned());
        let mut merged = HashSet::new();
        for variable in vars {
            let effective_then = if then_touched.contains(&variable) {
                then_state.contains(&variable)
            } else {
                entry.contains(&variable)
            };
            let effective_else = if else_touched.contains(&variable) {
                else_state.contains(&variable)
            } else {
                entry.contains(&variable)
            };
            if effective_then || effective_else {
                merged.insert(variable);
            }
        }
        self.tainted = merged;
        self.touched.clear();
    }

    /// Loop handling: the body may run zero times, so after the loop keep the
    /// union of the entry state and the body state (may-be-tainted).
    fn walk_loop(&mut self, node: AstNode<'_>) {
        let entry = self.tainted.clone();
        for child in node.children() {
            self.walk(child);
        }
        let body_state = std::mem::take(&mut self.tainted);
        self.tainted = entry;
        self.tainted.extend(body_state);
    }

    fn handle_local_declaration(
        &mut self,
        node: AstNode<'_>,
        source: &'a str,
        chain: &mut Vec<String>,
    ) {
        // Java exposes the declarator as a field; JavaScript/Python grammars
        // place `variable_declarator` nodes as direct children.
        // Go `var x = ...` uses var_spec with direct name/value fields.
        let declarator = if node.kind() == "var_spec" {
            Some(node)
        } else {
            node.child_by_field_name("declarator").or_else(|| {
                node.children()
                    .find(|child| child.kind() == "variable_declarator")
            })
        };
        let Some(declarator) = declarator else {
            return;
        };
        let Some(name) = declarator
            .child_by_field_name("name")
            .and_then(|n| n.text(source))
            .map(String::from)
        else {
            return;
        };
        let value = declarator
            .child_by_field_name("value")
            .and_then(|v| v.text(source))
            .map(String::from);
        self.touched.insert(name.clone());
        match value {
            Some(value) => self.apply_assignment(&name, &value, chain),
            None => {
                self.tainted.remove(&name);
            }
        }
    }

    fn handle_assignment(
        &mut self,
        node: AstNode<'_>,
        source: &'a str,
        chain: &mut Vec<String>,
    ) {
        let Some(left) = node
            .child_by_field_name("left")
            .and_then(|l| l.text(source))
            .map(String::from)
        else {
            return;
        };
        let Some(right) = node
            .child_by_field_name("right")
            .and_then(|r| r.text(source))
            .map(String::from)
        else {
            return;
        };
        self.apply_assignment(&left, &right, chain);

        // Sink assignments (e.g. `el.innerHTML = userInput`, `document.body.innerHTML =
        // tainted`) are DOM XSS sinks even though they are not calls.
        if let Some(text) = node.text(source).map(String::from) {
            if self.is_sink(&text) && self.expr_is_tainted(&right, chain) {
                self.emit_finding(node, text);
            }
        }
    }

    fn emit_finding(&mut self, node: AstNode<'_>, text: String) {
        let pos = node.start_position();
        let start = node.start_byte();
        let mut tainted = self
            .tainted
            .iter()
            .filter(|t| contains_identifier(&text, t))
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        if tainted.is_empty() {
            // Taint reached the sink via an expression (e.g. a function
            // return value) rather than a named local variable.
            tainted = "tainted expression".to_string();
        }
        self.findings.push(TaintFinding {
            start_byte: start,
            end_byte: node.end_byte(),
            start_line: pos.row + 1,
            start_column: pos.column + 1,
            tainted,
            sink: text,
        });
    }

    /// Taints `target` when `value` carries source data (a source call, a
    /// tainted variable, a tainted method return, or a combination); otherwise
    /// clears it. If the value is a sanitizer call, the target is explicitly
    /// marked clean. `chain` is the in-progress callee path: assignments inside
    /// a callee body must keep it, or a (mutually) recursive callee re-enters
    /// its own analysis forever.
    fn apply_assignment(&mut self, target: &str, value: &str, chain: &mut Vec<String>) {
        self.touched.insert(target.to_string());
        if self.is_sanitizer_call(value) {
            self.tainted.remove(target);
        } else if self.expr_is_tainted(value, chain) {
            self.tainted.insert(target.to_string());
        } else {
            self.tainted.remove(target);
        }
    }

    fn is_sanitizer_call(&self, value: &str) -> bool {
        self.config
            .sanitizers
            .iter()
            .any(|s| value.contains(s.as_str()))
    }

    /// Whether an expression text carries taint: it references a tainted
    /// variable, contains a source call, or is/contains a call to a method
    /// that returns tainted data (same-file or, via the code graph, cross-file).
    fn expr_is_tainted(&mut self, text: &str, chain: &mut Vec<String>) -> bool {
        if self
            .config
            .sources
            .iter()
            .any(|pattern| text.contains(pattern))
        {
            return true;
        }
        if is_tainted_text(text, &self.tainted) {
            return true;
        }
        let Some((name, args)) = parse_call(text) else {
            return false;
        };
        // A tainted argument propagates even when the callee is unknown.
        for arg in &args {
            if self.expr_is_tainted(arg, chain) {
                return true;
            }
        }
        if chain.contains(&name) {
            return false;
        }
        let candidates = self.resolve_callees(&name);
        if candidates.is_empty() {
            return false;
        }
        chain.push(name.clone());
        let tainted = candidates
            .iter()
            .any(|(method, source)| self.callee_returns_tainted(*method, source, &args, chain));
        chain.pop();
        tainted
    }

    /// Analyzes a method body with the caller's argument taint bound to its
    /// parameters, and reports whether any `return` expression is tainted.
    /// Sink findings inside the callee are deliberately not emitted here (the
    /// caller's sink site is the finding location).
    fn callee_returns_tainted(
        &mut self,
        method: AstNode<'a>,
        source: &'a str,
        args: &[String],
        chain: &mut Vec<String>,
    ) -> bool {
        // Evaluate argument taint in the caller's context before the callee
        // analysis clears the state; a variable argument is only recognized
        // as tainted against the caller's tainted set.
        let arg_tainted: Vec<bool> = args
            .iter()
            .map(|arg| self.expr_is_tainted(arg, chain))
            .collect();
        let saved = std::mem::take(&mut self.tainted);
        let saved_touched = std::mem::take(&mut self.touched);
        self.bind_params(method, source, &arg_tainted);
        let mut result = false;
        for child in method.children() {
            self.walk_for_returns(child, source, chain, &mut result);
            if result {
                break;
            }
        }
        self.tainted = saved;
        self.touched = saved_touched;
        result
    }

    /// Binds tainted caller arguments to the callee's parameters. The taint
    /// flags are evaluated in the caller's context before the callee analysis
    /// starts, so variable arguments propagate across hops.
    fn bind_params(&mut self, method: AstNode<'a>, source: &'a str, arg_tainted: &[bool]) {
        let params: Vec<AstNode<'a>> = method
            .child_by_field_name("parameters")
            .map(|params| {
                params
                    .children()
                    .filter(|child| {
                        matches!(
                            child.kind(),
                            "formal_parameter"
                                | "identifier"
                                | "typed_parameter"
                                | "typed_default_parameter"
                                | "default_parameter"
                                | "required_parameter"
                                | "optional_parameter"
                                | "pattern"
                                | "list_splat_pattern"
                                | "dictionary_splat_pattern"
                                | "parameter_declaration"
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (index, param) in params.iter().enumerate() {
            if !arg_tainted.get(index).copied().unwrap_or(false) {
                break;
            }
            if let Some(name) = param
                .child_by_field_name("name")
                .and_then(|n| n.text(source))
            {
                self.tainted.insert(name.to_string());
            }
        }
    }

    fn walk_for_returns(
        &mut self,
        node: AstNode<'_>,
        source: &'a str,
        chain: &mut Vec<String>,
        result: &mut bool,
    ) {
        if method_like_kinds(self.language).contains(&node.kind()) {
            return;
        }
        if node.kind() == "return_statement" {
            let value = node
                .children()
                .find(|child| {
                    let kind = child.kind();
                    kind != "return" && kind != ";"
                })
                .and_then(|child| child.text(source));
            if let Some(value) = value {
                if self.expr_is_tainted(value, chain) {
                    *result = true;
                }
            }
            return;
        }
        match node.kind() {
            kind if declaration_kinds(self.language).contains(&kind) => {
                self.handle_local_declaration(node, source, chain)
            }
            kind if assignment_kinds(self.language).contains(&kind) => {
                self.handle_assignment(node, source, chain)
            }
            _ => {}
        }
        if *result {
            return;
        }
        for child in node.children() {
            self.walk_for_returns(child, source, chain, result);
            if *result {
                break;
            }
        }
    }

    fn handle_sink_expression(&mut self, node: AstNode<'_>, source: &'a str) {
        let Some(text) = node.text(source).map(String::from) else {
            return;
        };

        if self.is_sink(&text) {
            if self.expr_is_tainted(&text, &mut Vec::new()) {
                self.emit_finding(node, text);
            }
            return;
        }
        // Cross-file scenario: a call with tainted arguments whose callee
        // (defined elsewhere in the project) reaches a sink inside its body is
        // reported at this call site — handler → service → repository chains.
        if self.expr_is_tainted(&text, &mut Vec::new()) {
            if let Some((name, args)) = parse_call(&text) {
                if let Some(sink) = self.callee_reaches_sink(&name, &args, &mut Vec::new()) {
                    self.emit_finding(node, format!("{name}(...) reaches sink {sink}"));
                }
            }
        }
    }

    /// Whether any definition of `name` (same- or cross-file) reaches a sink
    /// inside its body when the caller's tainted arguments are bound.
    fn callee_reaches_sink(
        &mut self,
        name: &str,
        args: &[String],
        chain: &mut Vec<String>,
    ) -> Option<String> {
        if chain.contains(&name.to_string()) {
            return None;
        }
        let candidates = self.resolve_callees(name);
        if candidates.is_empty() {
            return None;
        }
        chain.push(name.to_string());
        let mut found = None;
        for (method, source) in candidates {
            if let Some(sink) = self.callee_has_sink(method, source, args, chain) {
                found = Some(sink);
                break;
            }
        }
        chain.pop();
        found
    }

    fn callee_has_sink(
        &mut self,
        method: AstNode<'a>,
        source: &'a str,
        args: &[String],
        chain: &mut Vec<String>,
    ) -> Option<String> {
        let arg_tainted: Vec<bool> = args
            .iter()
            .map(|arg| self.expr_is_tainted(arg, chain))
            .collect();
        let saved = std::mem::take(&mut self.tainted);
        let saved_touched = std::mem::take(&mut self.touched);
        self.bind_params(method, source, &arg_tainted);
        let mut sink = None;
        for child in method.children() {
            if let Some(found) = self.walk_for_sinks(child, source, chain) {
                sink = Some(found);
                break;
            }
        }
        self.tainted = saved;
        self.touched = saved_touched;
        sink
    }

    /// Walks a callee body looking for a sink call whose arguments are tainted.
    fn walk_for_sinks(
        &mut self,
        node: AstNode<'_>,
        source: &'a str,
        chain: &mut Vec<String>,
    ) -> Option<String> {
        if method_like_kinds(self.language).contains(&node.kind()) {
            return None;
        }
        match node.kind() {
            kind if declaration_kinds(self.language).contains(&kind) => {
                self.handle_local_declaration(node, source, chain)
            }
            kind if assignment_kinds(self.language).contains(&kind) => {
                self.handle_assignment(node, source, chain)
            }
            _ => {}
        }
        if call_kinds(self.language).contains(&node.kind()) {
            if let Some(text) = node.text(source).map(String::from) {
                if self.is_sink(&text) {
                    if self.expr_is_tainted(&text, chain) {
                        return Some(text);
                    }
                } else if self.expr_is_tainted(&text, chain) {
                    // One more hop: a tainted call that is not itself a sink
                    // may reach a sink deeper in the chain (handler → service
                    // → repository). Cycle-guarded via the chain.
                    if let Some((name, args)) = parse_call(&text) {
                        if let Some(sink) = self.callee_reaches_sink(&name, &args, chain) {
                            return Some(sink);
                        }
                    }
                }
            }
        }
        for child in node.children() {
            if let Some(found) = self.walk_for_sinks(child, source, chain) {
                return Some(found);
            }
        }
        None
    }

    fn is_sink(&self, text: &str) -> bool {
        self.config
            .sinks
            .iter()
            .any(|sink| text.contains(sink.as_str()))
    }
}

/// Parses `name(args...)` from an expression text: returns the final callee
/// identifier (after any `receiver.` prefix) and the top-level argument texts.
pub(crate) fn parse_call(text: &str) -> Option<(String, Vec<String>)> {
    let open = text.find('(')?;
    let before = &text[..open];
    let name_start = before
        .rfind(|character: char| {
            !(character.is_ascii_alphanumeric() || character == '_' || character == '.')
        })
        .map(|index| index + 1)
        .unwrap_or(0);
    let name = before[name_start..]
        .rsplit('.')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if name.is_empty() {
        return None;
    }
    let mut args = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    for character in text[open + 1..].chars() {
        match character {
            '(' => {
                depth += 1;
                current.push(character);
            }
            ')' => {
                if depth == 0 {
                    if !current.trim().is_empty() {
                        args.push(current.trim().to_string());
                    }
                    return Some((name, args));
                }
                depth -= 1;
                current.push(character);
            }
            ',' if depth == 0 => {
                if !current.trim().is_empty() {
                    args.push(current.trim().to_string());
                }
                current.clear();
            }
            _ => current.push(character),
        }
    }
    None
}

pub(crate) fn line_text(source: &str, byte: usize) -> String {
    let byte = byte.min(source.len());
    let start = source[..byte].rfind('\n').map_or(0, |index| index + 1);
    let end = source[byte..]
        .find('\n')
        .map_or(source.len(), |index| byte + index);
    source[start..end].trim().to_string()
}

pub(crate) fn is_tainted_text(text: &str, tainted_vars: &HashSet<String>) -> bool {
    if tainted_vars.is_empty() {
        return false;
    }
    let stripped = strip_string_literals(text);
    tainted_vars
        .iter()
        .any(|var| contains_identifier(&stripped, var))
}

/// Replaces string literal contents with spaces so that words inside string
/// data are never mistaken for variable references. Template-literal
/// `${expr}` interpolations are preserved: they reference real variables.
fn strip_string_literals(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '"' | '\'' => {
                result.push(' ');
                while let Some(next) = chars.next() {
                    if next == '\\' {
                        chars.next();
                    } else if next == character {
                        break;
                    }
                }
                result.push(' ');
            }
            '`' => {
                result.push(' ');
                let mut depth = 0i32;
                let mut interpolating = false;
                while let Some(next) = chars.next() {
                    if interpolating {
                        result.push(next);
                        if next == '{' {
                            depth += 1;
                        } else if next == '}' {
                            depth -= 1;
                            if depth == 0 {
                                interpolating = false;
                            }
                        }
                        continue;
                    }
                    if next == '\\' {
                        chars.next();
                    } else if next == '$' && chars.clone().next() == Some('{') {
                        chars.next(); // consume the '{'
                        interpolating = true;
                        depth = 1;
                    } else if next == '`' {
                        break;
                    }
                }
                result.push(' ');
            }
            _ => result.push(character),
        }
    }
    result
}

fn contains_identifier(text: &str, identifier: &str) -> bool {
    if identifier.is_empty() {
        return false;
    }
    let mut offset = 0;
    while let Some(relative) = text[offset..].find(identifier) {
        let start = offset + relative;
        let end = start + identifier.len();
        let before_ok = text[..start]
            .chars()
            .next_back()
            .is_none_or(|character| !is_identifier_character(character));
        let after_ok = text[end..]
            .chars()
            .next()
            .is_none_or(|character| !is_identifier_character(character));
        if before_ok && after_ok {
            return true;
        }
        offset = end;
        if offset >= text.len() {
            break;
        }
    }
    false
}

fn is_identifier_character(character: char) -> bool {
    character == '_' || character.is_ascii_alphanumeric()
}
