//! Intraprocedural and intra-file interprocedural taint analysis for Java.
//!
//! The engine tracks tainted values from sources to sinks in source order,
//! binds caller arguments to callee parameters, and follows same-file
//! method return values. The public finding conversion lives in `taint.rs`.

use std::collections::{HashMap, HashSet};

use crate::{
    ast::AstNode,
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
    if config.sources.is_empty() || config.sinks.is_empty() {
        return Vec::new();
    }
    let mut state = State::new(source, config, language);
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

fn method_like_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::Java => &["method_declaration", "constructor_declaration"],
        Language::JavaScript | Language::TypeScript => &[
            "function_declaration",
            "function_expression",
            "arrow_function",
            "method_definition",
        ],
        Language::Python => &["function_definition"],
        Language::Go | Language::Unknown => &[],
    }
}

fn declaration_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::JavaScript | Language::TypeScript => {
            &["lexical_declaration", "variable_declaration"]
        }
        _ => &["local_variable_declaration"],
    }
}

fn assignment_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::Python => &["assignment"],
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

fn call_kinds(language: Language) -> &'static [&'static str] {
    match language {
        Language::Java => &["method_invocation", "object_creation_expression"],
        Language::JavaScript | Language::TypeScript => &["call_expression"],
        Language::Python => &["call"],
        Language::Go | Language::Unknown => &[],
    }
}

struct State<'a> {
    source: &'a str,
    config: &'a TaintConfig,
    language: Language,
    tainted: HashSet<String>,
    /// Variables assigned since the current branch/loop scope began. Used by
    /// the branch join to distinguish "reassigned clean" from "never touched".
    touched: HashSet<String>,
    findings: Vec<TaintFinding>,
    /// Functions declared in the analyzed file, keyed by name. Enables
    /// intra-file interprocedural taint propagation of return values.
    methods: HashMap<String, Vec<AstNode<'a>>>,
}

impl<'a> State<'a> {
    fn new(source: &'a str, config: &'a TaintConfig, language: Language) -> Self {
        Self {
            source,
            config,
            language,
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
            methods: &mut HashMap<String, Vec<AstNode<'a>>>,
        ) {
            if kinds.contains(&node.kind()) {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(|n| n.text(source))
                {
                    methods.entry(name.to_string()).or_default().push(node);
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
                self.handle_local_declaration(node)
            }
            kind if assignment_kinds(self.language).contains(&kind) => self.handle_assignment(node),
            kind if call_kinds(self.language).contains(&kind) => self.handle_sink_expression(node),
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

    fn handle_local_declaration(&mut self, node: AstNode<'_>) {
        // Java exposes the declarator as a field; JavaScript/Python grammars
        // place `variable_declarator` nodes as direct children.
        let declarator = node.child_by_field_name("declarator").or_else(|| {
            node.children()
                .find(|child| child.kind() == "variable_declarator")
        });
        let Some(declarator) = declarator else {
            return;
        };
        let Some(name) = declarator
            .child_by_field_name("name")
            .and_then(|n| n.text(self.source))
            .map(String::from)
        else {
            return;
        };
        let value = declarator
            .child_by_field_name("value")
            .and_then(|v| v.text(self.source))
            .map(String::from);
        self.touched.insert(name.clone());
        match value {
            Some(value) => self.apply_assignment(&name, &value),
            None => {
                self.tainted.remove(&name);
            }
        }
    }

    fn handle_assignment(&mut self, node: AstNode<'_>) {
        let Some(left) = node
            .child_by_field_name("left")
            .and_then(|l| l.text(self.source))
            .map(String::from)
        else {
            return;
        };
        let Some(right) = node
            .child_by_field_name("right")
            .and_then(|r| r.text(self.source))
            .map(String::from)
        else {
            return;
        };
        self.apply_assignment(&left, &right);

        // Sink assignments (e.g. `el.innerHTML = userInput`, `document.body.innerHTML =
        // tainted`) are DOM XSS sinks even though they are not calls.
        if let Some(text) = node.text(self.source).map(String::from) {
            if self.is_sink(&text) && self.expr_is_tainted(&right, &mut Vec::new()) {
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
    /// marked clean.
    fn apply_assignment(&mut self, target: &str, value: &str) {
        self.touched.insert(target.to_string());
        if self.is_sanitizer_call(value) {
            self.tainted.remove(target);
        } else if self.expr_is_tainted(value, &mut Vec::new()) {
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
    /// variable, contains a source call, or is/contains a call to a same-file
    /// method that returns tainted data (intra-file interprocedural taint).
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
        let candidates: Vec<AstNode<'a>> = self.methods.get(&name).cloned().unwrap_or_default();
        if candidates.is_empty() {
            return false;
        }
        chain.push(name.clone());
        let tainted = candidates
            .iter()
            .any(|method| self.callee_returns_tainted(*method, &args, chain));
        chain.pop();
        tainted
    }

    /// Analyzes a same-file method body with the caller's argument taint bound
    /// to its parameters, and reports whether any `return` expression is
    /// tainted. Sink findings inside the callee are deliberately not emitted
    /// here (the caller's sink site is the finding location).
    fn callee_returns_tainted(
        &mut self,
        method: AstNode<'a>,
        args: &[String],
        chain: &mut Vec<String>,
    ) -> bool {
        let saved = std::mem::take(&mut self.tainted);
        let saved_touched = std::mem::take(&mut self.touched);
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
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        for (index, param) in params.iter().enumerate() {
            let Some(arg) = args.get(index) else {
                break;
            };
            if self.expr_is_tainted(arg, chain) {
                if let Some(name) = param
                    .child_by_field_name("name")
                    .and_then(|n| n.text(self.source))
                {
                    self.tainted.insert(name.to_string());
                }
            }
        }
        let mut result = false;
        for child in method.children() {
            self.walk_for_returns(child, chain, &mut result);
            if result {
                break;
            }
        }
        self.tainted = saved;
        self.touched = saved_touched;
        result
    }

    fn walk_for_returns(&mut self, node: AstNode<'_>, chain: &mut Vec<String>, result: &mut bool) {
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
                .and_then(|child| child.text(self.source));
            if let Some(value) = value {
                if self.expr_is_tainted(value, chain) {
                    *result = true;
                }
            }
            return;
        }
        match node.kind() {
            "local_variable_declaration" => self.handle_local_declaration(node),
            "assignment_expression" => self.handle_assignment(node),
            _ => {}
        }
        if *result {
            return;
        }
        for child in node.children() {
            self.walk_for_returns(child, chain, result);
            if *result {
                break;
            }
        }
    }

    fn handle_sink_expression(&mut self, node: AstNode<'_>) {
        let Some(text) = node.text(self.source).map(String::from) else {
            return;
        };

        if self.is_sink(&text) && self.expr_is_tainted(&text, &mut Vec::new()) {
            self.emit_finding(node, text);
        }
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
fn parse_call(text: &str) -> Option<(String, Vec<String>)> {
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
    tainted_vars
        .iter()
        .any(|var| contains_identifier(text, var))
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
