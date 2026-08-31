//! Rule Packs and data-driven rules (ADR-0004).
//!
//! A Rule Pack is a directory with a `pack.toml` manifest and `rules/*.rule.toml`
//! files. This module parses, validates, and loads packs into a rule registry that
//! the scanner can execute. Rules are data; the analysis algorithms live in the engine.

use std::path::{Path, PathBuf};

use crate::{
    cache::CACHE_SCHEMA,
    finding::{Confidence, Finding, Severity, SourceLocation},
    language::Language,
};

pub use crate::pack_load::{
    built_in_packs, load_pack_dir, load_single_rule_file, validate_pack_dir,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PackMeta {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub authors: Option<Vec<String>>,
    /// Minimum Hawk version this pack requires (from `pack.toml` metadata).
    pub min_hawk: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub recommendation: Option<String>,
    pub category: Option<String>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub languages: Vec<Language>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    /// Framework this rule targets (e.g. Spring), for framework-aware rules.
    pub framework: Option<String>,
    /// The regex pattern, when this rule is a pattern-based rule.
    pub pattern: Option<PatternRule>,
    /// The taint config, when this rule is a data-flow (taint) rule.
    pub taint: Option<crate::taint::TaintConfig>,
    /// The tree-sitter query, when this rule is an AST (query) rule.
    pub query: Option<QueryRule>,
    /// Source file this rule was loaded from (for diagnostics).
    pub source: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternRule {
    pub regex: String,
    /// Optional exclusion regex (Semgrep pattern-not-regex style): matches of
    /// the primary regex whose text also matches this are discarded.
    pub not_regex: Option<String>,
    /// Optional replacement suggestion (Semgrep `fix` style), reported with
    /// the finding for `--autofix`-style workflows.
    pub fix: Option<String>,
}

/// A tree-sitter query (S-expression pattern), Semgrep "rules look like code".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryRule {
    pub tree_sitter: String,
    /// Capture name (without `@`) whose node marks the finding location. When
    /// set, each query match reports exactly the anchored node; when unset,
    /// every captured node is reported (legacy behavior).
    pub anchor: Option<String>,
    /// Matches whose anchored text also matches this regex are discarded
    /// (query-rule counterpart of pattern `not-regex`).
    pub not_regex: Option<String>,
}

/// Errors produced while loading or validating packs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackError {
    Read {
        path: PathBuf,
        source: String,
    },
    Parse {
        path: PathBuf,
        source: String,
    },
    Validate {
        message: String,
    },
    DuplicateId {
        id: String,
        first: PathBuf,
        second: PathBuf,
    },
}

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, source } => {
                write!(f, "unable to read pack '{}': {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(f, "unable to parse pack '{}': {source}", path.display())
            }
            Self::Validate { message } => write!(f, "invalid pack: {message}"),
            Self::DuplicateId { id, first, second } => write!(
                f,
                "rule id '{id}' defined by both '{}' and '{}'",
                first.display(),
                second.display()
            ),
        }
    }
}

impl std::error::Error for PackError {}

// ---------- runtime rule execution ----------

/// A compiled rule ready to run against a parsed file.
#[derive(Clone, Debug)]
pub struct CompiledRule {
    pub def: Rule,
    compiled_regex: Option<regex::Regex>,
    compiled_not_regex: Option<regex::Regex>,
}

impl CompiledRule {
    /// Compiles a loaded rule, materializing its regex matcher. Returns the rule
    /// itself as the error payload when compilation fails so callers can report
    /// the offending id.
    pub fn compile(def: Rule) -> Result<Self, Box<(Rule, String)>> {
        let run_regex = match &def.pattern {
            Some(pattern) => Some(regex::Regex::new(&pattern.regex).map_err(|error| {
                Box::new((def.clone(), format!("invalid pattern regex: {error}")))
            })?),
            None => None,
        };
        let compiled_not_regex = match &def.pattern {
            Some(pattern) => match &pattern.not_regex {
                Some(not) => Some(regex::Regex::new(not).map_err(|error| {
                    Box::new((def.clone(), format!("invalid not-regex: {error}")))
                })?),
                None => None,
            },
            None => None,
        };
        Ok(Self {
            def,
            compiled_regex: run_regex,
            compiled_not_regex,
        })
    }

    pub fn id(&self) -> &str {
        &self.def.id
    }

    pub fn languages(&self) -> &[Language] {
        &self.def.languages
    }

    pub fn severity(&self) -> Severity {
        self.def.severity
    }

    /// Executes the rule against a source string that has already been detcbable
    /// targets (pattern rules operate on raw text; future capabilities take the
    /// syntax tree). Returns findings with fingerprints and full metadata.
    pub fn check(&self, source: &str, path: &std::path::Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        let language = self.def.languages.first().copied();
        if let Some(run) = &self.compiled_regex {
            for m in run.find_iter(source) {
                if let Some(not) = &self.compiled_not_regex {
                    // Semgrep-style `pattern-not-regex`: if the line carrying
                    // this match also matches the exclusion, suppress it. This
                    // makes not-regex useful for context-sensitive exceptions
                    // (e.g. ignore a trailing 'safe' shellout form).
                    let line_start = source[..m.start()].rfind('\n').map(|i| i + 1).unwrap_or(0);
                    let after = &source[m.end()..];
                    let line_end = after
                        .find('\n')
                        .map(|i| m.end() + i)
                        .unwrap_or(source.len());
                    if not.is_match(&source[line_start..line_end]) {
                        continue;
                    }
                }
                let (line, column) = line_column(source, m.start());
                let mut finding = Finding::new(
                    self.def.id.clone(),
                    self.def.severity,
                    self.def.name.clone(),
                    SourceLocation {
                        path: path.to_path_buf(),
                        start_byte: m.start(),
                        end_byte: m.end(),
                        start_line: line,
                        start_column: column,
                        end_line: line,
                        end_column: column + (m.end() - m.start()),
                    },
                )
                .with_confidence(self.def.confidence)
                .with_rule_name(self.def.name.clone())
                .with_description(self.def.description.clone())
                .with_code_snippet(line_text(source, m.start()));
                if let Some(recommendation) = &self.def.recommendation {
                    finding = finding.with_recommendation(recommendation.clone());
                } else if let Some(fix) = &self.def.pattern.as_ref().and_then(|p| p.fix.as_ref()) {
                    finding = finding.with_recommendation(format!("Suggested fix: {fix}"));
                }
                if let Some(category) = &self.def.category {
                    finding = finding.with_category(category.clone());
                }
                if let Some(lang) = language {
                    finding = finding.with_language(lang);
                }
                if let Some(cwe) = &self.def.cwe {
                    finding = finding.with_cwe(cwe.clone());
                }
                if let Some(owasp) = &self.def.owasp {
                    finding = finding.with_owasp(owasp.clone());
                }
                if let Some(framework) = &self.def.framework {
                    finding = finding.with_framework(framework.clone());
                }
                findings.push(finding);
            }
        }
        findings
    }

    /// Executes the rule against a parsed syntax tree: pattern rules against the
    /// raw text, taint rules with the data-flow engine.
    pub fn check_parsed(
        &self,
        tree: &crate::parser::SyntaxTree,
        source: &str,
        path: &std::path::Path,
    ) -> Vec<Finding> {
        self.check_parsed_with_graph(tree, source, path, None)
    }

    /// `check_parsed` with the project code graph: taint rules resolve callees
    /// across the whole scanned file set.
    pub fn check_parsed_with_graph(
        &self,
        tree: &crate::parser::SyntaxTree,
        source: &str,
        path: &std::path::Path,
        graph: Option<&crate::code_graph::CodeGraph>,
    ) -> Vec<Finding> {
        if let Some(taint) = &self.def.taint {
            let language = self
                .def
                .languages
                .first()
                .copied()
                .unwrap_or(Language::Java);
            return crate::taint::analyze_with_graph(
                tree,
                source,
                taint,
                language,
                graph,
                Some(path),
            )
            .iter()
            .map(|tf| {
                crate::taint::to_finding(
                    tf,
                    source,
                    crate::taint::TaintMetadata {
                        rule_id: &self.def.id,
                        rule_name: &self.def.name,
                        description: &self.def.description,
                        recommendation: self.def.recommendation.as_deref(),
                        category: self.def.category.as_deref(),
                        framework: self.def.framework.as_deref(),
                        cwe: self.def.cwe.as_deref(),
                        owasp: self.def.owasp.as_deref(),
                        language: self.def.languages.first().copied(),
                        severity: self.def.severity,
                        confidence: self.def.confidence,
                    },
                    path,
                )
            })
            .collect();
        }
        if let Some(query) = &self.def.query {
            match execute_query(
                tree.raw_root_node(),
                source,
                &query.tree_sitter,
                query.anchor.as_deref(),
                query.not_regex.as_deref(),
                self.def.languages.first().copied(),
            ) {
                Ok(matches) => {
                    return matches
                        .iter()
                        .map(|node| {
                            let pos = node.start_position();
                            {
                                let mut finding = Finding::new(
                                    self.def.id.clone(),
                                    self.def.severity,
                                    self.def.name.clone(),
                                    SourceLocation {
                                        path: path.to_path_buf(),
                                        start_byte: node.start_byte(),
                                        end_byte: node.end_byte(),
                                        start_line: pos.row + 1,
                                        start_column: pos.column + 1,
                                        end_line: node.end_position().row + 1,
                                        end_column: node.end_position().column + 1,
                                    },
                                )
                                .with_confidence(self.def.confidence)
                                .with_rule_name(self.def.name.clone())
                                .with_description(self.def.description.clone())
                                .with_code_snippet(line_text(source, node.start_byte()));
                                if let Some(value) = self.def.category.as_deref() {
                                    finding = finding.with_category(value);
                                }
                                if let Some(value) = self.def.recommendation.as_deref() {
                                    finding = finding.with_recommendation(value);
                                }
                                if let Some(value) = self.def.framework.as_deref() {
                                    finding = finding.with_framework(value);
                                }
                                if let Some(value) = self.def.cwe.as_deref() {
                                    finding = finding.with_cwe(value);
                                }
                                if let Some(value) = self.def.owasp.as_deref() {
                                    finding = finding.with_owasp(value);
                                }
                                if let Some(value) = self.def.languages.first().copied() {
                                    finding = finding.with_language(value);
                                }
                                finding
                            }
                        })
                        .collect();
                }
                Err(message) => {
                    // Explicit failure per philosophy: a broken query must not
                    // yield a silent "no findings".
                    return vec![Finding::new(
                        format!("{}:query-error", self.def.id),
                        self.def.severity,
                        format!("tree-sitter query failed: {message}"),
                        SourceLocation {
                            path: path.to_path_buf(),
                            start_byte: 0,
                            end_byte: 0,
                            start_line: 1,
                            start_column: 1,
                            end_line: 1,
                            end_column: 1,
                        },
                    )];
                }
            }
        }
        self.check(source, path)
    }
}

/// Runs a tree-sitter query against a syntax tree and returns matching nodes.
///
/// With `anchor`, each query match contributes exactly the anchored capture's
/// node (the finding location); without it, every capture is reported. Nodes
/// whose text matches `not_regex` are discarded, and identical spans are
/// reported once. `#eq?`/`#match?`/`#any-of?` predicates are evaluated here
/// rather than by the tree-sitter crate, whose match iterator misbehaves when
/// a query carries text predicates (empty captures, runaway matches).
fn execute_query<'tree>(
    root: tree_sitter::Node<'tree>,
    source: &str,
    query_source: &str,
    anchor: Option<&str>,
    not_regex: Option<&str>,
    language: Option<Language>,
) -> Result<Vec<tree_sitter::Node<'tree>>, String> {
    use tree_sitter::StreamingIterator as _;
    let Some(language) = language else {
        return Err("query rules require a declared language".into());
    };
    let ts_language = match language {
        Language::Java => tree_sitter::Language::from(tree_sitter_java::LANGUAGE),
        Language::JavaScript => tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
        Language::TypeScript => {
            tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT)
        }
        Language::Python => tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
        Language::Go => tree_sitter::Language::from(tree_sitter_go::LANGUAGE),
        Language::Unknown => return Err("unsupported language".into()),
    };
    let (clean_query, predicates) = split_predicates(query_source);
    let query = tree_sitter::Query::new(&ts_language, &clean_query).map_err(|e| e.to_string())?;
    let not_regex = not_regex
        .map(|pattern| regex::Regex::new(pattern).map_err(|e| format!("invalid not-regex: {e}")))
        .transpose()?;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(&query, root, source.as_bytes());
    let mut out: Vec<tree_sitter::Node<'tree>> = Vec::new();
    let mut seen: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    while let Some(m) = matches.next() {
        if !predicates_match(&query, m, &predicates, source) {
            continue;
        }
        let captured: Vec<tree_sitter::Node<'tree>> =
            m.captures.iter().map(|capture| capture.node).collect();
        // With an anchor, only the anchored node is a finding site; the other
        // captures exist to constrain the pattern (e.g. `@arg` filters).
        let sites: Vec<tree_sitter::Node<'tree>> = match anchor {
            Some(anchor) => {
                let anchored = m
                    .captures
                    .iter()
                    .find(|capture| query.capture_names()[capture.index as usize] == anchor);
                match anchored {
                    Some(node) => vec![node.node],
                    None => continue,
                }
            }
            None => captured,
        };
        for node in sites {
            let text = node.utf8_text(source.as_bytes()).unwrap_or_default();
            if not_regex.as_ref().is_some_and(|re| re.is_match(text)) {
                continue;
            }
            if seen.insert((node.start_byte(), node.end_byte())) {
                out.push(node);
            }
        }
    }
    Ok(out)
}

/// A `#eq?`/`#match?`/`#any-of?`-style predicate declared in a query.
struct Predicate {
    operator: String,
    capture: String,
    /// String literal arguments; the compiled regex when operator is a match.
    values: Vec<String>,
    regex: Option<regex::Regex>,
}

/// Splits `(#operator @capture "arg" ...)` predicates out of a query string
/// and returns the clean query plus the parsed predicates. The predicate forms
/// supported mirror tree-sitter's text predicates.
fn split_predicates(query_source: &str) -> (String, Vec<Predicate>) {
    let mut stripped = String::with_capacity(query_source.len());
    let mut predicates = Vec::new();
    let chars: Vec<char> = query_source.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '(' && chars.get(index + 1) == Some(&'#') {
            // Scan to the balanced closing paren, respecting string quotes.
            let mut depth = 0i32;
            let mut in_quote = false;
            let mut end = index;
            while end < chars.len() {
                let character = chars[end];
                if in_quote {
                    if character == '\\' {
                        end += 1;
                    } else if character == '"' {
                        in_quote = false;
                    }
                } else {
                    match character {
                        '"' => in_quote = true,
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                end += 1;
            }
            let text: String = chars[index..end].iter().collect();
            if let Some(predicate) = parse_predicate(&text) {
                predicates.push(predicate);
            }
            stripped.push(' ');
            index = end;
        } else {
            stripped.push(chars[index]);
            index += 1;
        }
    }
    (stripped, predicates)
}

fn parse_predicate(text: &str) -> Option<Predicate> {
    let pattern = regex::Regex::new(
        r#"^\(\s*#(?P<op>[a-z?-]+)\s+@(?P<cap>[a-zA-Z_0-9]+)(?P<vals>(?:\s+"(?:[^"\\]|\\.)*")*)\s*\)$"#,
    )
    .ok()?;
    let captures = pattern.captures(text)?;
    // Normalize `eq?`/`match?` to `eq`/`match` for the evaluation arms.
    let operator = captures
        .name("op")?
        .as_str()
        .trim_end_matches('?')
        .to_string();
    let capture = captures.name("cap")?.as_str().to_string();
    let values = regex::Regex::new(r#""((?:[^"\\]|\\.)*)""#)
        .ok()?
        .captures_iter(captures.name("vals")?.as_str())
        .filter_map(|value| value.get(1))
        .map(|value| value.as_str().to_string())
        .collect::<Vec<_>>();
    let regex = if matches!(operator.as_str(), "match" | "not-match") {
        values
            .first()
            .and_then(|value| regex::Regex::new(value).ok())
    } else {
        None
    };
    Some(Predicate {
        operator,
        capture,
        values,
        regex,
    })
}

/// Evaluates the query's predicates against one match. A capture that appears
/// several times must satisfy the predicate at every occurrence; a predicate
/// whose capture is absent passes (matching tree-sitter semantics).
fn predicates_match(
    query: &tree_sitter::Query,
    m: &tree_sitter::QueryMatch,
    predicates: &[Predicate],
    source: &str,
) -> bool {
    for predicate in predicates {
        let texts: Vec<&str> = m
            .captures
            .iter()
            .filter(|capture| query.capture_names()[capture.index as usize] == predicate.capture)
            .filter_map(|capture| capture.node.utf8_text(source.as_bytes()).ok())
            .collect();
        let passes = match predicate.operator.as_str() {
            "eq" => !texts.is_empty() && texts.iter().all(|text| *text == predicate.values[0]),
            "not-eq" => texts.is_empty() || texts.iter().all(|text| *text != predicate.values[0]),
            "match" => {
                !texts.is_empty()
                    && predicate
                        .regex
                        .as_ref()
                        .is_some_and(|re| texts.iter().all(|text| re.is_match(text)))
            }
            "not-match" => {
                texts.is_empty()
                    || predicate
                        .regex
                        .as_ref()
                        .is_some_and(|re| texts.iter().all(|text| !re.is_match(text)))
            }
            "any-of" => {
                !texts.is_empty()
                    && texts
                        .iter()
                        .all(|text| predicate.values.iter().any(|value| value == text))
            }
            "not-any-of" => {
                texts.is_empty()
                    || texts
                        .iter()
                        .all(|text| !predicate.values.iter().any(|value| value == text))
            }
            // Unknown or structural predicates (`set!`, `is?`, ...) are
            // ignored rather than silently rejecting every match.
            _ => true,
        };
        if !passes {
            return false;
        }
    }
    true
}

/// The trimmed source line containing `byte` (used for code snippets).
fn line_text(source: &str, byte: usize) -> String {
    let start = source[..byte.min(source.len())]
        .rfind('\n')
        .map(|i| i + 1)
        .unwrap_or(0);
    let after = &source[byte.min(source.len())..];
    let end = after.find('\n').map(|i| byte + i).unwrap_or(source.len());
    source[start..end].trim().to_string()
}

fn line_column(source: &str, byte: usize) -> (usize, usize) {
    let prefix = &source[..byte.min(source.len())];
    let line = prefix.bytes().filter(|&b| b == b'\n').count() + 1;
    let col = prefix
        .rsplit_once('\n')
        .map(|(_, tail)| tail.chars().count() + 1)
        .unwrap_or_else(|| prefix.chars().count() + 1);
    (line, col)
}

// ---------------------------------------------------------------------------
// loading
// ---------------------------------------------------------------------------

/// Loads all rules from a pack directory. Deterministic: manifest first, then
/// rules sorted by file name.
/// A registry of loaded, compiled rules in stable pack/file order.
#[derive(Debug, Default)]
pub struct PackRegistry {
    pub packs: Vec<(PackMeta, Vec<CompiledRule>)>,
}

/// True when `left` is a strictly higher semver-ish version than `right`.
/// Compares numeric components (major.minor.patch); non-numeric or shorter
/// components are treated as zero, making it deterministic and total.
pub(crate) fn semver_gt(left: &str, right: &str) -> bool {
    fn parts(v: &str) -> [u64; 3] {
        let mut out = [0u64; 3];
        for (i, chunk) in v.split('.').take(3).enumerate() {
            out[i] = chunk.parse().unwrap_or(0);
        }
        out
    }
    parts(left) > parts(right)
}

impl CompiledRule {
    /// The first declared language (used for report metadata and fixture choices).
    pub fn primary_language(&self) -> Option<Language> {
        self.def.languages.first().copied()
    }

    /// Runs this rule against a source string and returns findings (no file parsing).
    pub fn check_source(&self, source: &str, path: &Path) -> Vec<Finding> {
        self.check(source, path)
    }
}

impl PackRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// A registry preloaded with the built-in packs.
    pub fn with_built_in() -> Result<Self, PackError> {
        let packs = built_in_packs()?;
        Ok(Self { packs })
    }

    /// Keeps only the packs whose manifest name is in `wanted` (in registry order).
    /// Empty slice keeps everything.
    pub fn select_packs(&mut self, wanted: &[String]) {
        if wanted.is_empty() {
            return;
        }
        self.packs
            .retain(|(meta, _)| wanted.iter().any(|w| w == &meta.name));
    }

    /// Loads packs from directories, in order. Returns duplicates as an error.
    pub fn load_dirs(&mut self, dirs: &[PathBuf]) -> Result<(), PackError> {
        let mut seen = std::collections::HashMap::new();
        for rule in self.iter() {
            seen.insert(rule.def.id.clone(), rule.def.source.clone());
        }
        for dir in dirs {
            let (meta, rules) = load_pack_dir(dir)?;
            let mut compiled = Vec::new();
            for rule in rules {
                let was_compiled = CompiledRule::compile(rule);
                let rule = match was_compiled {
                    Ok(r) => r,
                    Err(error) => {
                        let (rule, message) = *error;
                        return Err(PackError::Validate {
                            message: format!(
                                "rule '{}' in '{}': {message}",
                                rule.id,
                                dir.display()
                            ),
                        });
                    }
                };
                if let Some(first) = seen.insert(rule.def.id.clone(), rule.def.source.clone()) {
                    return Err(PackError::DuplicateId {
                        id: rule.def.id.clone(),
                        first,
                        second: rule.def.source.clone(),
                    });
                }
                compiled.push(rule);
            }
            self.packs.push((meta, compiled));
        }
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &CompiledRule> {
        self.packs.iter().flat_map(|(_, rules)| rules.iter())
    }

    pub fn count(&self) -> usize {
        self.packs.iter().map(|(_, r)| r.len()).sum()
    }

    pub fn pack_names(&self) -> Vec<String> {
        self.packs
            .iter()
            .map(|(meta, _)| meta.name.clone())
            .collect()
    }

    /// Loaded rules grouped by declared category ("uncategorized" when a
    /// rule declares none), as (category, rule count) sorted by category.
    /// Lets reports list every category — including ones with zero findings.
    pub fn rule_categories(&self) -> Vec<(String, usize)> {
        let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
        for rule in self.iter() {
            let category = rule
                .def
                .category
                .clone()
                .unwrap_or_else(|| "uncategorized".into());
            *counts.entry(category).or_default() += 1;
        }
        counts.into_iter().collect()
    }

    pub fn cache_namespace(&self) -> String {
        let mut material = String::new();
        for (meta, rules) in &self.packs {
            material.push_str(&meta.name);
            material.push('\0');
            material.push_str(&meta.version);
            material.push('\0');
            for rule in rules {
                material.push_str(&rule.def.id);
                material.push('\0');
                material.push_str(&rule.def.description);
                material.push('\0');
                if let Some(pattern) = &rule.def.pattern {
                    material.push_str(&pattern.regex);
                    material.push('\0');
                    if let Some(not_regex) = &pattern.not_regex {
                        material.push_str(not_regex);
                    }
                }
                if let Some(query) = &rule.def.query {
                    material.push_str(&query.tree_sitter);
                    material.push('\0');
                    if let Some(anchor) = &query.anchor {
                        material.push_str(anchor);
                        material.push('\0');
                    }
                    if let Some(not_regex) = &query.not_regex {
                        material.push_str(not_regex);
                    }
                }
                if let Some(taint) = &rule.def.taint {
                    for source in &taint.sources {
                        material.push_str(source);
                        material.push('\0');
                    }
                    for sanitizer in &taint.sanitizers {
                        material.push_str(sanitizer);
                        material.push('\0');
                    }
                    for sink in &taint.sinks {
                        material.push_str(sink);
                        material.push('\0');
                    }
                }
            }
        }
        format!(
            "{}:{}",
            CACHE_SCHEMA,
            crate::cache::hash_bytes(material.as_bytes())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Parser;

    fn write_pack(dir: &Path, manifest: &str, rule_files: &[(&str, &str)]) {
        std::fs::create_dir_all(dir.join("rules")).unwrap();
        std::fs::write(dir.join("pack.toml"), manifest).unwrap();
        for (name, content) in rule_files {
            std::fs::write(dir.join("rules").join(name), content).unwrap();
        }
    }

    #[test]
    fn loads_a_pack_and_compiles_pattern_rules_in_sorted_order() {
        let tmp = std::env::temp_dir().join(format!(
            "hawk-pack-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        write_pack(
            &tmp,
            "name = \"java-pack\"\nversion = \"1.0.0\"",
            &[
                (
                    "b.rule.toml",
                    "id = \"java.security.runtime-exec\"\nname = \"Runtime exec\"\ndescription = \"d\"\nseverity = \"high\"\nconfidence = \"high\"\nlanguages = [\"java\"]\ncwe = \"CWE-78\"\n\n[pattern]\nregex = \"Runtime\\\\.getRuntime\\\\(\\\\)\\\\.exec\"\n",
                ),
                (
                    "a.rule.toml",
                    "id = \"java.security.cookie\"\nname = \"Cookie\"\ndescription = \"d\"\nseverity = \"medium\"\nlanguages = [\"java\"]\n\n[pattern]\nregex = \"addCookie\"\n",
                ),
            ],
        );

        let mut registry = PackRegistry::new();
        registry
            .load_dirs(std::slice::from_ref(&tmp))
            .expect("pack should load");
        assert_eq!(registry.count(), 2);

        let ids: Vec<_> = registry.iter().map(|r| r.id()).collect();
        assert_eq!(ids, ["java.security.cookie", "java.security.runtime-exec"]);

        let runtime = registry
            .iter()
            .find(|r| r.id() == "java.security.runtime-exec")
            .unwrap();
        let findings = runtime.check(
            "class A { void x() { Runtime.getRuntime().exec(cmd); } }",
            Path::new("A.java"),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].confidence, Confidence::High);
        assert_eq!(findings[0].cwe.as_deref(), Some("CWE-78"));
        assert!(!findings[0].fingerprint.is_empty());

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn semver_comparison_handles_numeric_components() {
        assert!(semver_gt("0.10.0", "0.9.0"));
        assert!(!semver_gt("0.9.0", "0.10.0"));
        assert!(!semver_gt("1.0.0", "1.0.0"));
        assert!(semver_gt("2.0.0", "1.99.99"));
        assert!(!semver_gt("0.1.0", "0.1.0-beta"));
    }

    #[test]
    fn duplicate_rule_id_is_an_explicit_error() {
        let tmp = std::env::temp_dir().join(format!(
            "hawk-pack-dup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        write_pack(
            &tmp,
            "name = \"p\"\nversion = \"1\"",
            &[
                ("r1.toml", "id = \"dup\"\nname = \"n\"\ndescription = \"d\"\nseverity = \"info\"\nlanguages = [\"java\"]\n[pattern]\nregex = \"x\"\n"),
                ("r2.toml", "id = \"dup\"\nname = \"n\"\ndescription = \"d\"\nseverity = \"low\"\nlanguages = [\"java\"]\n[pattern]\nregex = \"y\"\n"),
            ],
        );

        let mut registry = PackRegistry::new();
        let error = registry
            .load_dirs(std::slice::from_ref(&tmp))
            .expect_err("must fail");
        assert!(matches!(error, PackError::DuplicateId { .. }));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn unknown_severity_is_an_explicit_error() {
        let tmp = std::env::temp_dir().join(format!(
            "hawk-pack-bad-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        write_pack(
            &tmp,
            "name = \"p\"\nversion = \"1\"",
            &[(
                "r1.toml",
                "id = \"r1\"\ndescription = \"d\"\nseverity = \"extreme\"\nlanguages = [\"java\"]\n[pattern]\nregex = \"x\"\n",
            )],
        );

        let mut registry = PackRegistry::new();
        let error = registry
            .load_dirs(std::slice::from_ref(&tmp))
            .expect_err("must fail");
        assert!(matches!(error, PackError::Validate { .. }));

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn not_regex_excludes_matching_text_and_fix_is_attached() {
        // Build the rule directly (bypassing TOML escaping) to verify engine
        // behavior deterministically.
        let rule = CompiledRule::compile(Rule {
            id: "rule.a".into(),
            name: "Rule A".into(),
            description: "d".into(),
            recommendation: None,
            category: None,
            severity: Severity::High,
            confidence: Confidence::High,
            languages: vec![Language::Java],
            cwe: None,
            owasp: None,
            framework: None,
            pattern: Some(PatternRule {
                regex: r"exec\(".to_string(),
                not_regex: Some(r"'safe'".to_string()),
                fix: Some("avoid exec".to_string()),
            }),
            taint: None,
            query: None,
            source: PathBuf::from("inline"),
        })
        .expect("rule should compile");

        // A call carrying the excluded literal is suppressed.
        let excluded = rule.check("exec('safe')", Path::new("A.java"));
        assert!(
            excluded.is_empty(),
            "not-regex should exclude the safe literal"
        );

        // A normal call fires and carries the fix as recommendation.
        let fired = rule.check("exec(userInput);", Path::new("A.java"));
        assert_eq!(fired.len(), 1);
        assert_eq!(
            fired[0].recommendation.as_deref(),
            Some("Suggested fix: avoid exec")
        );
    }

    #[test]
    fn query_rule_matches_ast_nodes_and_reports_findings() {
        let query_rule = CompiledRule::compile(Rule {
            id: "java.security.trace-log".into(),
            name: "Tracing call".into(),
            description: "Logging of sensitive operation".into(),
            recommendation: None,
            category: Some("logging".into()),
            severity: Severity::Low,
            confidence: Confidence::Low,
            languages: vec![Language::Java],
            cwe: None,
            owasp: None,
            framework: None,
            pattern: None,
            taint: None,
            query: Some(QueryRule {
                tree_sitter: "(method_invocation) @call".into(),
                anchor: None,
                not_regex: None,
            }),
            source: PathBuf::from("inline"),
        })
        .expect("query rule should compile");

        let parser = crate::parser::TreeSitterParser {
            language: Language::Java,
        };
        let source = "class A { void m() { a.b(); c.d(); } }";
        let tree = parser.parse(source).expect("java should parse");

        let findings = query_rule.check_parsed(&tree, source, Path::new("A.java"));
        // captures: method_invocation for a.b() and c.d()
        assert_eq!(
            findings.len(),
            2,
            "expected two query matches, got {}",
            findings.len()
        );
    }

    #[test]
    fn query_anchor_selects_the_finding_node_and_not_regex_filters_matches() {
        let query_rule = CompiledRule::compile(Rule {
            id: "java.security.dynamic-classload".into(),
            name: "Dynamic class loading".into(),
            description: "Reflection with a non-literal class name".into(),
            recommendation: None,
            category: Some("reflection".into()),
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            languages: vec![Language::Java],
            cwe: None,
            owasp: None,
            framework: None,
            pattern: None,
            taint: None,
            query: Some(QueryRule {
                tree_sitter: r#"
(method_invocation
  object: (identifier) @object
  name: (identifier) @name
  arguments: (argument_list) @args
) @call
(#eq? @name "forName")
"#
                .into(),
                anchor: Some("call".into()),
                not_regex: Some("forName\\s*\\(\\s*[\"']".into()),
            }),
            source: PathBuf::from("inline"),
        })
        .expect("query rule should compile");

        let parser = crate::parser::TreeSitterParser {
            language: Language::Java,
        };
        // Literal class name is filtered out by not-regex; the variable-driven
        // call is anchored at the whole method_invocation.
        let source = "class A { void m(String n) { Class.forName(\"a.B\"); Class.forName(n); } }";
        let tree = parser.parse(source).expect("java should parse");

        let findings = query_rule.check_parsed(&tree, source, Path::new("A.java"));
        assert_eq!(findings.len(), 1, "literal reflection must be filtered");
        assert!(findings[0].message.contains("Dynamic class loading"));
    }

    #[test]
    fn every_built_in_rule_has_a_fixture_that_passes() {
        let registry = PackRegistry::with_built_in().expect("built-ins should load");
        let mut missing = Vec::new();
        let mut failed = Vec::new();

        for (meta, rules) in &registry.packs {
            let pack_dir = match meta.name.as_str() {
                "java" => "java",
                "javascript" => "js",
                "python" => "python",
                "go" => "go",
                "korea-secure-coding" => "korea",
                other => other,
            };
            let fixtures_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("rules")
                .join(pack_dir)
                .join("fixtures");
            for rule in rules {
                let fixture = std::fs::read_dir(&fixtures_dir)
                    .map(|entries| {
                        entries
                            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                            .find(|path| {
                                path.file_name().and_then(|name| name.to_str()).is_some_and(
                                    |name| name.starts_with(&format!("{}.", rule.id())),
                                )
                            })
                    })
                    .ok()
                    .flatten();
                let Some(fixture) = fixture else {
                    missing.push(rule.id().to_string());
                    continue;
                };
                let content = match std::fs::read_to_string(&fixture) {
                    Ok(content) => content,
                    Err(error) => {
                        failed.push(format!("{}: cannot read fixture: {error}", rule.id()));
                        continue;
                    }
                };
                let language = crate::language::Language::from_path(&fixture);
                let findings = if language == crate::language::Language::Unknown {
                    rule.check_source(&content, &fixture)
                } else {
                    let registry = crate::parser::ParserRegistry::default();
                    match registry.parser_for(language) {
                        Some(parser) => match parser.parse(&content) {
                            Ok(tree) => rule.check_parsed(&tree, &content, &fixture),
                            Err(error) => {
                                failed.push(format!(
                                    "{}: fixture does not parse: {error}",
                                    rule.id()
                                ));
                                continue;
                            }
                        },
                        None => rule.check_source(&content, &fixture),
                    }
                };
                let annotations = crate::fixture::parse_annotations(&content);
                if annotations.is_empty() {
                    failed.push(format!(
                        "{}: fixture has no ruleid/ok annotations",
                        rule.id()
                    ));
                    continue;
                }
                let rule_id = rule.id().to_string();
                let verdicts = crate::fixture::evaluate(&annotations, &findings, |annotated| {
                    annotated == rule_id
                });
                if !verdicts.is_empty() {
                    let detail: Vec<String> =
                        verdicts.iter().map(crate::fixture::verdict_line).collect();
                    failed.push(format!("{}: {}", rule.id(), detail.join("; ")));
                }
            }
        }

        assert!(
            missing.is_empty(),
            "rules without fixtures: {}",
            missing.join(", ")
        );
        assert!(
            failed.is_empty(),
            "fixture failures:\n{}",
            failed.join("\n")
        );
    }
}
