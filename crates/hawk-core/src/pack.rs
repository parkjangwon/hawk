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
            match crate::pack_query::execute_query(
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
                    for annotation in &taint.param_annotations {
                        material.push_str(annotation);
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
#[path = "pack_tests.rs"]
mod tests;
