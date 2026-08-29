//! Rule Packs and data-driven rules (ADR-0004).
//!
//! A Rule Pack is a directory with a `pack.toml` manifest and `rules/*.rule.toml`
//! files. This module parses, validates, and loads packs into a rule registry that
//! the scanner can execute. Rules are data; the analysis algorithms live in the engine.

use std::path::{Path, PathBuf};

use crate::{
    finding::{Confidence, Finding, Severity, SourceLocation},
    language::Language,
};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackMeta {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub authors: Option<Vec<String>>,
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
    /// The regex pattern, when this rule is a pattern-based rule.
    pub pattern: Option<PatternRule>,
    /// Source file this rule was loaded from (for diagnostics).
    pub source: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternRule {
    pub regex: String,
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

// ---------- raw TOML shapes ----------

#[derive(Debug, Deserialize)]
struct RawManifest {
    name: String,
    version: String,
    description: Option<String>,
    authors: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    id: String,
    name: Option<String>,
    description: String,
    recommendation: Option<String>,
    category: Option<String>,
    severity: String,
    confidence: Option<String>,
    languages: Vec<String>,
    cwe: Option<String>,
    owasp: Option<String>,
    pattern: Option<RawPattern>,
    query: Option<RawQuery>,
    taint: Option<RawTaint>,
}

#[derive(Debug, Deserialize)]
struct RawPattern {
    regex: String,
}

#[derive(Debug, Deserialize)]
struct RawQuery {
    #[allow(dead_code)]
    tree_sitter: String, // slotted for Phase 3 (AST/query capability)
}

#[derive(Debug, Deserialize)]
struct RawTaint {
    #[allow(dead_code)]
    sources: Vec<String>,
    #[allow(dead_code)]
    sanitizers: Vec<String>,
    #[allow(dead_code)]
    sinks: Vec<String>,
}

impl RawRule {
    fn capability_marker(&self) -> Result<&'static str, String> {
        match (&self.pattern, &self.query, &self.taint) {
            (Some(_), None, None) => Ok("pattern"),
            (None, Some(_), None) => Ok("query"),
            (None, None, Some(_)) => Ok("taint"),
            _ => {
                Err("a rule must declare exactly one capability (pattern, query, or taint)".into())
            }
        }
    }
}

// ---------- runtime rule execution ----------

/// A compiled rule ready to run against a parsed file.
#[derive(Clone, Debug)]
pub struct CompiledRule {
    pub def: Rule,
    compiled_regex: Option<regex::Regex>,
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
        Ok(Self {
            def,
            compiled_regex: run_regex,
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
                .with_description(self.def.description.clone());
                if let Some(recommendation) = &self.def.recommendation {
                    finding = finding.with_recommendation(recommendation.clone());
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
                findings.push(finding);
            }
        }
        findings
    }
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
pub fn load_pack_dir(dir: &Path) -> Result<(PackMeta, Vec<Rule>), PackError> {
    let manifest_path = dir.join("pack.toml");
    if !manifest_path.is_file() {
        return Err(PackError::Validate {
            message: format!("pack directory '{}' has no pack.toml", dir.display()),
        });
    }
    let manifest_content =
        std::fs::read_to_string(&manifest_path).map_err(|e| PackError::Read {
            path: manifest_path.clone(),
            source: e.to_string(),
        })?;
    let raw: RawManifest = toml::from_str(&manifest_content).map_err(|e| PackError::Parse {
        path: manifest_path.clone(),
        source: e.to_string(),
    })?;
    let meta = PackMeta {
        name: raw.name,
        version: raw.version,
        description: raw.description,
        authors: raw.authors,
    };

    let mut rule_files = Vec::new();
    collect_rule_files(&dir.join("rules"), &mut rule_files)?;
    rule_files.sort();

    let mut rules = Vec::new();
    for file in rule_files {
        let content = std::fs::read_to_string(&file).map_err(|e| PackError::Read {
            path: file.clone(),
            source: e.to_string(),
        })?;
        let raw: RawRule = toml::from_str(&content).map_err(|e| PackError::Parse {
            path: file.clone(),
            source: e.to_string(),
        })?;
        rules.push(parse_rule(raw, file)?);
    }

    Ok((meta, rules))
}

fn collect_rule_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), PackError> {
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(|e| PackError::Validate {
                    message: format!("unreadable rules entry: {e}"),
                })?;
                let path = entry.path();
                if path.is_file()
                    && path
                        .extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e == "toml")
                {
                    out.push(path);
                }
            }
            Ok(())
        }
        Err(_) => Ok(()),
    }
}

fn parse_rule(raw: RawRule, path: PathBuf) -> Result<Rule, PackError> {
    let severity = parse_severity(&raw.severity).ok_or_else(|| PackError::Validate {
        message: format!("rule '{}' has unknown severity '{}'", raw.id, raw.severity),
    })?;
    let confidence = match raw.confidence.as_deref() {
        None | Some("medium") => Confidence::Medium,
        Some("low") => Confidence::Low,
        Some("high") => Confidence::High,
        Some(other) => {
            return Err(PackError::Validate {
                message: format!("rule '{}' has unknown confidence '{other}'", raw.id),
            })
        }
    };
    let mut languages = Vec::new();
    for lang in &raw.languages {
        match lang.as_str() {
            "java" => languages.push(Language::Java),
            "javascript" => languages.push(Language::JavaScript),
            "typescript" => languages.push(Language::TypeScript),
            "python" => languages.push(Language::Python),
            "go" => languages.push(Language::Go),
            other => {
                return Err(PackError::Validate {
                    message: format!("rule '{}' has unknown language '{other}'", raw.id),
                })
            }
        }
    }
    if languages.is_empty() {
        return Err(PackError::Validate {
            message: format!("rule '{}' declares no languages", raw.id),
        });
    }
    let capability = raw
        .capability_marker()
        .map_err(|message| PackError::Validate {
            message: format!("rule '{}': {message}", raw.id),
        })?;
    let pattern = match capability {
        "pattern" => raw.pattern.map(|p| PatternRule { regex: p.regex }),
        _ => None, // query/taint capabilities load without a pattern engine for now
    };

    Ok(Rule {
        id: raw.id,
        name: raw.name.unwrap_or_else(|| "rule".to_string()),
        description: raw.description,
        recommendation: raw.recommendation,
        category: raw.category,
        severity,
        confidence,
        languages,
        cwe: raw.cwe,
        owasp: raw.owasp,
        pattern,
        source: path,
    })
}

fn parse_severity(value: &str) -> Option<Severity> {
    match value {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

/// A registry of loaded, compiled rules in stable pack/file order.
#[derive(Debug, Default)]
pub struct PackRegistry {
    pub packs: Vec<(PackMeta, Vec<CompiledRule>)>,
}

impl PackRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads packs from directories, in order. Returns duplicates as an error.
    pub fn load_dirs(&mut self, dirs: &[PathBuf]) -> Result<(), PackError> {
        let mut seen = std::collections::HashMap::new();
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
