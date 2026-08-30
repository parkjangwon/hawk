//! Pack and rule loading: TOML parsing, directory discovery, and validation.
//!
//! Kept separate from the runtime rule model (`pack.rs`) so the executable
//! types stay small and focused on analysis rather than I/O.

use std::path::{Path, PathBuf};

use crate::{
    finding::{Confidence, Severity},
    language::Language,
    pack::{semver_gt, CompiledRule, PackError, PackMeta, PatternRule, QueryRule, Rule},
};
use serde::Deserialize;

// ---------- raw TOML shapes ----------

#[derive(Debug, Deserialize)]
struct RawManifest {
    name: String,
    version: String,
    description: Option<String>,
    authors: Option<Vec<String>>,
    #[serde(default)]
    metadata: RawManifestMetadata,
}

#[derive(Debug, Default, Deserialize)]
struct RawManifestMetadata {
    #[serde(rename = "compat")]
    compat: Option<RawCompatibility>,
}

#[derive(Debug, Deserialize)]
struct RawCompatibility {
    /// Minimum Hawk rule-schema version this pack requires (semver-like).
    #[serde(rename = "min-hawk")]
    min_hawk: Option<String>,
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
    framework: Option<String>,
    pattern: Option<RawPattern>,
    query: Option<RawQuery>,
    taint: Option<RawTaint>,
}

#[derive(Debug, Deserialize)]
struct RawPattern {
    regex: String,
    #[serde(rename = "not-regex")]
    not_regex: Option<String>,
    fix: Option<String>,
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
        min_hawk: raw.metadata.compat.and_then(|m| m.min_hawk),
    };

    let mut rule_files = Vec::new();
    let rules_dir = dir.join("rules");
    if !rules_dir.is_dir() {
        return Err(PackError::Validate {
            message: format!("pack directory '{}' has no rules directory", dir.display()),
        });
    }
    collect_rule_files(&rules_dir, &mut rule_files)?;
    rule_files.sort();
    if rule_files.is_empty() {
        return Err(PackError::Validate {
            message: format!("pack directory '{}' contains no .toml rules", dir.display()),
        });
    }

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
    let entries = std::fs::read_dir(dir).map_err(|e| PackError::Read {
        path: dir.to_path_buf(),
        source: e.to_string(),
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| PackError::Validate {
            message: format!("unreadable rules entry: {e}"),
        })?;
        let path = entry.path();
        if path.is_dir() {
            collect_rule_files(&path, out)?;
        } else if path.is_file()
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
        "pattern" => raw.pattern.map(|p| PatternRule {
            regex: p.regex,
            not_regex: p.not_regex,
            fix: p.fix,
        }),
        _ => None,
    };
    let query = match capability {
        "query" => raw.query.map(|q| QueryRule {
            tree_sitter: q.tree_sitter,
        }),
        _ => None,
    };

    let taint = match capability {
        "taint" => raw.taint.map(|t| crate::taint::TaintConfig {
            sources: t.sources,
            sanitizers: t.sanitizers,
            sinks: t.sinks,
        }),
        _ => None,
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
        framework: raw.framework,
        pattern,
        taint,
        query,
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

/// Same as `parse_rule` but with an explicit source path (e.g. a virtual
/// `include_str!` path) for diagnostics.
fn parse_rule_str(content: &str, path: PathBuf) -> Result<Rule, PackError> {
    let raw: RawRule = toml::from_str(content).map_err(|e| PackError::Parse {
        path: path.clone(),
        source: e.to_string(),
    })?;
    parse_rule(raw, path)
}

fn parse_manifest_str(content: &str, path: PathBuf) -> Result<PackMeta, PackError> {
    let raw: RawManifest = toml::from_str(content).map_err(|e| PackError::Parse {
        path,
        source: e.to_string(),
    })?;
    Ok(PackMeta {
        name: raw.name,
        version: raw.version,
        description: raw.description,
        authors: raw.authors,
        min_hawk: raw.metadata.compat.and_then(|m| m.min_hawk),
    })
}

/// The built-in rule packs embedded in the binary, as (manifest, rules) pairs
/// in a fixed order. Keep this list in sync with `rules/{java,js,python,go}`;
/// the loader is intentionally the single source of truth.
pub fn built_in_packs() -> Result<Vec<(PackMeta, Vec<CompiledRule>)>, PackError> {
    let packs: &[(&str, &[(&str, &str)])] = &[
        (
            include_str!("../rules/java/pack.toml"),
            &[
                (
                    "built-in:java/java.security.runtime-exec.rule.toml",
                    include_str!("../rules/java/java.security.runtime-exec.rule.toml"),
                ),
                (
                    "built-in:java/java.security.process-builder.rule.toml",
                    include_str!("../rules/java/java.security.process-builder.rule.toml"),
                ),
                (
                    "built-in:java/java.security.cookie.rule.toml",
                    include_str!("../rules/java/java.security.cookie.rule.toml"),
                ),
                (
                    "built-in:java/java.security.sql-injection.rule.toml",
                    include_str!("../rules/java/java.security.sql-injection.rule.toml"),
                ),
                (
                    "built-in:java/java.security.command-injection.rule.toml",
                    include_str!("../rules/java/java.security.command-injection.rule.toml"),
                ),
                (
                    "built-in:java/java.security.xss.rule.toml",
                    include_str!("../rules/java/java.security.xss.rule.toml"),
                ),
                (
                    "built-in:java/java.security.path-traversal.rule.toml",
                    include_str!("../rules/java/java.security.path-traversal.rule.toml"),
                ),
                (
                    "built-in:java/java.security.ssrf.rule.toml",
                    include_str!("../rules/java/java.security.ssrf.rule.toml"),
                ),
                (
                    "built-in:java/java.security.spring-query.rule.toml",
                    include_str!("../rules/java/java.security.spring-query.rule.toml"),
                ),
            ],
        ),
        (
            include_str!("../rules/js/pack.toml"),
            &[
                (
                    "built-in:js/javascript.security.eval.rule.toml",
                    include_str!("../rules/js/javascript.security.eval.rule.toml"),
                ),
                (
                    "built-in:js/javascript.security.inner-html.rule.toml",
                    include_str!("../rules/js/javascript.security.inner-html.rule.toml"),
                ),
                (
                    "built-in:js/javascript.security.child-process.rule.toml",
                    include_str!("../rules/js/javascript.security.child-process.rule.toml"),
                ),
                (
                    "built-in:js/javascript.security.document-write.rule.toml",
                    include_str!("../rules/js/javascript.security.document-write.rule.toml"),
                ),
                (
                    "built-in:js/javascript.security.open-redirect.rule.toml",
                    include_str!("../rules/js/javascript.security.open-redirect.rule.toml"),
                ),
            ],
        ),
        (
            include_str!("../rules/python/pack.toml"),
            &[
                (
                    "built-in:python/python.security.os-system.rule.toml",
                    include_str!("../rules/python/python.security.os-system.rule.toml"),
                ),
                (
                    "built-in:python/python.security.pickle.rule.toml",
                    include_str!("../rules/python/python.security.pickle.rule.toml"),
                ),
                (
                    "built-in:python/python.security.subprocess-shell.rule.toml",
                    include_str!("../rules/python/python.security.subprocess-shell.rule.toml"),
                ),
                (
                    "built-in:python/python.security.ssti.rule.toml",
                    include_str!("../rules/python/python.security.ssti.rule.toml"),
                ),
                (
                    "built-in:python/python.security.eval-exec.rule.toml",
                    include_str!("../rules/python/python.security.eval-exec.rule.toml"),
                ),
                (
                    "built-in:python/python.security.ssrf.rule.toml",
                    include_str!("../rules/python/python.security.ssrf.rule.toml"),
                ),
            ],
        ),
        (
            include_str!("../rules/go/pack.toml"),
            &[(
                "built-in:go/go.security.exec-command.rule.toml",
                include_str!("../rules/go/go.security.exec-command.rule.toml"),
            )],
        ),
        (
            include_str!("../rules/korea/pack.toml"),
            &[
                (
                    "built-in:rules/korea/korea.java.hardcoded-password.rule.toml",
                    include_str!("../rules/korea/korea.java.hardcoded-password.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.weak-random.rule.toml",
                    include_str!("../rules/korea/korea.java.weak-random.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.stacktrace-public.rule.toml",
                    include_str!("../rules/korea/korea.java.stacktrace-public.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.hardcoded-key.rule.toml",
                    include_str!("../rules/korea/korea.java.hardcoded-key.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.code-injection.rule.toml",
                    include_str!("../rules/korea/korea.java.code-injection.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.open-redirect.rule.toml",
                    include_str!("../rules/korea/korea.java.open-redirect.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.xxe.rule.toml",
                    include_str!("../rules/korea/korea.java.xxe.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.ldap-injection.rule.toml",
                    include_str!("../rules/korea/korea.java.ldap-injection.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.http-response-splitting.rule.toml",
                    include_str!("../rules/korea/korea.java.http-response-splitting.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.weak-crypto-algorithm.rule.toml",
                    include_str!("../rules/korea/korea.java.weak-crypto-algorithm.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.short-crypto-key.rule.toml",
                    include_str!("../rules/korea/korea.java.short-crypto-key.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.weak-signature.rule.toml",
                    include_str!("../rules/korea/korea.java.weak-signature.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.insecure-certificate-validation.rule.toml",
                    include_str!(
                        "../rules/korea/korea.java.insecure-certificate-validation.rule.toml"
                    ),
                ),
                (
                    "built-in:rules/korea/korea.java.comment-sensitive-info.rule.toml",
                    include_str!("../rules/korea/korea.java.comment-sensitive-info.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.unsigned-code-download.rule.toml",
                    include_str!("../rules/korea/korea.java.unsigned-code-download.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.toctou.rule.toml",
                    include_str!("../rules/korea/korea.java.toctou.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.infinite-loop.rule.toml",
                    include_str!("../rules/korea/korea.java.infinite-loop.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.improper-exception.rule.toml",
                    include_str!("../rules/korea/korea.java.improper-exception.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.unsafe-deserialization.rule.toml",
                    include_str!("../rules/korea/korea.java.unsafe-deserialization.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.debug-code.rule.toml",
                    include_str!("../rules/korea/korea.java.debug-code.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.unsafe-api.rule.toml",
                    include_str!("../rules/korea/korea.java.unsafe-api.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.java.raw-socket.rule.toml",
                    include_str!("../rules/korea/korea.java.raw-socket.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.js.sql-injection.rule.toml",
                    include_str!("../rules/korea/korea.js.sql-injection.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.js.path-traversal.rule.toml",
                    include_str!("../rules/korea/korea.js.path-traversal.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.js.xss-react.rule.toml",
                    include_str!("../rules/korea/korea.js.xss-react.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.js.command-injection.rule.toml",
                    include_str!("../rules/korea/korea.js.command-injection.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.js.xxe.rule.toml",
                    include_str!("../rules/korea/korea.js.xxe.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.js.ldap-injection.rule.toml",
                    include_str!("../rules/korea/korea.js.ldap-injection.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.js.ssrf.rule.toml",
                    include_str!("../rules/korea/korea.js.ssrf.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.js.weak-crypto.rule.toml",
                    include_str!("../rules/korea/korea.js.weak-crypto.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.js.weak-random.rule.toml",
                    include_str!("../rules/korea/korea.js.weak-random.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.js.infinite-loop.rule.toml",
                    include_str!("../rules/korea/korea.js.infinite-loop.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.js.error-message-info.rule.toml",
                    include_str!("../rules/korea/korea.js.error-message-info.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.js.improper-exception.rule.toml",
                    include_str!("../rules/korea/korea.js.improper-exception.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.js.debug-code.rule.toml",
                    include_str!("../rules/korea/korea.js.debug-code.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.py.sql-injection.rule.toml",
                    include_str!("../rules/korea/korea.py.sql-injection.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.py.path-traversal.rule.toml",
                    include_str!("../rules/korea/korea.py.path-traversal.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.py.xxe.rule.toml",
                    include_str!("../rules/korea/korea.py.xxe.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.py.weak-crypto.rule.toml",
                    include_str!("../rules/korea/korea.py.weak-crypto.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.py.weak-random.rule.toml",
                    include_str!("../rules/korea/korea.py.weak-random.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.py.toctou.rule.toml",
                    include_str!("../rules/korea/korea.py.toctou.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.py.infinite-loop.rule.toml",
                    include_str!("../rules/korea/korea.py.infinite-loop.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.py.error-message-info.rule.toml",
                    include_str!("../rules/korea/korea.py.error-message-info.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.py.improper-exception.rule.toml",
                    include_str!("../rules/korea/korea.py.improper-exception.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.py.unsafe-deserialization.rule.toml",
                    include_str!("../rules/korea/korea.py.unsafe-deserialization.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.js.xss.rule.toml",
                    include_str!("../rules/korea/korea.js.xss.rule.toml"),
                ),
                (
                    "built-in:rules/korea/korea.py.xss.rule.toml",
                    include_str!("../rules/korea/korea.py.xss.rule.toml"),
                ),
            ],
        ),
    ];

    let mut loaded = Vec::with_capacity(packs.len());
    for (manifest, files) in packs {
        let meta = parse_manifest_str(manifest, PathBuf::from("built-in"))?;
        let mut rules = Vec::with_capacity(files.len());
        for (path, content) in *files {
            let rule = parse_rule_str(content, PathBuf::from(*path))?;
            let compiled = CompiledRule::compile(rule).map_err(|error| {
                let (rule, message) = *error;
                PackError::Validate {
                    message: format!("built-in rule '{}': {message}", rule.id),
                }
            })?;
            rules.push(compiled);
        }
        loaded.push((meta, rules));
    }
    Ok(loaded)
}

/// Validates a pack directory and returns its manifest metadata (used by
/// `hawk rule validate`). Invalid packs fail loudly.
pub fn validate_pack_dir(dir: &Path) -> Result<PackMeta, PackError> {
    // Reuse the loader; any parse/validate error propagates.
    let (meta, rules) = load_pack_dir(dir)?;
    if let Some(min) = &meta.min_hawk {
        if semver_gt(min, env!("CARGO_PKG_VERSION")) {
            return Err(PackError::Validate {
                message: format!(
                    "pack '{}' requires hawk >= {min}, but this is {}",
                    meta.name,
                    env!("CARGO_PKG_VERSION")
                ),
            });
        }
    }
    for rule in rules {
        CompiledRule::compile(rule).map_err(|error| {
            let (rule, message) = *error;
            PackError::Validate {
                message: format!("rule '{}': {message}", rule.id),
            }
        })?;
    }
    Ok(meta)
}

/// Loads a single rule file (outside any pack), used by `hawk rule test`.
pub fn load_single_rule_file(path: &Path) -> Result<CompiledRule, PackError> {
    let content = std::fs::read_to_string(path).map_err(|e| PackError::Read {
        path: path.to_path_buf(),
        source: e.to_string(),
    })?;
    let rule = parse_rule_str(&content, path.to_path_buf())?;
    CompiledRule::compile(rule).map_err(|error| {
        let (rule, message) = *error;
        PackError::Validate {
            message: format!("rule '{}': {message}", rule.id),
        }
    })
}
