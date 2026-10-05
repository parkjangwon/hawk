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
fn embedded_rule_set_matches_the_rules_directory() {
    // Defense in depth for the build.rs generation: the embedded pack list is
    // generated from `rules/`, so the counts must agree. A mismatch means the
    // generator skipped something (or a stray file appeared) — fail loudly
    // instead of silently shipping a subset of the rules.
    let registry = PackRegistry::with_built_in().expect("built-ins should load");
    let embedded = registry.count();

    let rules_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("rules");
    let mut on_disk = Vec::new();
    collect_rule_files_recursive(&rules_root, &mut on_disk);

    assert_eq!(
        embedded,
        on_disk.len(),
        "embedded rules ({embedded}) must match on-disk rule files ({}): {:?}",
        on_disk.len(),
        on_disk
    );
}

fn collect_rule_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if !name.starts_with('.') {
                collect_rule_files_recursive(&path, out);
            }
        } else if name.ends_with(".rule.toml") {
            out.push(path);
        }
    }
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
                            path.file_name()
                                .and_then(|name| name.to_str())
                                .is_some_and(|name| name.starts_with(&format!("{}.", rule.id())))
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
                            failed.push(format!("{}: fixture does not parse: {error}", rule.id()));
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
            let verdicts =
                crate::fixture::evaluate(&annotations, &findings, |annotated| annotated == rule_id);
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
