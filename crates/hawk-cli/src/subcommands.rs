//! Subcommand implementations (`hawk rule ...`, `hawk baseline ...`, `hawk config`).
//!
//! Kept separate from the CLI entry point (`main.rs`) so argument parsing
//! stays small and each command family is independently reviewable.

use crate::{build_scanner, fatal, RunOutcome};
use hawk_core::config::Config;

/// Dispatches the `hawk rule` subcommand family.
pub(crate) fn run_rule_command(args: &[String]) -> RunOutcome {
    let Some(sub) = args.first() else {
        return fatal("missing rule subcommand (list, explain, test)".into());
    };
    match sub.as_str() {
        "list" => run_rule_list(&args[1..]),
        "explain" => run_rule_explain(&args[1..]),
        "test" => run_rule_test(&args[1..]),
        "validate" => run_rule_validate(&args[1..]),
        "help" | "--help" | "-h" => {
            println!("Usage: hawk rule <list|explain <id>|test <rule-file> <fixture>>");
            RunOutcome::Help
        }
        other => fatal(format!("unknown rule subcommand '{other}'")),
    }
}

fn run_rule_list(args: &[String]) -> RunOutcome {
    if !args.is_empty() {
        return fatal("rule list takes no arguments".into());
    }
    let registry = match hawk_core::pack::PackRegistry::with_built_in() {
        Ok(registry) => registry,
        Err(error) => return fatal(format!("rule pack error: {error}")),
    };
    for rule in registry.iter() {
        println!(
            "{} [{}] {} {}",
            rule.id(),
            rule.primary_language()
                .map(|l| format!("{l:?}"))
                .unwrap_or_else(|| "?".into()),
            rule.severity(),
            rule.def.name
        );
    }
    RunOutcome::Clean
}

fn run_rule_explain(args: &[String]) -> RunOutcome {
    let Some(id) = args.first() else {
        return fatal("rule explain requires a rule id".into());
    };
    let registry = match hawk_core::pack::PackRegistry::with_built_in() {
        Ok(registry) => registry,
        Err(error) => return fatal(format!("rule pack error: {error}")),
    };
    let Some(rule) = registry.iter().find(|r| r.id() == id) else {
        return fatal(format!("unknown rule '{id}'"));
    };
    let def = &rule.def;
    println!("{id}");
    println!("  name: {}", def.name);
    println!("  severity: {}", def.severity);
    println!("  confidence: {}", def.confidence);
    println!("  languages: {:?}", def.languages);
    if let Some(category) = &def.category {
        println!("  category: {category}");
    }
    if let Some(cwe) = &def.cwe {
        println!("  cwe: {cwe}");
    }
    if let Some(owasp) = &def.owasp {
        println!("  owasp: {owasp}");
    }
    println!("  description: {}", def.description);
    if let Some(recommendation) = &def.recommendation {
        println!("  recommendation: {recommendation}");
    }
    RunOutcome::Clean
}

/// Validates one or more rule files or pack directories without scanning.
fn run_rule_validate(args: &[String]) -> RunOutcome {
    if args.is_empty() {
        return fatal("rule validate requires a rule file or pack directory".into());
    }
    let mut failed = false;
    for target in args {
        let path = std::path::Path::new(target);
        if path.is_dir() {
            match hawk_core::pack::validate_pack_dir(path) {
                Ok(meta) => match &meta.min_hawk {
                    Some(min) => println!(
                        "{}: pack '{}' v{} — valid (requires hawk >= {})",
                        target, meta.name, meta.version, min
                    ),
                    None => println!("{}: pack '{}' v{} — valid", target, meta.name, meta.version),
                },
                Err(error) => {
                    eprintln!("{}: invalid — {error}", target);
                    failed = true;
                }
            }
        } else {
            match hawk_core::pack::load_single_rule_file(path) {
                Ok(rule) => println!("{}: '{}' — valid", target, rule.id()),
                Err(error) => {
                    eprintln!("{}: invalid — {error}", target);
                    failed = true;
                }
            }
        }
    }
    if failed {
        RunOutcome::Fatal
    } else {
        RunOutcome::Clean
    }
}

fn run_rule_test(args: &[String]) -> RunOutcome {
    let mut expected: Option<usize> = None;
    let mut positional = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--expected" => {
                expected = iter
                    .next()
                    .and_then(|v| v.parse::<usize>().ok())
                    .or_else(|| {
                        eprintln!("error: --expected requires a count");
                        None
                    });
                if expected.is_none() {
                    return RunOutcome::Fatal;
                }
            }
            other if other.starts_with('-') => {
                return fatal(format!("unknown option '{other}'"));
            }
            _ => positional.push(arg.clone()),
        }
    }

    let (rule_path, fixture) = match positional.as_slice() {
        [rule, fixture] => (rule.clone(), fixture.clone()),
        _ => return fatal("rule test requires <rule-file> <fixture-file>".into()),
    };

    let rule = match hawk_core::pack::load_single_rule_file(std::path::Path::new(&rule_path)) {
        Ok(rule) => rule,
        Err(error) => return fatal(format!("unable to load rule '{rule_path}': {error}")),
    };
    let source = match std::fs::read_to_string(&fixture) {
        Ok(source) => source,
        Err(error) => {
            return fatal(format!("unable to read fixture '{fixture}': {error}"));
        }
    };
    // Language compatibility: a rule must not run against a fixture written in
    // a language it does not declare.
    let fixture_language = hawk_core::language::Language::from_path(std::path::Path::new(&fixture));
    if fixture_language != hawk_core::language::Language::Unknown
        && !rule.languages().contains(&fixture_language)
    {
        return fatal(format!(
            "rule '{}' does not apply to language {:?} (fixture '{fixture}')",
            rule.id(),
            fixture_language
        ));
    }

    // Taint/query rules operate on the syntax tree; pattern rules on text.
    // Always prefer the parsed path when a parser exists for the fixture.
    let findings = match parse_fixture_for_language(&source, &fixture) {
        Some((tree, _language)) => {
            rule.check_parsed(&tree, &source, std::path::Path::new(&fixture))
        }
        None => rule.check_source(&source, std::path::Path::new(&fixture)),
    };

    // Semgrep-style inline annotations take precedence when present.
    let annotations = hawk_core::fixture::parse_annotations(&source);
    if !annotations.is_empty() {
        for annotation in &annotations {
            let label = match annotation.kind {
                hawk_core::fixture::AnnotationKind::RuleId => "ruleid",
                hawk_core::fixture::AnnotationKind::Ok => "ok",
            };
            println!("  {} {label}: {}", annotation.line, annotation.rule_id);
        }
        let rule_id = rule.id().to_string();
        let verdicts = hawk_core::fixture::evaluate(&annotations, &findings, |annotated_id| {
            annotated_id == rule_id
        });
        if verdicts.is_empty() {
            println!("ok: {} passed", rule.id());
            return RunOutcome::Clean;
        }
        for verdict in &verdicts {
            eprintln!("{}", hawk_core::fixture::verdict_line(verdict));
        }
        return RunOutcome::Fatal;
    }

    let got = findings.len();
    println!("{}: {got} finding(s) against '{fixture}'", rule.id());
    for finding in findings.iter().take(10) {
        println!(
            "  {}:{}:{} {}",
            finding.location.path.display(),
            finding.location.start_line,
            finding.location.start_column,
            finding.message
        );
    }
    match expected {
        Some(want) if want != got => {
            eprintln!("error: expected {want} finding(s), got {got}");
            RunOutcome::Fatal
        }
        _ => RunOutcome::Clean,
    }
}

/// Displays the effective configuration (defaults merged with hawk.toml).
pub(crate) fn run_config_command(args: &[String]) -> RunOutcome {
    if !args.is_empty() {
        return fatal("config takes no arguments".into());
    }
    let config = match hawk_core::config::Config::load() {
        Ok(config) => config,
        Err(error) => return fatal(format!("config error: {error}")),
    };
    match &config.source {
        Some(path) => println!("config source: {}", path.display()),
        None => println!("config source: none (using defaults)"),
    }
    println!("include: {:?}", config.include);
    println!("exclude: {:?}", config.exclude);
    println!("packs:   {:?}", config.packs);
    println!("pack-dirs: {:?}", config.pack_dirs);
    println!(
        "report:  format={:?} output={:?}",
        config.report.format, config.report.output
    );
    match &config.policy.exit_on_severity {
        Some(s) => println!("policy:  exit-on-severity={s}"),
        None => println!("policy:  exit-on-severity=<any finding>"),
    }
    RunOutcome::Clean
}

/// Parses fixture source into a syntax tree when a parser exists for its
/// language; returns (tree, language). `None` for unknown languages.
fn parse_fixture_for_language(
    source: &str,
    fixture: &str,
) -> Option<(hawk_core::parser::SyntaxTree, hawk_core::language::Language)> {
    let language = hawk_core::language::Language::from_path(std::path::Path::new(fixture));
    if language == hawk_core::language::Language::Unknown {
        return None;
    }
    let registry = hawk_core::parser::ParserRegistry::default();
    let parser = registry.parser_for(language)?;
    let tree = parser.parse(source).ok()?;
    Some((tree, language))
}
/// Dispatches the `hawk baseline` subcommand family.
pub(crate) fn run_baseline_command(args: &[String]) -> RunOutcome {
    let Some(sub) = args.first() else {
        return fatal("missing baseline subcommand (create, update, status)".into());
    };
    let config = match Config::load() {
        Ok(config) => config,
        Err(error) => return fatal(format!("config error: {error}")),
    };
    let path = hawk_core::baseline::baseline_path(&config.root_dir());
    let cache_dir = config.data_dir().join("cache");
    match sub.as_str() {
        "create" => run_baseline_create(&config, &path, &cache_dir),
        "update" => run_baseline_create(&config, &path, &cache_dir),
        "status" => run_baseline_status(&config, &path, &cache_dir),
        "help" | "--help" | "-h" => {
            println!("Usage: hawk baseline <create|update|status>");
            RunOutcome::Help
        }
        other => fatal(format!("unknown baseline subcommand '{other}'")),
    }
}

/// Scans the configured scope and stores all finding fingerprints as the new baseline.
fn run_baseline_create(
    config: &Config,
    path: &std::path::Path,
    cache_dir: &std::path::Path,
) -> RunOutcome {
    let scanner = match build_scanner(config, &config.packs, &config.pack_dirs) {
        Ok(s) => s.with_cache(cache_dir.to_path_buf()),
        Err(error) => return fatal(error),
    };
    let result = match scanner.scan_paths(&[]) {
        Ok(result) => result,
        Err(error) => return fatal(error.to_string()),
    };
    let fingerprints: Vec<String> = result
        .findings
        .iter()
        .map(|f| f.fingerprint.clone())
        .collect();
    let baseline = hawk_core::baseline::Baseline { fingerprints };
    match baseline.save(path) {
        Ok(()) => {
            println!(
                "baseline written with {} fingerprint(s) to {}",
                baseline.fingerprints.len(),
                path.display()
            );
            RunOutcome::Clean
        }
        Err(error) => fatal(format!("baseline error: {error}")),
    }
}

/// Compares the current findings against an existing baseline.
fn run_baseline_status(
    config: &Config,
    path: &std::path::Path,
    cache_dir: &std::path::Path,
) -> RunOutcome {
    let baseline = match hawk_core::baseline::Baseline::load(path) {
        Ok(baseline) => baseline,
        Err(error) => return fatal(format!("baseline error: {error}")),
    };
    let scanner = match build_scanner(config, &config.packs, &config.pack_dirs) {
        Ok(scanner) => scanner.with_cache(cache_dir.to_path_buf()),
        Err(error) => return fatal(error),
    };
    let result = match scanner.scan_paths(&[]) {
        Ok(result) => result,
        Err(error) => return fatal(error.to_string()),
    };
    let status = hawk_core::baseline::classify(
        &baseline,
        &result.findings.iter().cloned().collect::<Vec<_>>(),
    );
    println!(
        "baseline: {} existing, {} new, {} fixed",
        status.existing.len(),
        status.new.len(),
        status.fixed.len()
    );
    if status.new.is_empty() && status.fixed.is_empty() {
        RunOutcome::Clean
    } else {
        RunOutcome::Findings
    }
}
