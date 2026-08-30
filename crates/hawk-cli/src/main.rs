use std::path::PathBuf;
use std::process::ExitCode;

use hawk_core::{
    config::{Config, ReportFormat},
    finding::Severity,
    git::GitScope,
    reporter::TerminalReporter,
    scan::Scanner,
    scope::{resolve, ScanTarget},
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The terminal outcome of an invocation, mapped to the exit-code contract
/// documented in ADR-0001.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    Help,
    Version,
    Clean,
    Findings,
    Degraded,
    Fatal,
}

impl RunOutcome {
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Help | Self::Version | Self::Clean => 0,
            Self::Fatal => 1,
            Self::Findings => 2,
            Self::Degraded => 3,
        }
    }
}

fn main() -> ExitCode {
    let outcome = run(std::env::args().skip(1));
    ExitCode::from(outcome.exit_code())
}

fn run<I>(args: I) -> RunOutcome
where
    I: IntoIterator<Item = String>,
{
    let args: Vec<String> = args.into_iter().collect();
    if args.first().map(String::as_str) == Some("rule") {
        return run_rule_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("baseline") {
        return run_baseline_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("config") {
        return run_config_command(&args[1..]);
    }
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return RunOutcome::Help;
    }
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("hawk {VERSION}");
        return RunOutcome::Version;
    }

    let config = match Config::load() {
        Ok(config) => config,
        Err(error) => return fatal(format!("config error: {error}")),
    };

    // Parse options. CLI values override project configuration.
    let mut git_mode: Option<GitScope> = None;
    let mut use_cache = true;
    let mut format: Option<String> = config_format(&config);
    let mut output: Option<PathBuf> = config.report.output.clone();
    let mut fail_on_severity: Option<Severity> = config.policy.exit_on_severity;
    let mut packs: Vec<String> = config.packs.clone();
    let mut pack_dirs: Vec<PathBuf> = config.pack_dirs.clone();
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut it = args.iter().peekable();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--changed" => git_mode = Some(GitScope::Changed),
            "--staged" => git_mode = Some(GitScope::Staged),
            "--no-cache" => use_cache = false,
            "--pack" => {
                packs.push(match it.next() {
                    Some(value) => value.clone(),
                    None => return fatal("--pack requires a pack name".to_string()),
                });
            }
            "--pack-dir" => {
                pack_dirs.push(match it.next() {
                    Some(value) => PathBuf::from(value),
                    None => return fatal("--pack-dir requires a directory".to_string()),
                });
            }
            "--fail-on-severity" => {
                let level = match it.next() {
                    Some(value) => value.clone(),
                    None => return fatal("--fail-on-severity requires a severity".to_string()),
                };
                fail_on_severity = Some(match parse_severity(&level) {
                    Some(s) => s,
                    None => {
                        return fatal(format!(
                        "unknown severity '{level}' (expected info, low, medium, high, critical)"
                    ))
                    }
                });
            }
            "--format" => {
                format = Some(match it.next() {
                    Some(value) => value.clone(),
                    None => return fatal("--format requires a value".to_string()),
                });
            }
            "--output" | "-o" => {
                output = Some(match it.next() {
                    Some(value) => PathBuf::from(value),
                    None => return fatal("--output requires a path".to_string()),
                });
            }
            "--" => {
                paths.extend(it.cloned().map(PathBuf::from));
                break;
            }
            other if other.starts_with('-') => {
                return fatal(format!("unknown option '{other}'"));
            }
            _ => paths.push(PathBuf::from(arg)),
        }
    }

    let mut scanner = match Scanner::built_in() {
        Ok(scanner) => scanner.with_excludes(config.exclude.clone()),
        Err(error) => return fatal(error.to_string()),
    };
    if let Err(error) = scanner.load_pack_dirs(&pack_dirs) {
        return fatal(error.to_string());
    }
    if !packs.is_empty() {
        scanner.select_packs(&packs);
    }

    // Git-aware modes resolve explicit paths to changed/staged files first.
    let targets = if let Some(mode) = git_mode {
        let cwd = std::env::current_dir().expect("current directory should exist");
        match hawk_core::git::changed_files(&cwd, mode) {
            Ok(files) => files.into_iter().map(ScanTarget::File).collect::<Vec<_>>(),
            Err(error) => return fatal(error.to_string()),
        }
    } else {
        let configured_paths = if paths.is_empty() {
            config
                .include
                .iter()
                .map(|path| config.root_dir().join(path))
                .collect::<Vec<_>>()
        } else {
            paths.clone()
        };
        let refs: Vec<_> = configured_paths.iter().map(PathBuf::as_path).collect();
        match resolve(&refs) {
            Ok(targets) => targets,
            Err(error) => {
                return fatal(match error {
                    hawk_core::scope::ScopeError::PathNotFound(path) => {
                        format!("path not found: {}", path.display())
                    }
                    hawk_core::scope::ScopeError::MetadataUnavailable { path } => {
                        format!("unable to determine path type: {}", path.display())
                    }
                });
            }
        }
    };

    if use_cache {
        // Cache lives in .hawk/cache under the project root. Best-effort writes
        // never turn a correct scan into an operational failure.
        scanner = scanner.with_cache(config.data_dir().join("cache"));
    }

    let started = std::time::Instant::now();
    let result = match scanner.scan_targets(&targets) {
        Ok(result) => result,
        Err(error) => return fatal(error.to_string()),
    };
    let duration = started.elapsed().as_millis();

    let rendered = match format.as_deref() {
        None | Some("terminal") | Some("text") => TerminalReporter.render(&result),
        Some("json") => hawk_core::report::JsonReporter.render(&result, duration),
        Some("sarif") => hawk_core::report::SarifReporter.render(&result, duration),
        Some("html") => hawk_core::report::HtmlReporter.render(&result, duration),
        Some(other) => {
            return fatal(format!(
                "unknown report format '{other}' (expected terminal, json, sarif, html)"
            ))
        }
    };

    match output {
        Some(path) => {
            if let Err(error) = std::fs::write(&path, rendered) {
                return fatal(format!("unable to write report: {error}"));
            }
        }
        None => print!("{rendered}"),
    }

    if result.degraded() {
        RunOutcome::Degraded
    } else if let Some(minimum) = fail_on_severity {
        if result.findings.iter().any(|f| f.severity >= minimum) {
            RunOutcome::Findings
        } else {
            RunOutcome::Clean
        }
    } else if !result.findings.is_empty() {
        RunOutcome::Findings
    } else {
        RunOutcome::Clean
    }
}

fn config_format(config: &Config) -> Option<String> {
    match config.report.format {
        ReportFormat::Auto => None,
        ReportFormat::Terminal => Some("terminal".to_string()),
        ReportFormat::Json => Some("json".to_string()),
        ReportFormat::Sarif => Some("sarif".to_string()),
        ReportFormat::Html => Some("html".to_string()),
    }
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

fn fatal(message: String) -> RunOutcome {
    eprintln!("error: {message}");
    RunOutcome::Fatal
}

fn print_help() {
    println!("Hawk — local-first static security analysis\n\nUsage:\n  hawk [OPTIONS] [PATH ...]\n  hawk rule <list|explain <id>|test <rule> <fixture>>\n\nArguments:\n  PATH ...  File or directory to scan (default: current directory.\n\nOptions:\n  -h, --help     Print help\n  -V, --version  Print version\n  --changed      Scan working-tree files changed since the index\n  --staged       Scan files staged for commit\n  --no-cache     Disable the incremental result cache
  --pack NAME    Only load the named rule pack (repeatable)
  --format F     Report format: terminal (default), json, sarif, html
  --fail-on-severity L  Only fail (exit 2) for findings at/above severity L
  -o, --output   Write the report to a file instead of stdout\n\nExit codes:\n  0 clean    1 fatal error, 2 findings, 3 degraded (incomplete( scan");
}

/// Dispatches the `hawk rule` subcommand family.
fn run_rule_command(args: &[String]) -> RunOutcome {
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
        let verdicts = hawk_core::fixture::evaluate(&annotations, &findings, |_| true);
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
fn run_config_command(args: &[String]) -> RunOutcome {
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
fn run_baseline_command(args: &[String]) -> RunOutcome {
    let Some(sub) = args.first() else {
        return fatal("missing baseline subcommand (create, update, status)".into());
    };
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let path = hawk_core::baseline::baseline_path(&cwd);
    match sub.as_str() {
        "create" => run_baseline_create(&path, cwd.join(".hawk").join("cache")),
        "update" => run_baseline_create(&path, cwd.join(".hawk").join("cache")),
        "status" => run_baseline_status(&path),
        "help" | "--help" | "-h" => {
            println!("Usage: hawk baseline <create|update|status>");
            RunOutcome::Help
        }
        other => fatal(format!("unknown baseline subcommand '{other}'")),
    }
}

/// Scans the current directory and stores all finding fingerprints as the new baseline.
fn run_baseline_create(path: &std::path::Path, cache_dir: PathBuf) -> RunOutcome {
    let scanner = match Scanner::built_in() {
        Ok(s) => s.with_cache(cache_dir),
        Err(error) => return fatal(error.to_string()),
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
fn run_baseline_status(path: &std::path::Path) -> RunOutcome {
    let baseline = match hawk_core::baseline::Baseline::load(path) {
        Ok(baseline) => baseline,
        Err(error) => return fatal(format!("baseline error: {error}")),
    };
    println!(
        "baseline has {} fingerprint(s)",
        baseline.fingerprints.len()
    );
    RunOutcome::Clean
}

#[cfg(test)]
mod tests {
    use super::{run, RunOutcome};

    #[test]
    fn help_is_available() {
        assert_eq!(run(["--help".to_owned()]).exit_code(), 0);
    }
    #[test]
    fn version_is_available() {
        assert_eq!(run(["--version".to_owned()]).exit_code(), 0);
    }
    #[test]
    fn unknown_options_are_rejected() {
        assert_eq!(run(["--unknown".to_owned()]).exit_code(), 1);
    }
    #[test]
    fn exit_codes_follow_the_adr_contract() {
        assert_eq!(RunOutcome::Help.exit_code(), 0);
        assert_eq!(RunOutcome::Version.exit_code(), 0);
        assert_eq!(RunOutcome::Clean.exit_code(), 0);
        assert_eq!(RunOutcome::Fatal.exit_code(), 1);
        assert_eq!(RunOutcome::Findings.exit_code(), 2);
        assert_eq!(RunOutcome::Degraded.exit_code(), 3);
    }
}
