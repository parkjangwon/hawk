use std::path::PathBuf;
use std::process::ExitCode;

use hawk_core::{reporter::TerminalReporter, scan::Scanner, scope::resolve};

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
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return RunOutcome::Help;
    }
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("hawk {VERSION}");
        return RunOutcome::Version;
    }
    if let Some(option) = args.iter().find(|arg| arg.starts_with('-')) {
        return fatal(format!("unknown option '{option}'"));
    }

    let paths: Vec<PathBuf> = args.into_iter().map(PathBuf::from).collect();
    let refs: Vec<_> = paths.iter().map(PathBuf::as_path).collect();
    let targets = match resolve(&refs) {
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
    };

    let scanner = match Scanner::built_in() {
        Ok(scanner) => scanner,
        Err(error) => return fatal(error.to_string()),
    };
    let result = match scanner.scan_targets(&targets) {
        Ok(result) => result,
        Err(error) => return fatal(error.to_string()),
    };

    print!("{}", TerminalReporter.render(&result));

    if result.degraded() {
        RunOutcome::Degraded
    } else if !result.findings.is_empty() {
        RunOutcome::Findings
    } else {
        RunOutcome::Clean
    }
}

fn fatal(message: String) -> RunOutcome {
    eprintln!("error: {message}");
    RunOutcome::Fatal
}

fn print_help() {
    println!("Hawk — local-first static security analysis\n\nUsage:\n  hawk [PATH ...]\n  hawk rule list\n  hawk rule explain <id>\n  hawk rule test <rule-file> <fixture-file> [--expected <count>]\n\nArguments:\n  PATH ...  File or directory to scan (default: current directory.\n\nOptions:\n  -h, --help     Print help\n  -V, --version  Print version\n\nExit codes:\n  0 clean    1 fatal error, 2 findings, 3 degraded (incomplete( scan");
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
    let findings = rule.check_source(&source, std::path::Path::new(&fixture));
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
