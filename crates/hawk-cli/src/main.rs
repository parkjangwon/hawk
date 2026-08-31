use std::path::PathBuf;
use std::process::ExitCode;

mod subcommands;

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
        return subcommands::run_rule_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("baseline") {
        return subcommands::run_baseline_command(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("config") {
        return subcommands::run_config_command(&args[1..]);
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
    let mut use_baseline = false;
    let mut packs: Vec<String> = config.packs.clone();
    let mut cli_selected_packs = false;
    let mut pack_dirs: Vec<PathBuf> = config.pack_dirs.clone();
    let mut paths: Vec<PathBuf> = Vec::new();
    let mut it = args.iter().peekable();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--changed" => git_mode = Some(GitScope::Changed),
            "--staged" => git_mode = Some(GitScope::Staged),
            "--no-cache" => use_cache = false,
            "--baseline" => use_baseline = true,
            "--pack" => {
                if !cli_selected_packs {
                    packs.clear();
                    cli_selected_packs = true;
                }
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

    let mut scanner = match build_scanner(&config, &packs, &pack_dirs) {
        Ok(scanner) => scanner,
        Err(error) => return fatal(error),
    };

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
    let mut result = result;
    if use_baseline {
        let baseline_path = hawk_core::baseline::baseline_path(&config.root_dir());
        let baseline = match hawk_core::baseline::Baseline::load(&baseline_path) {
            Ok(baseline) => baseline,
            Err(error) => return fatal(format!("baseline error: {error}")),
        };
        let status = hawk_core::baseline::classify(
            &baseline,
            &result.findings.iter().cloned().collect::<Vec<_>>(),
        );
        eprintln!(
            "baseline: {} existing, {} new, {} fixed",
            status.existing.len(),
            status.new.len(),
            status.fixed.len()
        );
        let mut filtered = hawk_core::finding::Findings::new();
        for finding in status.new {
            filtered.push(finding);
        }
        result.findings = filtered;
    }

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

/// Builds a scanner applying project configuration and selected packs.
/// Shared by normal scans and baseline commands so their rule set and scope
/// semantics stay identical.
pub(crate) fn build_scanner(
    config: &Config,
    packs: &[String],
    pack_dirs: &[PathBuf],
) -> Result<Scanner, String> {
    let mut scanner = Scanner::built_in()
        .map_err(|error| error.to_string())?
        .with_excludes(config.exclude.clone());
    scanner
        .load_pack_dirs(pack_dirs)
        .map_err(|e| e.to_string())?;
    if !packs.is_empty() {
        scanner.select_packs(packs);
    }
    Ok(scanner)
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

pub(crate) fn fatal(message: String) -> RunOutcome {
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
