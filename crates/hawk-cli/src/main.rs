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
    println!("Hawk — local-first static security analysis\n\nUsage:\n  hawk [PATH ...]\n\nArguments:\n  PATH ...  File or directory to scan (default: current directory.\n\nOptions:\n  -h, --help     Print help\n  -V, --version  Print version\n\nExit codes:\n  0 clean    1 fatal error, 2 findings, 3 degraded (incomplete( scan");
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
