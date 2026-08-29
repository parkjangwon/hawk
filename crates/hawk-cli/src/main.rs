use std::path::PathBuf;
use std::process::ExitCode;

use hawk_core::{reporter::TerminalReporter, scan::Scanner, scope::resolve};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run<I>(args: I) -> Result<(), String>
where
    I: IntoIterator<Item = String>,
{
    let args: Vec<String> = args.into_iter().collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(());
    }
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("hawk {VERSION}");
        return Ok(());
    }
    if let Some(option) = args.iter().find(|arg| arg.starts_with('-')) {
        return Err(format!("unknown option '{option}'"));
    }

    let paths: Vec<PathBuf> = args.into_iter().map(PathBuf::from).collect();
    let refs: Vec<_> = paths.iter().map(PathBuf::as_path).collect();
    let targets = resolve(&refs).map_err(|error| format!("{error}"))?;
    let result = Scanner::built_in()
        .scan_targets(&targets)
        .map_err(|error| error.to_string())?;

    print!("{}", TerminalReporter.render(&result.findings));
    Ok(())
}

fn print_help() {
    println!("Hawk — local-first static security analysis\n\nUsage:\n  hawk [PATH ...]\n\nArguments:\n  PATH ...  File or directory to scan (default: current directory)\n\nOptions:\n  -h, --help     Print help\n  -V, --version  Print version");
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn help_is_available() {
        assert!(run(["--help".to_owned()]).is_ok());
    }
    #[test]
    fn version_is_available() {
        assert!(run(["--version".to_owned()]).is_ok());
    }
    #[test]
    fn unknown_options_are_rejected() {
        assert_eq!(
            run(["--unknown".to_owned()]).unwrap_err(),
            "unknown option '--unknown'"
        );
    }
}
