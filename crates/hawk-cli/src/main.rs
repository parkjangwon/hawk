use std::path::PathBuf;
use std::process::ExitCode;

use hawk_core::scope::{resolve, ScanTarget};

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
    let path_refs: Vec<_> = paths.iter().map(PathBuf::as_path).collect();
    let targets = resolve(&path_refs).map_err(format_scope_error)?;

    for target in targets {
        print_target(&target);
    }

    Ok(())
}

fn print_target(target: &ScanTarget) {
    let kind = match target {
        ScanTarget::File(_) => "file",
        ScanTarget::Directory(_) => "directory",
    };

    println!("scan {kind}: {}", target.path().display());
}

fn format_scope_error(error: hawk_core::scope::ScopeError) -> String {
    match error {
        hawk_core::scope::ScopeError::PathNotFound(path) => {
            format!("path not found: {}", path.display())
        }
        hawk_core::scope::ScopeError::MetadataUnavailable { path } => {
            format!("unable to determine path type: {}", path.display())
        }
    }
}

fn print_help() {
    println!(
        "Hawk — local-first static security analysis\n\nUsage:\n  hawk [PATH ...]\n\nArguments:\n  PATH ...  File or directory to scan (default: current directory)\n\nOptions:\n  -h, --help     Print help\n  -V, --version  Print version"
    );
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
        let error = run(["--unknown".to_owned()]).expect_err("unknown option must fail");
        assert_eq!(error, "unknown option '--unknown'");
    }
}
