//! Project configuration (`hawk.toml`) and serde bindings.
//!
//! Precedence is Defaults → Project Config → CLI Arguments (ADR-0003). This
//! module owns discovery + parsing of the project file; CLI merging happens in
//! the CLI crate.

use std::path::{Path, PathBuf};

use serde::Deserialize;

pub const CONFIG_FILE_NAME: &str = "hawk.toml";
pub const DATA_DIR_NAME: &str = ".hawk";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Auto,
    Terminal,
    Json,
    Sarif,
    Html,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportConfig {
    pub format: ReportFormat,
    pub output: Option<PathBuf>,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            format: ReportFormat::Auto,
            output: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExitPolicy {
    /// Findings at or above this severity trigger the automation exit code 2.
    /// `None` means "any finding" (the default).
    pub exit_on_severity: Option<crate::finding::Severity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    /// Extra include path patterns (relative to the config root); empty = scan requested scope only.
    pub include: Vec<String>,
    /// Exclude path patterns (relative to the config root), layered over default ignores.
    pub exclude: Vec<String>,
    /// Selected rule packs. Empty = all built-in packs.
    pub packs: Vec<String>,
    /// Directories searched for user rule packs, in order.
    pub pack_dirs: Vec<PathBuf>,
    pub report: ReportConfig,
    pub policy: ExitPolicy,
    /// Absolute path of the config file that produced this config, if any.
    pub source: Option<PathBuf>,
    /// The directory that owns this config (project root), if loaded from a file.
    pub root: Option<PathBuf>,
}

impl Config {
    /// The effective project root: the directory the config was loaded from,
    /// or the current working directory when no config file exists.
    pub fn root_dir(&self) -> PathBuf {
        self.root
            .clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    }

    /// Local data directory (`.hawk/`) inside the project root.
    pub fn data_dir(&self) -> PathBuf {
        self.root_dir().join(DATA_DIR_NAME)
    }

    /// Searches for `hawk.toml` from `dir` upward (defaults to the current
    /// directory). Returns the containing directory.
    pub fn find_root(start: &Path) -> Option<PathBuf> {
        let mut current = start;
        loop {
            if current.join(CONFIG_FILE_NAME).is_file() {
                return Some(current.to_path_buf());
            }
            current = current.parent()?;
        }
    }

    /// Loads configuration from the current directory chain. Never fails on
    /// missing file — returns defaults with no source.
    pub fn load() -> Result<Config, ConfigError> {
        let cwd =
            std::env::current_dir().map_err(|error| ConfigError::CurrentDir(error.to_string()))?;
        let root = Config::find_root(&cwd);
        match root {
            Some(dir) => Self::from_file_at(&dir.join(CONFIG_FILE_NAME)),
            None => Ok(Config::default()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    CurrentDir(String),
    NoHome,

    Read { path: PathBuf, source: String },
    Parse { path: PathBuf, source: String },
    Validate { message: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentDir(error) => write!(f, "unable to determine current directory: {error}"),
            Self::NoHome => write!(f, "unable to locate the home directory"),
            Self::Read { path, source } => {
                write!(f, "unable to read config '{}': {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(f, "unable to parse config '{}': {source}", path.display())
            }
            Self::Validate { message } => write!(f, "invalid config: {message}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Default, Deserialize)]
struct RawConfig {
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    packs: Option<Vec<String>>,
    #[serde(rename = "pack-dirs")]
    pack_dirs: Option<Vec<PathBuf>>,
    report: Option<RawReport>,
    policy: Option<RawPolicy>,
}

#[derive(Debug, Deserialize)]
struct RawReport {
    format: Option<String>,
    output: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct RawPolicy {
    #[serde(rename = "exit-on-severity")]
    exit_on_severity: Option<String>,
}

/// A `Config` value may be constructed directly for tests; parsing is otherwise
/// the only public path.
impl Config {
    pub fn parse(content: &str, path: &Path) -> Result<Config, ConfigError> {
        let raw: RawConfig = toml::from_str(content).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: source.to_string(),
        })?;
        Self::from_raw(raw, path)
    }

    /// Parses in-memory content as if it were the file at `path` (test helper).
    pub fn from_file(content: &str, path: &Path) -> Result<Config, ConfigError> {
        Self::parse(content, path)
    }

    pub fn from_file_at(path: &Path) -> Result<Config, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source: source.to_string(),
        })?;
        Self::from_file(&content, path)
    }

    fn from_raw(raw: RawConfig, path: &Path) -> Result<Config, ConfigError> {
        let mut config = Config {
            source: Some(path.to_path_buf()),
            root: path.parent().map(Path::to_path_buf),
            ..Config::default()
        };

        if let Some(include) = raw.include {
            config.include = include;
        }
        if let Some(exclude) = raw.exclude {
            config.exclude = exclude;
        }
        if let Some(packs) = raw.packs {
            config.packs = packs;
        }
        if let Some(pack_dirs) = raw.pack_dirs {
            config.pack_dirs = pack_dirs
                .into_iter()
                .map(|dir| {
                    if dir.is_absolute() {
                        dir
                    } else {
                        path.parent().unwrap_or_else(|| Path::new(".")).join(dir)
                    }
                })
                .collect();
        }
        if let Some(report) = raw.report {
            if let Some(format) = report.format {
                config.report.format = match format.as_str() {
                    "auto" => ReportFormat::Auto,
                    "terminal" => ReportFormat::Terminal,
                    "json" => ReportFormat::Json,
                    "sarif" => ReportFormat::Sarif,
                    "html" => ReportFormat::Html,
                    _ => {
                        return Err(ConfigError::Validate {
                            message: format!(
                                "unknown report format '{format}' (expected auto, terminal, json, sarif, html)"
                            ),
                        })
                    }
                };
            }
            if let Some(output) = report.output {
                config.report.output = Some(if output.is_absolute() {
                    output
                } else {
                    path.parent().unwrap_or_else(|| Path::new(".")).join(output)
                });
            }
        }
        if let Some(policy) = raw.policy {
            if let Some(level) = policy.exit_on_severity {
                config.policy.exit_on_severity =
                    Some(parse_severity(&level).map_err(|unknown| ConfigError::Validate {
                        message: format!(
                            "unknown severity '{unknown}' in policy.exit-on-severity (expected info, low, medium, high, critical)"
                        ),
                    })?);
            }
        }
        Ok(config)
    }
}

fn parse_severity(value: &str) -> Result<crate::finding::Severity, String> {
    match value.to_ascii_lowercase().as_str() {
        "info" => Ok(crate::finding::Severity::Info),
        "low" => Ok(crate::finding::Severity::Low),
        "medium" => Ok(crate::finding::Severity::Medium),
        "high" => Ok(crate::finding::Severity::High),
        "critical" => Ok(crate::finding::Severity::Critical),
        _ => Err(value.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn default_config_works_without_a_file() {
        let config = Config::default();
        assert!(config.include.is_empty());
        assert!(config.exclude.is_empty());
        assert_eq!(config.report.format, ReportFormat::Auto);
        assert_eq!(config.policy.exit_on_severity, None);
        assert!(config.source.is_none());
    }

    #[test]
    fn parses_a_full_config_file() {
        let toml_str = r#"
include = ["src", "lib"]
exclude = ["vendor"]
packs = ["java"]
pack-dirs = ["./rules"]

[report]
format = "json"
output = "report.json"

[policy]
exit-on-severity = "high"
"#;
        let config = Config::from_file(toml_str, Path::new("x/hawk.toml")).unwrap();

        assert_eq!(config.include, vec!["src", "lib"]);
        assert_eq!(config.exclude, vec!["vendor"]);
        assert_eq!(config.packs, vec!["java"]);
        assert_eq!(config.report.format, ReportFormat::Json);
        assert_eq!(
            config.report.output.as_deref(),
            Some(Path::new("x/report.json"))
        );
        assert_eq!(
            config.policy.exit_on_severity,
            Some(crate::finding::Severity::High)
        );
        assert_eq!(config.root.as_deref(), Some(Path::new("x")));
    }

    #[test]
    fn empty_toml_parses_to_defaults() {
        let config = Config::from_file("", Path::new("x/hawk.toml")).unwrap();

        assert!(config.include.is_empty());
        assert_eq!(config.report.format, ReportFormat::Auto);
        assert!(config.source.is_some());
    }

    #[test]
    fn unknown_report_format_is_an_explicit_error() {
        let toml_str = r#"[report]
format = "xml"
"#;
        let error = Config::from_file(toml_str, Path::new("hawk.toml"))
            .expect_err("unknown format must fail");
        assert!(matches!(error, ConfigError::Validate { .. }));
    }

    #[test]
    fn unknown_exit_severity_is_an_explicit_error() {
        let toml_str = r#"[policy]
exit-on-severity = "extreme"
"#;
        let error = Config::from_file(toml_str, Path::new("hawk.toml"))
            .expect_err("unknown severity must fail");
        assert!(matches!(error, ConfigError::Validate { .. }));
    }

    #[test]
    fn find_root_walks_up_to_the_nearest_config() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let tmp = std::env::temp_dir().join(format!(
            "hawk-config-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&tmp).unwrap();
        let sub = tmp.join("a/b");
        fs::create_dir_all(&sub).unwrap();
        fs::write(tmp.join(CONFIG_FILE_NAME), "").unwrap();

        let root = Config::find_root(&sub).expect("should find config in ancestor");
        assert_eq!(root, tmp);
        fs::remove_dir_all(&tmp).unwrap();
    }
}
