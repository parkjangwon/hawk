use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Java,
    JavaScript,
    TypeScript,
    Python,
    Go,
    Unknown,
}

impl Language {
    pub fn from_path(path: &Path) -> Self {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("java") => Self::Java,
            Some("js" | "mjs" | "cjs") => Self::JavaScript,
            Some("ts" | "mts" | "cts" | "tsx") => Self::TypeScript,
            Some("py" | "pyw") => Self::Python,
            Some("go") => Self::Go,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Language;
    use std::path::Path;

    #[test]
    fn detects_supported_languages_by_extension() {
        assert_eq!(Language::from_path(Path::new("Main.java")), Language::Java);
        assert_eq!(
            Language::from_path(Path::new("app.js")),
            Language::JavaScript
        );
        assert_eq!(
            Language::from_path(Path::new("app.tsx")),
            Language::TypeScript
        );
        assert_eq!(
            Language::from_path(Path::new("server.py")),
            Language::Python
        );
        assert_eq!(Language::from_path(Path::new("main.go")), Language::Go);
    }

    #[test]
    fn unknown_extensions_are_not_assigned_a_language() {
        assert_eq!(
            Language::from_path(Path::new("README.md")),
            Language::Unknown
        );
        assert_eq!(Language::from_path(Path::new("binary")), Language::Unknown);
    }

    #[test]
    fn extension_matching_is_case_sensitive() {
        assert_eq!(
            Language::from_path(Path::new("Main.JAVA")),
            Language::Unknown
        );
    }
}
