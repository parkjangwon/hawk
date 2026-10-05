use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Language {
    Java,
    JavaScript,
    TypeScript,
    /// JSX-flavored TypeScript (`.tsx`). Uses the dedicated tree-sitter TSX
    /// grammar: parsing JSX with the plain TypeScript grammar produces error
    /// nodes, which degraded every React scan.
    Tsx,
    Python,
    Go,
    Unknown,
}

impl Language {
    pub fn from_path(path: &Path) -> Self {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("java") => Self::Java,
            Some("js" | "mjs" | "cjs") => Self::JavaScript,
            Some("ts" | "mts" | "cts") => Self::TypeScript,
            Some("tsx") => Self::Tsx,
            Some("py" | "pyw") => Self::Python,
            Some("go") => Self::Go,
            _ => Self::Unknown,
        }
    }

    /// Whether a rule declaring `languages` runs against a file of language
    /// `file`. TSX files are analyzed by rules declaring TypeScript or
    /// JavaScript (the React ecosystem is covered by both).
    pub fn rule_applies_to(languages: &[Language], file: Language) -> bool {
        languages.contains(&file)
            || (file == Language::Tsx
                && (languages.contains(&Language::TypeScript)
                    || languages.contains(&Language::JavaScript)))
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
        assert_eq!(Language::from_path(Path::new("app.tsx")), Language::Tsx);
        assert_eq!(
            Language::from_path(Path::new("app.ts")),
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
    #[test]
    fn tsx_rules_match_typescript_and_javascript_rule_sets() {
        let js_only = [Language::JavaScript];
        let ts_only = [Language::TypeScript];
        let java_only = [Language::Java];
        assert!(Language::rule_applies_to(&js_only, Language::Tsx));
        assert!(Language::rule_applies_to(&ts_only, Language::Tsx));
        assert!(!Language::rule_applies_to(&java_only, Language::Tsx));
        // Plain TypeScript files do not inherit JavaScript-only rules.
        assert!(!Language::rule_applies_to(&js_only, Language::TypeScript));
        assert!(Language::rule_applies_to(&java_only, Language::Java));
    }
}
