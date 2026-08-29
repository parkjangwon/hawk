use crate::language::Language;

#[derive(Debug, Clone)]
pub struct SyntaxTree {
    pub(crate) tree: tree_sitter::Tree,
}

impl SyntaxTree {
    pub fn root_kind(&self) -> &str {
        self.tree.root_node().kind()
    }

    pub fn has_error(&self) -> bool {
        self.tree.root_node().has_error()
    }

    pub(crate) fn raw_root_node(&self) -> tree_sitter::Node<'_> {
        self.tree.root_node()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    UnsupportedLanguage(Language),
    InvalidSource(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedLanguage(language) => write!(f, "unsupported language: {language:?}"),
            Self::InvalidSource(message) => write!(f, "invalid source: {message}"),
        }
    }
}

impl std::error::Error for ParseError {}

pub trait Parser {
    fn language(&self) -> Language;
    fn parse(&self, source: &str) -> Result<SyntaxTree, ParseError>;
}

#[derive(Debug, Default)]
pub struct JavaParser;

impl Parser for JavaParser {
    fn language(&self) -> Language {
        Language::Java
    }

    fn parse(&self, source: &str) -> Result<SyntaxTree, ParseError> {
        if source.contains('\0') {
            return Err(ParseError::InvalidSource("source contains NUL byte".into()));
        }

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(tree_sitter_java::language())
            .map_err(|error| ParseError::InvalidSource(error.to_string()))?;

        let tree = parser
            .parse(source, None)
            .ok_or_else(|| ParseError::InvalidSource("parser returned no syntax tree".into()))?;

        Ok(SyntaxTree { tree })
    }
}

#[derive(Debug, Default)]
pub struct ParserRegistry {
    java: JavaParser,
}

impl ParserRegistry {
    pub fn parser_for(&self, language: Language) -> Option<&dyn Parser> {
        match language {
            Language::Java => Some(&self.java),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_parser_reports_its_language() {
        assert_eq!(JavaParser.language(), Language::Java);
    }

    #[test]
    fn java_parser_produces_a_real_compilation_unit_tree() {
        let tree = JavaParser
            .parse("class Example { int value = 1; }")
            .expect("valid Java should parse");

        assert_eq!(tree.root_kind(), "program");
        assert!(!tree.has_error());
    }

    #[test]
    fn parser_registry_only_returns_supported_parsers() {
        let registry = ParserRegistry::default();
        assert!(registry.parser_for(Language::Java).is_some());
        assert!(registry.parser_for(Language::Python).is_none());
    }

    #[test]
    fn malformed_java_is_reported_as_a_tree_with_errors() {
        let tree = JavaParser
            .parse("class Example {")
            .expect("Tree-sitter should still produce an error tree");

        assert!(tree.has_error());
    }

    #[test]
    fn invalid_source_returns_a_parse_error() {
        let error = JavaParser
            .parse("class\0Example {}")
            .expect_err("NUL bytes should be rejected");

        assert_eq!(
            error,
            ParseError::InvalidSource("source contains NUL byte".into())
        );
    }
}
