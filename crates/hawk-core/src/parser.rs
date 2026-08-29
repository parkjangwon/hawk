use crate::language::Language;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    pub language: Language,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxNode {
    pub kind: String,
    pub start_byte: usize,
    pub end_byte: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxTree {
    pub root: SyntaxNode,
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

        Ok(SyntaxTree {
            root: SyntaxNode {
                kind: "compilation_unit".into(),
                start_byte: 0,
                end_byte: source.len(),
            },
        })
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
    fn java_parser_produces_a_compilation_unit_root() {
        let source = "class Example {}";
        let tree = JavaParser.parse(source).expect("valid Java should parse");

        assert_eq!(tree.root.kind, "compilation_unit");
        assert_eq!(tree.root.start_byte, 0);
        assert_eq!(tree.root.end_byte, source.len());
    }

    #[test]
    fn parser_registry_only_returns_supported_parsers() {
        let registry = ParserRegistry::default();
        assert!(registry.parser_for(Language::Java).is_some());
        assert!(registry.parser_for(Language::Python).is_none());
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
