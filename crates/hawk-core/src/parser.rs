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

/// A generic tree-sitter-backed parser for one language.
#[derive(Debug)]
pub struct TreeSitterParser {
    pub(crate) language: Language,
}

impl TreeSitterParser {
    /// The tree-sitter `Language` for this parser's language (needed by
    /// tree-sitter queries). `None` for unknown languages.
    pub fn tree_sitter_language(&self) -> Result<tree_sitter::Language, ParseError> {
        self.language_parameter()
    }

    fn language_parameter(&self) -> Result<tree_sitter::Language, ParseError> {
        let language = match self.language {
            Language::Java => tree_sitter::Language::from(tree_sitter_java::LANGUAGE),
            Language::JavaScript => tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
            Language::TypeScript => {
                tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT)
            }
            Language::Python => tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
            Language::Go => tree_sitter::Language::from(tree_sitter_go::LANGUAGE),
            Language::Unknown => {
                return Err(ParseError::UnsupportedLanguage(self.language));
            }
        };
        Ok(language)
    }
}

impl Parser for TreeSitterParser {
    fn language(&self) -> Language {
        self.language
    }

    fn parse(&self, source: &str) -> Result<SyntaxTree, ParseError> {
        if source.contains('\0') {
            return Err(ParseError::InvalidSource("source contains NUL byte".into()));
        }
        let ts_language = self.language_parameter()?;
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&ts_language)
            .map_err(|error| ParseError::InvalidSource(error.to_string()))?;
        let tree = parser
            .parse(source, None)
            .ok_or_else(|| ParseError::InvalidSource("parser returned no syntax tree".into()))?;
        Ok(SyntaxTree { tree })
    }
}

#[derive(Debug)]
pub struct ParserRegistry {
    java: TreeSitterParser,
    javascript: TreeSitterParser,
    typescript: TreeSitterParser,
    python: TreeSitterParser,
    go: TreeSitterParser,
    // TSX reuses the TypeScript grammar; routed via language() checks.
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self {
            java: TreeSitterParser {
                language: Language::Java,
            },
            javascript: TreeSitterParser {
                language: Language::JavaScript,
            },
            typescript: TreeSitterParser {
                language: Language::TypeScript,
            },
            python: TreeSitterParser {
                language: Language::Python,
            },
            go: TreeSitterParser {
                language: Language::Go,
            },
        }
    }
}

impl ParserRegistry {
    pub fn parser_for(&self, language: Language) -> Option<&dyn Parser> {
        match language {
            Language::Java => Some(&self.java as &dyn Parser),
            Language::JavaScript => Some(&self.javascript as &dyn Parser),
            Language::TypeScript => Some(&self.typescript as &dyn Parser),
            Language::Python => Some(&self.python as &dyn Parser),
            Language::Go => Some(&self.go as &dyn Parser),
            Language::Unknown => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::StreamingIterator;

    #[test]
    fn java_parser_produces_a_real_compilation_unit_tree() {
        let parser = TreeSitterParser {
            language: Language::Java,
        };
        let tree = parser
            .parse("class Example { int value = 1; }")
            .expect("valid Java should parse");

        assert_eq!(tree.root_kind(), "program");
        assert!(!tree.has_error());
    }

    #[test]
    fn javascript_parser_produces_a_program_tree() {
        let parser = TreeSitterParser {
            language: Language::JavaScript,
        };
        let tree = parser.parse("const x = 1;").expect("valid JS should parse");

        assert_eq!(tree.root_kind(), "program");
        assert!(!tree.has_error());
    }

    #[test]
    fn typescript_parser_produces_a_program_tree() {
        let parser = TreeSitterParser {
            language: Language::TypeScript,
        };
        let tree = parser
            .parse("interface X { a: string }\nconst x: X = { a: \"y\" };")
            .expect("valid TS should parse");

        assert_eq!(tree.root_kind(), "program");
        assert!(!tree.has_error());
    }

    #[test]
    fn python_parser_produces_a_module_tree() {
        let parser = TreeSitterParser {
            language: Language::Python,
        };
        let tree = parser
            .parse("import os\nos.system('ls')")
            .expect("valid Python should parse");

        assert_eq!(tree.root_kind(), "module");
        assert!(!tree.has_error());
    }

    #[test]
    fn go_parser_produces_a_source_file_tree() {
        let parser = TreeSitterParser {
            language: Language::Go,
        };
        let tree = parser
            .parse("package main\nfunc main() { println(\"hi\") }")
            .expect("valid Go should parse");

        assert_eq!(tree.root_kind(), "source_file");
        assert!(!tree.has_error());
    }

    #[test]
    fn tree_sitter_query_matches_ast_nodes() {
        let parser = TreeSitterParser {
            language: Language::Java,
        };
        let source = "class A { void run() { Runtime.getRuntime().exec(cmd); } }";
        let tree = parser.parse(source).expect("valid Java should parse");
        let ts_language = parser
            .tree_sitter_language()
            .expect("language should be available");

        // Find every method invocation (the C-style "shape" pattern).
        let query = tree_sitter::Query::new(&ts_language, "(method_invocation) @m")
            .expect("query should parse");
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.raw_root_node(), source.as_bytes());
        let mut count = 0usize;
        while matches.next().is_some() {
            count += 1;
        }
        assert!(count >= 2, "expected method invocations, got {count}");
    }

    #[test]
    fn parser_registry_returns_supported_parsers() {
        let registry = ParserRegistry::default();
        assert!(registry.parser_for(Language::Java).is_some());
        assert!(registry.parser_for(Language::JavaScript).is_some());
        assert!(registry.parser_for(Language::TypeScript).is_some());
        assert!(registry.parser_for(Language::Python).is_some());
        assert!(registry.parser_for(Language::Go).is_some());
        assert!(registry.parser_for(Language::Unknown).is_none());
    }

    #[test]
    fn unknown_language_is_an_explicit_error() {
        let parser = TreeSitterParser {
            language: Language::Unknown,
        };
        let error = parser
            .parse("anything")
            .expect_err("unknown language must fail");

        assert!(matches!(
            error,
            ParseError::UnsupportedLanguage(Language::Unknown)
        ));
    }

    #[test]
    fn malformed_java_is_reported_as_a_tree_with_errors() {
        let parser = TreeSitterParser {
            language: Language::Java,
        };
        let tree = parser
            .parse("class Example {")
            .expect("Tree-sitter should still produce an error tree");

        assert!(tree.has_error());
    }

    #[test]
    fn invalid_source_returns_a_parse_error() {
        let parser = TreeSitterParser {
            language: Language::Java,
        };
        let error = parser
            .parse("class\0Example {}")
            .expect_err("NUL bytes should be rejected");

        assert_eq!(
            error,
            ParseError::InvalidSource("source contains NUL byte".into())
        );
    }
}
