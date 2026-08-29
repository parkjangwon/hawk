use crate::parser::SyntaxTree;

#[derive(Debug, Clone, Copy)]
pub struct AstNode<'tree> {
    node: tree_sitter::Node<'tree>,
}

impl<'tree> AstNode<'tree> {
    pub(crate) fn new(node: tree_sitter::Node<'tree>) -> Self {
        Self { node }
    }

    pub fn kind(&self) -> &str {
        self.node.kind()
    }

    pub fn start_byte(&self) -> usize {
        self.node.start_byte()
    }

    pub fn end_byte(&self) -> usize {
        self.node.end_byte()
    }

    pub fn child_count(&self) -> usize {
        self.node.child_count()
    }

    pub fn children(&self) -> impl Iterator<Item = AstNode<'tree>> {
        let cursor = &mut self.node.walk();
        self.node
            .children(cursor)
            .map(Self::new)
            .collect::<Vec<_>>()
            .into_iter()
    }

    pub fn text<'source>(&self, source: &'source str) -> Option<&'source str> {
        source.get(self.start_byte()..self.end_byte())
    }
}

impl SyntaxTree {
    pub fn root(&self) -> AstNode<'_> {
        AstNode::new(self.root_node())
    }

    pub(crate) fn root_node(&self) -> tree_sitter::Node<'_> {
        self.raw_root_node()
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::{JavaParser, Parser};

    #[test]
    fn root_exposes_structural_information() {
        let source = "class Example { int value = 1; }";
        let tree = JavaParser.parse(source).unwrap();
        let root = tree.root();

        assert_eq!(root.kind(), "program");
        assert_eq!(root.start_byte(), 0);
        assert_eq!(root.end_byte(), source.len());
        assert_eq!(root.text(source), Some(source));
        assert!(root.child_count() > 0);
    }

    #[test]
    fn children_can_be_traversed_without_exposing_tree_sitter() {
        let source = "class Example {}";
        let tree = JavaParser.parse(source).unwrap();
        let kinds: Vec<_> = tree
            .root()
            .children()
            .map(|node| node.kind().to_owned())
            .collect();

        assert!(kinds.contains(&"class_declaration"));
    }

    #[test]
    fn node_text_returns_none_for_invalid_utf8_boundaries() {
        let source = "class Example {}";
        let tree = JavaParser.parse(source).unwrap();
        let node = tree.root();

        assert_eq!(node.text("different"), None);
    }
}
