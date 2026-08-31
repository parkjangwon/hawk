use crate::parser::SyntaxTree;

/// Maximum nesting depth of live `children()` iterators (i.e. the recursion
/// depth of hawk's AST walks). Deeply nested generated/minified code could
/// otherwise overflow the stack; walks simply stop descending past this depth.
pub(crate) const MAX_AST_DEPTH: usize = 1024;

thread_local! {
    static AST_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// RAII guard: counts live AST iterators so recursive walks can bound their
/// depth without threading a depth parameter through every visitor.
pub(crate) struct DepthGuard {
    over: bool,
}

impl DepthGuard {
    fn enter() -> DepthGuard {
        AST_DEPTH.with(|depth| {
            let next = depth.get() + 1;
            depth.set(next);
            DepthGuard {
                over: next > MAX_AST_DEPTH,
            }
        })
    }
}

impl Drop for DepthGuard {
    fn drop(&mut self) {
        AST_DEPTH.with(|depth| depth.set(depth.get() - 1));
    }
}

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

    pub fn start_position(&self) -> tree_sitter::Point {
        self.node.start_position()
    }

    pub fn end_position(&self) -> tree_sitter::Point {
        self.node.end_position()
    }

    pub fn child_by_field_name(&self, name: &str) -> Option<Self> {
        self.node.child_by_field_name(name).map(Self::new)
    }

    pub fn parent(&self) -> Option<Self> {
        self.node.parent().map(Self::new)
    }

    /// Iterates the named children. The iterator is streaming (no per-call
    /// allocation) and participates in the AST recursion depth guard: beyond
    /// `MAX_AST_DEPTH` nested live iterators it yields nothing, which bounds
    /// every recursive walk in the codebase at one choke point.
    pub fn children(&self) -> impl Iterator<Item = AstNode<'tree>> {
        let guard = DepthGuard::enter();
        let cursor = self.node.walk();
        AstChildren {
            cursor,
            first: true,
            over: guard.over,
            _guard: guard,
        }
    }

    pub fn text<'source>(&self, source: &'source str) -> Option<&'source str> {
        source.get(self.start_byte()..self.end_byte())
    }
}

/// Streaming children iterator; owns the tree cursor so no allocation or
/// `&mut` borrow of the node is needed.
pub(crate) struct AstChildren<'tree> {
    cursor: tree_sitter::TreeCursor<'tree>,
    first: bool,
    over: bool,
    _guard: DepthGuard,
}

impl<'tree> Iterator for AstChildren<'tree> {
    type Item = AstNode<'tree>;

    fn next(&mut self) -> Option<AstNode<'tree>> {
        if self.over {
            return None;
        }
        let descended = if self.first {
            self.cursor.goto_first_child()
        } else {
            self.cursor.goto_next_sibling()
        };
        self.first = false;
        descended.then(|| AstNode::new(self.cursor.node()))
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
    use super::*;
    use crate::{
        language::Language,
        parser::{Parser, TreeSitterParser},
    };

    #[test]
    fn root_exposes_structural_information() {
        let source = "class Example { int value = 1; }";
        let parser = TreeSitterParser {
            language: Language::Java,
        };
        let tree = parser.parse(source).unwrap();
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
        let parser = TreeSitterParser {
            language: Language::Java,
        };
        let tree = parser.parse(source).unwrap();
        let kinds: Vec<_> = tree
            .root()
            .children()
            .map(|node| node.kind().to_owned())
            .collect();

        assert!(kinds.iter().any(|kind| kind == "class_declaration"));
    }

    #[test]
    fn node_text_returns_none_for_invalid_utf8_boundaries() {
        let source = "class Example {}";
        let parser = TreeSitterParser {
            language: Language::Java,
        };
        let tree = parser.parse(source).unwrap();
        let node = tree.root();

        assert_eq!(node.text("different"), None);
    }

    #[test]
    fn children_streaming_iterator_yields_the_same_nodes() {
        let source = "class Example { void a() { b(); } void b() {} }";
        let parser = TreeSitterParser {
            language: Language::Java,
        };
        let tree = parser.parse(source).unwrap();
        let kinds: Vec<_> = tree
            .root()
            .children()
            .map(|node| node.kind().to_owned())
            .collect();
        assert!(
            kinds.iter().any(|kind| kind == "class_declaration"),
            "streaming children must yield the class node"
        );
        let class = tree
            .root()
            .children()
            .find(|node| node.kind() == "class_declaration")
            .expect("class node");
        assert!(
            class.children().any(|node| node.kind() == "class_body"),
            "nested iteration must still work"
        );
    }

    #[test]
    fn recursive_walk_stops_at_the_depth_guard() {
        // A pathologically deep expression (generated/minified code) would
        // overflow the stack in a recursive walk; the guard in children()
        // bounds the traversal instead.
        let depth = MAX_AST_DEPTH * 4;
        let source = format!("{}x{}", "(".repeat(depth), ")".repeat(depth));
        let parser = TreeSitterParser {
            language: Language::JavaScript,
        };
        let tree = parser.parse(&source).unwrap();

        fn count(node: AstNode<'_>, visited: &mut usize) {
            *visited += 1;
            for child in node.children() {
                count(child, visited);
            }
        }
        let mut visited = 0;
        count(tree.root(), &mut visited);
        // The whole tree has ~2*depth+1 nodes; the guarded walk must visit
        // only the top MAX_AST_DEPTH levels.
        assert!(
            visited < depth * 2,
            "depth guard must cut the walk short (visited {visited} of ~{})",
            depth * 2
        );
    }
}
