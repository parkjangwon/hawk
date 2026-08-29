use crate::{
    ast::AstNode,
    finding::{Finding, Findings, Severity, SourceLocation},
    language::Language,
};

pub trait Rule {
    fn id(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn severity(&self) -> Severity;
    fn languages(&self) -> &'static [Language];
    fn check(&self, root: AstNode<'_>, source: &str, path: &std::path::Path) -> Findings;
}

#[derive(Debug, Default)]
pub struct JavaRuntimeExecRule;

impl Rule for JavaRuntimeExecRule {
    fn id(&self) -> &'static str {
        "java.security.runtime-exec"
    }

    fn description(&self) -> &'static str {
        "Detects Runtime.exec calls that may execute operating-system commands."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn languages(&self) -> &'static [Language] {
        &[Language::Java]
    }

    fn check(&self, root: AstNode<'_>, source: &str, path: &std::path::Path) -> Findings {
        let mut findings = Findings::new();
        visit(root, source, path, &mut findings, self);
        findings
    }
}

fn visit(
    root: AstNode<'_>,
    source: &str,
    path: &std::path::Path,
    findings: &mut Findings,
    rule: &impl Rule,
) {
    if root.kind() == "method_invocation"
        && root
            .child_by_field_name("name")
            .and_then(|name| name.text(source))
            == Some("exec")
        && root
            .child_by_field_name("object")
            .and_then(|object| object.text(source))
            .is_some_and(|object| object == "Runtime.getRuntime()")
    {
        findings.push(Finding::new(
            rule.id(),
            rule.severity(),
            rule.description(),
            location(&root, path),
        ));
    }

    for child in root.children() {
        visit(child, source, path, findings, rule);
    }
}

fn location(node: &AstNode<'_>, path: &std::path::Path) -> SourceLocation {
    let start = node.start_position();
    let end = node.end_position();

    SourceLocation {
        path: path.to_path_buf(),
        start_byte: node.start_byte(),
        end_byte: node.end_byte(),
        start_line: start.row + 1,
        start_column: start.column + 1,
        end_line: end.row + 1,
        end_column: end.column + 1,
    }
}

#[derive(Default)]
pub struct RuleRegistry {
    rules: Vec<Box<dyn Rule + Send + Sync>>,
}

impl RuleRegistry {
    pub fn built_in() -> Self {
        Self {
            rules: vec![Box::new(JavaRuntimeExecRule)],
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &(dyn Rule + Send + Sync)> {
        self.rules.iter().map(Box::as_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{JavaParser, Parser};

    #[test]
    fn runtime_exec_rule_detects_runtime_exec() {
        let source =
            "class Example { void run(String input) { Runtime.getRuntime().exec(input); } }";
        let tree = JavaParser.parse(source).unwrap();
        let findings =
            JavaRuntimeExecRule.check(tree.root(), source, std::path::Path::new("Example.java"));

        assert_eq!(findings.len(), 1);
        let finding = findings.iter().next().unwrap();
        assert_eq!(finding.rule_id, "java.security.runtime-exec");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.location.start_line, 1);
    }

    #[test]
    fn runtime_exec_rule_ignores_unrelated_method_calls() {
        let source = "class Example { void run() { process.exec(); } }";
        let tree = JavaParser.parse(source).unwrap();
        let findings =
            JavaRuntimeExecRule.check(tree.root(), source, std::path::Path::new("Example.java"));

        assert!(findings.is_empty());
    }

    #[test]
    fn built_in_registry_contains_only_built_in_rules() {
        let registry = RuleRegistry::built_in();
        let ids: Vec<_> = registry.iter().map(Rule::id).collect();

        assert_eq!(ids, ["java.security.runtime-exec"]);
    }
}
