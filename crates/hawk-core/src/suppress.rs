//! Inline finding suppression (`hawk:ignore` / `nosec`).
//!
//! A false positive a developer cannot silence is the fastest way to lose
//! adoption, so findings can be suppressed in the source itself:
//!
//! ```text
//! Runtime.getRuntime().exec("df -h"); // hawk:ignore
//! String token = loadToken(); // hawk:ignore java.security.cookie
//! String key = "…"; # nosec korea.java.hardcoded-password
//! ```
//!
//! Semantics (documented in the README):
//! - `hawk:ignore` suppresses every rule; `hawk:ignore <id> [<id>…]`
//!   suppresses only the listed rule ids (whitespace/comma separated).
//! - `nosec` is accepted as an alias with identical semantics (Bandit-style).
//! - The marker must sit inside a comment on the finding's line or on the
//!   line directly above it — the same tolerance the fixture annotations use.
//! - A marker that carries ids but does not match a finding's rule id has no
//!   effect, so existing suppressions keep working as rules evolve.

use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suppression {
    /// 1-based source line carrying the marker.
    pub line: usize,
    /// Suppressed rule ids; `None` suppresses every rule.
    pub rules: Option<HashSet<String>>,
}

/// Parses suppression markers out of source text.
pub fn parse_suppressions(source: &str) -> Vec<Suppression> {
    let mut suppressions = Vec::new();
    for (index, raw_line) in source.lines().enumerate() {
        if let Some(rules) = marker_rules(raw_line) {
            suppressions.push(Suppression {
                line: index + 1,
                rules,
            });
        }
    }
    suppressions
}

/// Whether a finding at `line` for `rule_id` is suppressed. A marker applies
/// to its own line and to the line directly below it.
pub fn is_suppressed(suppressions: &[Suppression], line: usize, rule_id: &str) -> bool {
    suppressions.iter().any(|suppression| {
        let on_line = suppression.line == line || suppression.line + 1 == line;
        on_line
            && suppression
                .rules
                .as_ref()
                .is_none_or(|rules| rules.contains(rule_id))
    })
}

/// Extracts the suppressed rule set from one line, if the line carries a
/// marker inside a comment. `None`-rules means "suppress everything".
fn marker_rules(line: &str) -> Option<Option<HashSet<String>>> {
    for marker in ["hawk:ignore", "nosec"] {
        let mut search_from = 0;
        while let Some(position) = line[search_from..].find(marker) {
            let absolute = search_from + position;
            search_from = absolute + marker.len();
            if !inside_comment(line, absolute) {
                continue;
            }
            // Only the first marker on a line defines the id list.
            let rest = line[absolute + marker.len()..].trim();
            let rest = rest.strip_prefix(':').unwrap_or(rest);
            let ids: HashSet<String> = rest
                .split([',', ' ', '\t'])
                .map(str::trim)
                .filter(|id| is_rule_id_like(id))
                .map(String::from)
                .collect();
            return Some(if ids.is_empty() { None } else { Some(ids) });
        }
    }
    None
}

/// True when the marker sits behind a comment opener with nothing but
/// whitespace in between — so `x = "nosec"` (a string literal) never counts.
fn inside_comment(line: &str, marker_position: usize) -> bool {
    let before = &line[..marker_position];
    // Nearest comment opener before the marker; require whitespace-only gap.
    for opener in ["//", "#", "/*", "*", "--"] {
        if let Some(open_at) = before.rfind(opener) {
            if before[open_at + opener.len()..].trim().is_empty() {
                return true;
            }
        }
    }
    // A line that is itself a comment (block-comment continuation or any
    // language whose opener we do not model) still counts when it contains
    // no code-bearing assignment shape. Conservative: only `*`/block style.
    false
}

fn is_rule_id_like(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_and_scoped_markers() {
        let source = "\
a(); // hawk:ignore
b(); // hawk:ignore rule.one rule.two
c(); # nosec
d(); # nosec: rule.three
e();
";
        let suppressions = parse_suppressions(source);
        assert_eq!(suppressions.len(), 4);
        assert_eq!(suppressions[0].line, 1);
        assert_eq!(suppressions[0].rules, None);
        let scoped = suppressions[1].rules.clone().unwrap();
        assert!(scoped.contains("rule.one") && scoped.contains("rule.two"));
        assert_eq!(suppressions[3].line, 4);
        assert!(suppressions[3]
            .rules
            .as_ref()
            .unwrap()
            .contains("rule.three"));
    }

    #[test]
    fn markers_inside_string_literals_do_not_count() {
        let source = "let hint = \"use nosec here\";\nlet url = '/hawk:ignore';\n";
        assert!(parse_suppressions(source).is_empty());
    }

    #[test]
    fn same_line_and_line_below_are_covered() {
        let suppressions = parse_suppressions("// hawk:ignore\nfoo();\n");
        assert!(is_suppressed(&suppressions, 1, "any.rule"));
        assert!(is_suppressed(&suppressions, 2, "any.rule"));
        assert!(!is_suppressed(&suppressions, 3, "any.rule"));
    }

    #[test]
    fn scoped_marker_does_not_suppress_other_rules() {
        let suppressions = parse_suppressions("foo(); // hawk:ignore rule.one\n");
        assert!(is_suppressed(&suppressions, 1, "rule.one"));
        assert!(!is_suppressed(&suppressions, 1, "rule.two"));
    }

    #[test]
    fn comment_above_the_finding_line_is_honored() {
        // Mirrors the fixture-annotation tolerance: the marker may sit on the
        // line above the flagged code.
        let suppressions = parse_suppressions("// nosec java.security.cookie\naddCookie(c);\n");
        assert!(is_suppressed(&suppressions, 2, "java.security.cookie"));
        assert!(!is_suppressed(
            &suppressions,
            2,
            "java.security.xss-response"
        ));
    }
}
