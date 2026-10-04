//! Tree-sitter query execution and predicate matching for AST-based rules.

use crate::language::Language;

/// Runs a tree-sitter query against a syntax tree and returns matching nodes.
///
/// With `anchor`, each query match contributes exactly the anchored capture's
/// node (the finding location); without it, every capture is reported. Nodes
/// whose text matches `not_regex` are discarded, and identical spans are
/// reported once. `#eq?`/`#match?`/`#any-of?` predicates are evaluated here
/// rather than by the tree-sitter crate, whose match iterator misbehaves when
/// a query carries text predicates (empty captures, runaway matches).
pub(crate) fn execute_query<'tree>(
    root: tree_sitter::Node<'tree>,
    source: &str,
    query_source: &str,
    anchor: Option<&str>,
    not_regex: Option<&str>,
    language: Option<Language>,
) -> Result<Vec<tree_sitter::Node<'tree>>, String> {
    use tree_sitter::StreamingIterator as _;
    let Some(language) = language else {
        return Err("query rules require a declared language".into());
    };
    let ts_language = match language {
        Language::Java => tree_sitter::Language::from(tree_sitter_java::LANGUAGE),
        Language::JavaScript => tree_sitter::Language::from(tree_sitter_javascript::LANGUAGE),
        Language::TypeScript => {
            tree_sitter::Language::from(tree_sitter_typescript::LANGUAGE_TYPESCRIPT)
        }
        Language::Python => tree_sitter::Language::from(tree_sitter_python::LANGUAGE),
        Language::Go => tree_sitter::Language::from(tree_sitter_go::LANGUAGE),
        Language::Unknown => return Err("unsupported language".into()),
    };
    let (clean_query, predicates) = split_predicates(query_source);
    let query = tree_sitter::Query::new(&ts_language, &clean_query).map_err(|e| e.to_string())?;
    let not_regex = not_regex
        .map(|pattern| regex::Regex::new(pattern).map_err(|e| format!("invalid not-regex: {e}")))
        .transpose()?;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut matches = cursor.matches(&query, root, source.as_bytes());
    let mut out: Vec<tree_sitter::Node<'tree>> = Vec::new();
    let mut seen: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();
    while let Some(m) = matches.next() {
        if !predicates_match(&query, m, &predicates, source) {
            continue;
        }
        let captured: Vec<tree_sitter::Node<'tree>> =
            m.captures.iter().map(|capture| capture.node).collect();
        // With an anchor, only the anchored node is a finding site; the other
        // captures exist to constrain the pattern (e.g. `@arg` filters).
        let sites: Vec<tree_sitter::Node<'tree>> = match anchor {
            Some(anchor) => {
                let anchored = m
                    .captures
                    .iter()
                    .find(|capture| query.capture_names()[capture.index as usize] == anchor);
                match anchored {
                    Some(node) => vec![node.node],
                    None => continue,
                }
            }
            None => captured,
        };
        for node in sites {
            let text = node.utf8_text(source.as_bytes()).unwrap_or_default();
            if not_regex.as_ref().is_some_and(|re| re.is_match(text)) {
                continue;
            }
            if seen.insert((node.start_byte(), node.end_byte())) {
                out.push(node);
            }
        }
    }
    Ok(out)
}

/// A `#eq?`/`#match?`/`#any-of?`-style predicate declared in a query.
struct Predicate {
    operator: String,
    capture: String,
    /// String literal arguments; the compiled regex when operator is a match.
    values: Vec<String>,
    regex: Option<regex::Regex>,
}

/// Splits `(#operator @capture "arg" ...)` predicates out of a query string
/// and returns the clean query plus the parsed predicates. The predicate forms
/// supported mirror tree-sitter's text predicates.
fn split_predicates(query_source: &str) -> (String, Vec<Predicate>) {
    let mut stripped = String::with_capacity(query_source.len());
    let mut predicates = Vec::new();
    let chars: Vec<char> = query_source.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '(' && chars.get(index + 1) == Some(&'#') {
            // Scan to the balanced closing paren, respecting string quotes.
            let mut depth = 0i32;
            let mut in_quote = false;
            let mut end = index;
            while end < chars.len() {
                let character = chars[end];
                if in_quote {
                    if character == '\\' {
                        end += 1;
                    } else if character == '"' {
                        in_quote = false;
                    }
                } else {
                    match character {
                        '"' => in_quote = true,
                        '(' => depth += 1,
                        ')' => {
                            depth -= 1;
                            if depth == 0 {
                                end += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                end += 1;
            }
            let text: String = chars[index..end].iter().collect();
            if let Some(predicate) = parse_predicate(&text) {
                predicates.push(predicate);
            }
            stripped.push(' ');
            index = end;
        } else {
            stripped.push(chars[index]);
            index += 1;
        }
    }
    (stripped, predicates)
}

fn parse_predicate(text: &str) -> Option<Predicate> {
    let pattern = regex::Regex::new(
        r#"^\(\s*#(?P<op>[a-z?-]+)\s+@(?P<cap>[a-zA-Z_0-9]+)(?P<vals>(?:\s+"(?:[^"\\]|\\.)*")*)\s*\)$"#,
    )
    .ok()?;
    let captures = pattern.captures(text)?;
    // Normalize `eq?`/`match?` to `eq`/`match` for the evaluation arms.
    let operator = captures
        .name("op")?
        .as_str()
        .trim_end_matches('?')
        .to_string();
    let capture = captures.name("cap")?.as_str().to_string();
    let values = regex::Regex::new(r#""((?:[^"\\]|\\.)*)""#)
        .ok()?
        .captures_iter(captures.name("vals")?.as_str())
        .filter_map(|value| value.get(1))
        .map(|value| value.as_str().to_string())
        .collect::<Vec<_>>();
    let regex = if matches!(operator.as_str(), "match" | "not-match") {
        values
            .first()
            .and_then(|value| regex::Regex::new(value).ok())
    } else {
        None
    };
    Some(Predicate {
        operator,
        capture,
        values,
        regex,
    })
}

/// Evaluates the query's predicates against one match. A capture that appears
/// several times must satisfy the predicate at every occurrence; a predicate
/// whose capture is absent passes (matching tree-sitter semantics).
fn predicates_match(
    query: &tree_sitter::Query,
    m: &tree_sitter::QueryMatch,
    predicates: &[Predicate],
    source: &str,
) -> bool {
    for predicate in predicates {
        let texts: Vec<&str> = m
            .captures
            .iter()
            .filter(|capture| query.capture_names()[capture.index as usize] == predicate.capture)
            .filter_map(|capture| capture.node.utf8_text(source.as_bytes()).ok())
            .collect();
        let passes = match predicate.operator.as_str() {
            "eq" => !texts.is_empty() && texts.iter().all(|text| *text == predicate.values[0]),
            "not-eq" => texts.is_empty() || texts.iter().all(|text| *text != predicate.values[0]),
            "match" => {
                !texts.is_empty()
                    && predicate
                        .regex
                        .as_ref()
                        .is_some_and(|re| texts.iter().all(|text| re.is_match(text)))
            }
            "not-match" => {
                texts.is_empty()
                    || predicate
                        .regex
                        .as_ref()
                        .is_some_and(|re| texts.iter().all(|text| !re.is_match(text)))
            }
            "any-of" => {
                !texts.is_empty()
                    && texts
                        .iter()
                        .all(|text| predicate.values.iter().any(|value| value == text))
            }
            "not-any-of" => {
                texts.is_empty()
                    || texts
                        .iter()
                        .all(|text| !predicate.values.iter().any(|value| value == text))
            }
            // Unknown or structural predicates (`set!`, `is?`, ...) are
            // ignored rather than silently rejecting every match.
            _ => true,
        };
        if !passes {
            return false;
        }
    }
    true
}
