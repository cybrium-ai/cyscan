use std::borrow::Cow;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ComparisonValue<'a> {
    Integer(i64),
    Text(Cow<'a, str>),
}

#[derive(Debug, Clone, Default)]
pub(super) struct CaptureMeta<'a> {
    pub text: &'a str,
    pub kind: Option<&'a str>,
}

pub(super) fn metavariable_comparison_matches<'a>(
    expression: &str,
    captures: &HashMap<String, CaptureMeta<'a>>,
) -> bool {
    let expr = expression.trim();
    if expr.is_empty() {
        return true;
    }

    let Some((lhs, op, rhs)) = split_comparison(expr) else {
        return false;
    };
    let Some(lhs) = eval_operand(lhs, captures) else {
        return false;
    };
    let Some(rhs) = eval_operand(rhs, captures) else {
        return false;
    };

    match op {
        "==" => values_equal(&lhs, &rhs),
        "!=" => !values_equal(&lhs, &rhs),
        ">" | ">=" | "<" | "<=" => compare_numeric(&lhs, &rhs, op),
        "contains" => compare_contains(&lhs, &rhs),
        "starts_with" => compare_starts_with(&lhs, &rhs),
        "ends_with" => compare_ends_with(&lhs, &rhs),
        "matches" => compare_matches(&lhs, &rhs),
        _ => false,
    }
}

pub(super) fn metavariable_comparisons_match<'a>(
    expressions: &[String],
    singular: Option<&str>,
    captures: &HashMap<String, CaptureMeta<'a>>,
) -> bool {
    singular
        .into_iter()
        .chain(expressions.iter().map(String::as_str))
        .all(|expr| metavariable_comparison_matches(expr, captures))
}

pub(super) fn metavariable_types_match<'a>(
    constraints: &HashMap<String, String>,
    captures: &HashMap<String, CaptureMeta<'a>>,
) -> bool {
    constraints.iter().all(|(name, expected)| {
        let capture = name.trim().trim_start_matches('$');
        let Some(meta) = captures.get(capture) else {
            return false;
        };
        capture_type_matches(expected, meta)
    })
}

/// Per-capture regex match — Semgrep `metavariable-regex` parity.
/// Returns true only when EVERY constraint is satisfied; an unknown
/// capture or an unparseable regex causes failure for that pair.
pub(super) fn metavariable_regex_match<'a>(
    constraints: &HashMap<String, String>,
    captures: &HashMap<String, CaptureMeta<'a>>,
) -> bool {
    if constraints.is_empty() { return true; }
    constraints.iter().all(|(raw_name, pattern)| {
        let name = raw_name.trim().trim_start_matches('$');
        let Some(meta) = captures.get(name) else { return false };
        match ::regex::Regex::new(pattern) {
            Ok(re) => re.is_match(meta.text),
            Err(_) => false,
        }
    })
}

/// Per-capture sub-pattern match — Semgrep `metavariable-pattern`
/// parity (regex flavour). Tries substring first (cheap), then regex.
/// Nested AST patterns are out of scope for this OSS engine and
/// deferred to a future release.
pub(super) fn metavariable_pattern_match<'a>(
    constraints: &HashMap<String, String>,
    captures: &HashMap<String, CaptureMeta<'a>>,
) -> bool {
    if constraints.is_empty() { return true; }
    constraints.iter().all(|(raw_name, pattern)| {
        let name = raw_name.trim().trim_start_matches('$');
        let Some(meta) = captures.get(name) else { return false };
        if meta.text.contains(pattern.as_str()) { return true; }
        match ::regex::Regex::new(pattern) {
            Ok(re) => re.is_match(meta.text),
            Err(_) => false,
        }
    })
}

/// Matched-span negative regex filter — Semgrep `pattern-not-regex`
/// parity. Returns true when the span SURVIVES the filter.
pub(super) fn pattern_not_regex_passes(patterns: &[String], text: &str) -> bool {
    if patterns.is_empty() { return true; }
    !patterns.iter().any(|p| {
        ::regex::Regex::new(p).map(|re| re.is_match(text)).unwrap_or(false)
    })
}

/// Per-capture analyzer — Semgrep Pro `metavariable-analysis` parity.
/// Each entry maps a capture name to one of:
///   * "redos"   — catastrophic-backtracking risk in a regex literal
///   * "entropy" — high-entropy string (>= 4.5 bits/char, length ≥ 16)
/// All analyzers must pass for the match to fire.
pub(super) fn metavariable_analysis_passes<'a>(
    constraints: &HashMap<String, String>,
    captures: &HashMap<String, CaptureMeta<'a>>,
) -> bool {
    if constraints.is_empty() { return true; }
    constraints.iter().all(|(raw_name, analyzer)| {
        let name = raw_name.trim().trim_start_matches('$');
        let Some(meta) = captures.get(name) else { return false };
        match analyzer.trim().to_lowercase().as_str() {
            "redos"   => has_redos_risk(meta.text),
            "entropy" => has_high_entropy(meta.text),
            _         => false,
        }
    })
}

/// Conservative ReDoS detector — flags regex literals with the
/// catastrophic-backtracking patterns documented in OWASP ReDoS.
/// Heuristic but high-signal: catches `(a+)+`, `(a|a)+`, `(.*)*`,
/// `(.+)+`, alternations of overlapping branches inside repeats.
pub fn has_redos_risk(regex_str: &str) -> bool {
    let s = regex_str;
    // 1. Nested unbounded quantifier — `(...)+` or `(...)*` immediately
    //    followed by `+` or `*`. Classic catastrophic backtracking.
    if has_nested_quantifier(s) { return true; }

    // 2. `.*` or `.+` more than once with intervening fixed text — not
    //    always pathological but flagged for review.
    let dotstar_count = s.matches(".*").count() + s.matches(".+").count();
    if dotstar_count >= 2 { return true; }

    // 3. Alternation inside a quantifier where alternatives overlap
    //    (e.g. `(a|a)+`, `(\d|\d+)+`). Cheap-but-imperfect detector:
    //    look for `(...|...)+` where the alternatives are equal after
    //    trimming whitespace.
    if let Some(start) = s.find("(") {
        if let Some(close) = s[start..].find(")+").or_else(|| s[start..].find(")*")) {
            let inner = &s[start+1..start+close];
            if inner.contains('|') {
                let parts: Vec<&str> = inner.split('|').map(str::trim).collect();
                for i in 0..parts.len() {
                    for j in i+1..parts.len() {
                        if parts[i] == parts[j]
                            || (parts[i].len() < parts[j].len() && parts[j].contains(parts[i]))
                            || (parts[j].len() < parts[i].len() && parts[i].contains(parts[j]))
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

fn has_nested_quantifier(s: &str) -> bool {
    // Look for `)+` or `)*` immediately preceded by a quantifier inside
    // the group (`+` or `*` on the inner side of `)`).
    let bytes = s.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        if (c == b'+' || c == b'*') && i + 1 < bytes.len() {
            let nxt = bytes[i + 1];
            if nxt == b')' && i + 2 < bytes.len() {
                let after = bytes[i + 2];
                if after == b'+' || after == b'*' || after == b'{' {
                    return true;
                }
            }
        }
    }
    false
}

/// Shannon-entropy gate. Returns true when the string looks like a
/// secret / token: length ≥ 16, Shannon entropy ≥ 3.5 bits/char,
/// AND the string mixes at least two of {upper, lower, digit} —
/// matches real API keys / JWTs / base64 secrets without flagging
/// natural-language sentences (which clear the entropy bar but are
/// usually all-lowercase).
pub fn has_high_entropy(s: &str) -> bool {
    if s.len() < 16 { return false; }
    if !mixes_two_char_classes(s) { return false; }
    let mut counts = [0u32; 256];
    let mut total = 0u32;
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    if total == 0 { return false; }
    let total_f = total as f64;
    let entropy: f64 = counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total_f;
            -p * p.log2()
        })
        .sum();
    entropy >= 3.5
}

fn mixes_two_char_classes(s: &str) -> bool {
    let mut classes = 0u8;
    if s.bytes().any(|b| b.is_ascii_lowercase()) { classes += 1; }
    if s.bytes().any(|b| b.is_ascii_uppercase()) { classes += 1; }
    if s.bytes().any(|b| b.is_ascii_digit())     { classes += 1; }
    classes >= 2
}

#[cfg(test)]
mod analyzer_tests {
    use super::*;

    #[test]
    fn redos_detects_nested_unbounded_quantifier() {
        assert!(has_redos_risk("(a+)+"));
        assert!(has_redos_risk("(.*)*"));
        assert!(has_redos_risk("(.+)+"));
    }

    #[test]
    fn redos_skips_safe_patterns() {
        assert!(!has_redos_risk(r"^[A-Za-z0-9_-]+$"));
        assert!(!has_redos_risk("hello"));
    }

    #[test]
    fn redos_detects_overlapping_alternation_in_quantifier() {
        assert!(has_redos_risk(r"(a|a)+"));
    }

    #[test]
    fn entropy_flags_high_entropy_token() {
        assert!(has_high_entropy("aGVsbG93b3JsZGZvb2Jhcg=="));
        assert!(has_high_entropy("xK7zP9mNvL2qR5tY8wB3aE6h"));
    }

    #[test]
    fn entropy_skips_low_entropy_strings() {
        assert!(!has_high_entropy("hello world"));
        assert!(!has_high_entropy("aaaaaaaaaaaaaaaa"));
    }
}

fn split_comparison(expr: &str) -> Option<(&str, &'static str, &str)> {
    for op in [
        " starts_with ",
        " ends_with ",
        " contains ",
        " matches ",
        "==",
        "!=",
        ">=",
        "<=",
        ">",
        "<",
    ] {
        if let Some(index) = expr.find(op) {
            let lhs = expr[..index].trim();
            let rhs = expr[index + op.len()..].trim();
            if !lhs.is_empty() && !rhs.is_empty() {
                return Some((lhs, normalize_operator(op), rhs));
            }
        }
    }
    None
}

fn normalize_operator(op: &str) -> &'static str {
    match op.trim() {
        "starts_with" => "starts_with",
        "ends_with" => "ends_with",
        "contains" => "contains",
        "matches" => "matches",
        "==" => "==",
        "!=" => "!=",
        ">=" => ">=",
        "<=" => "<=",
        ">" => ">",
        "<" => "<",
        _ => "",
    }
}

fn eval_operand<'a>(
    operand: &'a str,
    captures: &HashMap<String, CaptureMeta<'a>>,
) -> Option<ComparisonValue<'a>> {
    let operand = operand.trim();
    if let Some(inner) = unary_arg("len", operand) {
        let value = eval_operand(inner, captures)?;
        return Some(ComparisonValue::Integer(
            text_value(&value)?.chars().count() as i64,
        ));
    }
    if let Some(inner) = unary_arg("lower", operand) {
        let value = eval_operand(inner, captures)?;
        return Some(ComparisonValue::Text(Cow::Owned(
            text_value(&value)?.to_lowercase(),
        )));
    }
    if let Some(inner) = unary_arg("upper", operand) {
        let value = eval_operand(inner, captures)?;
        return Some(ComparisonValue::Text(Cow::Owned(
            text_value(&value)?.to_uppercase(),
        )));
    }
    if let Some(inner) = unary_arg("trim", operand) {
        let value = eval_operand(inner, captures)?;
        return Some(ComparisonValue::Text(Cow::Owned(
            text_value(&value)?.trim().to_string(),
        )));
    }

    if let Ok(value) = operand.parse::<i64>() {
        return Some(ComparisonValue::Integer(value));
    }

    if let Some(stripped) = strip_quoted(operand) {
        return Some(ComparisonValue::Text(Cow::Borrowed(stripped)));
    }

    if operand.starts_with('$') {
        let value = resolve_capture(operand, captures)?;
        if let Ok(parsed) = value.trim().parse::<i64>() {
            return Some(ComparisonValue::Integer(parsed));
        }
        return Some(ComparisonValue::Text(Cow::Borrowed(value.trim())));
    }

    None
}

fn text_value<'a>(value: &'a ComparisonValue<'a>) -> Option<&'a str> {
    match value {
        ComparisonValue::Text(text) => Some(text.as_ref()),
        ComparisonValue::Integer(_) => None,
    }
}

fn unary_arg<'a>(func: &str, operand: &'a str) -> Option<&'a str> {
    operand
        .strip_prefix(func)
        .and_then(|value| value.strip_prefix('('))
        .and_then(|value| value.strip_suffix(')'))
        .map(str::trim)
}

fn resolve_capture<'a>(name: &str, captures: &HashMap<String, CaptureMeta<'a>>) -> Option<&'a str> {
    let capture = name.trim().trim_start_matches('$');
    if capture.is_empty() {
        return None;
    }
    captures.get(capture).map(|meta| meta.text)
}

fn values_equal(lhs: &ComparisonValue<'_>, rhs: &ComparisonValue<'_>) -> bool {
    match (lhs, rhs) {
        (ComparisonValue::Integer(left), ComparisonValue::Integer(right)) => left == right,
        (ComparisonValue::Text(left), ComparisonValue::Text(right)) => left == right,
        _ => false,
    }
}

fn compare_numeric(lhs: &ComparisonValue<'_>, rhs: &ComparisonValue<'_>, op: &str) -> bool {
    let (ComparisonValue::Integer(left), ComparisonValue::Integer(right)) = (lhs, rhs) else {
        return false;
    };
    match op {
        ">" => left > right,
        ">=" => left >= right,
        "<" => left < right,
        "<=" => left <= right,
        _ => false,
    }
}

fn compare_contains(lhs: &ComparisonValue<'_>, rhs: &ComparisonValue<'_>) -> bool {
    let (ComparisonValue::Text(left), ComparisonValue::Text(right)) = (lhs, rhs) else {
        return false;
    };
    left.contains(right.as_ref())
}

fn compare_starts_with(lhs: &ComparisonValue<'_>, rhs: &ComparisonValue<'_>) -> bool {
    let (ComparisonValue::Text(left), ComparisonValue::Text(right)) = (lhs, rhs) else {
        return false;
    };
    left.starts_with(right.as_ref())
}

fn compare_ends_with(lhs: &ComparisonValue<'_>, rhs: &ComparisonValue<'_>) -> bool {
    let (ComparisonValue::Text(left), ComparisonValue::Text(right)) = (lhs, rhs) else {
        return false;
    };
    left.ends_with(right.as_ref())
}

fn compare_matches(lhs: &ComparisonValue<'_>, rhs: &ComparisonValue<'_>) -> bool {
    let (ComparisonValue::Text(left), ComparisonValue::Text(right)) = (lhs, rhs) else {
        return false;
    };
    regex::Regex::new(right)
        .ok()
        .is_some_and(|re| re.is_match(left))
}

fn capture_type_matches(expected: &str, meta: &CaptureMeta<'_>) -> bool {
    let expected = expected.trim().to_ascii_lowercase();
    let kind = meta.kind.unwrap_or_default().to_ascii_lowercase();
    let text = meta.text.trim();
    match expected.as_str() {
        "identifier" => kind.contains("identifier") || regex_identifier(text),
        "string" => kind.contains("string") || kind.contains("template") || quoted_text(text),
        "number" => {
            kind.contains("number")
                || kind.contains("integer")
                || kind.contains("float")
                || text.parse::<f64>().is_ok()
        }
        "call" => {
            kind.contains("call")
                || kind.contains("invocation")
                || (text.contains('(') && text.ends_with(')'))
        }
        "member_access" => {
            kind.contains("member")
                || kind.contains("attribute")
                || kind.contains("selector")
                || kind.contains("field")
                || text.contains('.')
                || text.contains('[')
        }
        "literal" => {
            quoted_text(text)
                || text.parse::<f64>().is_ok()
                || matches!(text, "true" | "false" | "null" | "None")
        }
        _ => false,
    }
}

fn regex_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn quoted_text(value: &str) -> bool {
    strip_quoted(value).is_some()
}

fn strip_quoted(value: &str) -> Option<&str> {
    if value.len() < 2 {
        return None;
    }
    let bytes = value.as_bytes();
    let quote = bytes[0];
    if (quote == b'"' || quote == b'\'') && bytes[value.len() - 1] == quote {
        return Some(&value[1..value.len() - 1]);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        metavariable_comparison_matches, metavariable_comparisons_match, metavariable_types_match,
        CaptureMeta,
    };
    use std::collections::HashMap;

    fn captures<'a>(pairs: &[(&'a str, &'a str)]) -> HashMap<String, CaptureMeta<'a>> {
        pairs
            .iter()
            .map(|(k, v)| {
                (
                    (*k).to_string(),
                    CaptureMeta {
                        text: v,
                        kind: None,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn len_based_comparison_matches() {
        let captures = captures(&[("arg", "user_input")]);
        assert!(metavariable_comparison_matches("len($arg) > 5", &captures));
        assert!(!metavariable_comparison_matches(
            "len($arg) > 20",
            &captures
        ));
    }

    #[test]
    fn string_functions_and_capture_to_capture_work() {
        let captures = captures(&[("fn", " Eval "), ("expected", "eval")]);
        assert!(metavariable_comparison_matches(
            r#"lower(trim($fn)) == $expected"#,
            &captures
        ));
        assert!(metavariable_comparison_matches(
            r#"$fn contains "va""#,
            &captures
        ));
    }

    #[test]
    fn plural_comparisons_all_must_match() {
        let captures = captures(&[("arg", "user_input"), ("fn", "eval")]);
        assert!(metavariable_comparisons_match(
            &[r#"len($arg) > 4"#.into(), r#"$fn == "eval""#.into()],
            None,
            &captures
        ));
        assert!(!metavariable_comparisons_match(
            &[r#"len($arg) > 20"#.into()],
            Some(r#"$fn == "eval""#),
            &captures
        ));
    }

    #[test]
    fn metavariable_types_use_kind_and_text() {
        let mut captures = HashMap::new();
        captures.insert(
            "arg".into(),
            CaptureMeta {
                text: "\"hello\"",
                kind: Some("string"),
            },
        );
        captures.insert(
            "fn".into(),
            CaptureMeta {
                text: "eval",
                kind: Some("identifier"),
            },
        );
        let constraints = HashMap::from([
            ("arg".to_string(), "string".to_string()),
            ("fn".to_string(), "identifier".to_string()),
        ]);
        assert!(metavariable_types_match(&constraints, &captures));
    }
}
