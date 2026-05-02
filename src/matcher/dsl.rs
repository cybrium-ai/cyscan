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
