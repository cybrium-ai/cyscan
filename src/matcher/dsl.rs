use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ComparisonValue<'a> {
    Integer(i64),
    Text(Cow<'a, str>),
}

pub(super) fn metavariable_comparison_matches<'a, F>(expression: &str, mut resolver: F) -> bool
where
    F: FnMut(&str) -> Option<&'a str>,
{
    let expr = expression.trim();
    if expr.is_empty() {
        return true;
    }

    let Some((lhs, op, rhs)) = split_comparison(expr) else {
        return false;
    };
    let Some(lhs) = eval_operand(lhs, &mut resolver) else {
        return false;
    };
    let Some(rhs) = eval_operand(rhs, &mut resolver) else {
        return false;
    };

    match (lhs, rhs) {
        (ComparisonValue::Integer(left), ComparisonValue::Integer(right)) => match op {
            "==" => left == right,
            "!=" => left != right,
            ">" => left > right,
            ">=" => left >= right,
            "<" => left < right,
            "<=" => left <= right,
            _ => false,
        },
        (ComparisonValue::Text(left), ComparisonValue::Text(right)) => match op {
            "==" => left == right,
            "!=" => left != right,
            _ => false,
        },
        _ => false,
    }
}

fn split_comparison(expr: &str) -> Option<(&str, &'static str, &str)> {
    for op in ["==", "!=", ">=", "<=", ">", "<"] {
        if let Some(index) = expr.find(op) {
            let lhs = expr[..index].trim();
            let rhs = expr[index + op.len()..].trim();
            if !lhs.is_empty() && !rhs.is_empty() {
                return Some((lhs, op, rhs));
            }
        }
    }
    None
}

fn eval_operand<'a, F>(operand: &str, resolver: &mut F) -> Option<ComparisonValue<'a>>
where
    F: FnMut(&str) -> Option<&'a str>,
{
    let operand = operand.trim();
    if let Some(inner) = operand
        .strip_prefix("len(")
        .and_then(|value| value.strip_suffix(')'))
    {
        let value = resolve_capture(inner.trim(), resolver)?;
        return Some(ComparisonValue::Integer(value.chars().count() as i64));
    }

    if let Ok(value) = operand.parse::<i64>() {
        return Some(ComparisonValue::Integer(value));
    }

    if let Some(stripped) = strip_quoted(operand) {
        return Some(ComparisonValue::Text(Cow::Owned(stripped.to_string())));
    }

    if operand.starts_with('$') {
        let value = resolve_capture(operand, resolver)?;
        if let Ok(parsed) = value.trim().parse::<i64>() {
            return Some(ComparisonValue::Integer(parsed));
        }
        return Some(ComparisonValue::Text(Cow::Borrowed(value.trim())));
    }

    None
}

fn resolve_capture<'a, F>(name: &str, resolver: &mut F) -> Option<&'a str>
where
    F: FnMut(&str) -> Option<&'a str>,
{
    let capture = name.trim().trim_start_matches('$');
    if capture.is_empty() {
        return None;
    }
    resolver(capture)
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
    use std::collections::HashMap;

    use super::metavariable_comparison_matches;

    #[test]
    fn len_based_comparison_matches() {
        let mut captures = HashMap::new();
        captures.insert("arg", "user_input");
        assert!(metavariable_comparison_matches("len($arg) > 5", |name| {
            captures.get(name).copied()
        }));
        assert!(!metavariable_comparison_matches("len($arg) > 20", |name| {
            captures.get(name).copied()
        }));
    }

    #[test]
    fn string_equality_comparison_matches() {
        let mut captures = HashMap::new();
        captures.insert("fn", "eval");
        assert!(metavariable_comparison_matches(
            r#"$fn == "eval""#,
            |name| captures.get(name).copied()
        ));
        assert!(!metavariable_comparison_matches(
            r#"$fn == "safeEval""#,
            |name| captures.get(name).copied()
        ));
    }
}
