//! Regex matcher. Runs the compiled regex line-by-line, so column/row
//! reporting is straightforward. Multiline anchors aren't supported —
//! if a rule needs that, upgrade to tree-sitter.

use std::path::{Path, PathBuf};
use std::collections::HashMap;

use regex::{Regex, RegexBuilder};

use crate::{finding::Finding, lang::Lang, rule::Rule};

use super::semantics::FileSemantics;

/// Convert semgrep-style AST pattern to regex.
///
/// Semgrep uses `$VAR` for metavariables and `...` for wildcards.
/// We convert these to regex equivalents so imported rules work
/// without a full semgrep engine.
fn semgrep_to_regex(pattern: &str) -> String {
    // If pattern already looks like valid regex (no $VAR or ...), return as-is
    if !pattern.contains('$') && !pattern.contains("...") {
        return pattern.to_string();
    }

    let mut result = String::with_capacity(pattern.len() * 2);
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            c if c.is_whitespace() => {
                while i < chars.len() && chars[i].is_whitespace() {
                    i += 1;
                }
                result.push_str(r"\s+");
            }
            '$' => {
                // $VAR_NAME → \w+ (match any identifier)
                i += 1;
                // Skip the variable name (uppercase letters + underscores + digits)
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                result.push_str(r"\w+");
            }
            '.' if i + 2 < chars.len() && chars[i+1] == '.' && chars[i+2] == '.' => {
                // ... → .* (match anything)
                result.push_str(".*");
                i += 3;
            }
            // Escape regex metacharacters that might appear in code patterns
            '(' => { result.push_str(r"\("); i += 1; }
            ')' => { result.push_str(r"\)"); i += 1; }
            '[' => { result.push_str(r"\["); i += 1; }
            ']' => { result.push_str(r"\]"); i += 1; }
            '{' => { result.push_str(r"\{"); i += 1; }
            '}' => { result.push_str(r"\}"); i += 1; }
            '+' => { result.push_str(r"\+"); i += 1; }
            '*' => { result.push_str(r"\*"); i += 1; }
            '?' => { result.push_str(r"\?"); i += 1; }
            '|' if !is_regex_alternation(&chars, i) => { result.push_str(r"\|"); i += 1; }
            '^' => { result.push_str(r"\^"); i += 1; }
            c => { result.push(c); i += 1; }
        }
    }

    // Trim whitespace from the result
    result.trim().to_string()
}

/// Check if a `|` is part of a regex alternation (has regex chars around it)
/// vs. a literal pipe in code. Simple heuristic.
fn is_regex_alternation(chars: &[char], pos: usize) -> bool {
    // If the original pattern already has regex escapes, it's intentional
    if pos > 0 && chars[pos - 1] == '\\' { return false; }
    false // Default: treat | as literal in semgrep patterns
}

pub fn match_rule(
    rule: &Rule,
    lang: Lang,
    path: &Path,
    source: &str,
    semantics: &FileSemantics,
) -> Vec<Finding> {
    // YAML block literal `|` keeps a trailing newline, which the regex
    // crate treats as a literal \n requirement. Trim any surrounding
    // whitespace so rule authors don't have to remember `|-` every time.
    let raw = rule.regex.as_deref().or(rule.pattern.as_deref());
    let Some(pat) = raw.map(str::trim) else { return Vec::new() };
    if pat.is_empty() { return Vec::new() }

    // Convert semgrep AST patterns to regex:
    //   $VAR, $NAME, $FUNC  →  \w+  (any identifier)
    //   ...                  →  .*   (any code)
    //   [...]                →  \[.*\]
    //   $FUNC(...)           →  \w+\(.*\)
    let converted = semgrep_to_regex(pat);

    // Skip patterns that are too short/broad after conversion (would match everything)
    let meaningful = converted.replace(r"\w+", "").replace(".*", "").replace(r"\s+", "");
    if meaningful.trim().len() < 3 {
        return Vec::new();
    }

    let re = match Regex::new(&converted) {
        Ok(r)  => r,
        Err(e) => {
            log::debug!("rule {}: pattern compile failed: {e}", rule.id);
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    if needs_multiline_matching(pat) {
        let re = match RegexBuilder::new(&converted)
            .dot_matches_new_line(true)
            .multi_line(true)
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                log::debug!("rule {}: multiline pattern compile failed: {e}", rule.id);
                return Vec::new();
            }
        };

        for m in re.find_iter(source) {
            let (line, column) = byte_to_line_col(source, m.start());
            let (end_line, end_column) = byte_to_line_col(source, m.end());
            let snippet = source[m.start()..m.end()]
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            let (evidence, reachability) =
                annotate_regex_finding(rule, lang, source, &source[m.start()..m.end()], semantics);

            out.push(Finding {
                rule_id:    rule.id.clone(),
                title:      rule.title.clone(),
                severity:   rule.severity,
                message:    rule.message.clone(),
                file:       PathBuf::from(path),
                line,
                column,
                end_line,
                end_column,
                fingerprint: String::new(),
                start_byte: m.start(),
                end_byte:   m.end(),
                snippet,
                fix_recipe: rule.fix_recipe.clone(),
                fix:        rule.fix.clone(),
                cwe:        rule.cwe.clone(),
                evidence,
                reachability,
            });
        }
    } else {
        // Track byte offset of each line start so we can report absolute byte
        // ranges for the fixer. `source.lines()` strips newlines, so we walk
        // the source manually to keep offsets honest on \r\n and \n alike.
        let mut line_start = 0usize;
        for (line_ix, line) in source.split_inclusive('\n').enumerate() {
            let trimmed = line.trim_end_matches(['\r', '\n']);
            for m in re.find_iter(trimmed) {
                let (evidence, reachability) = annotate_regex_finding(rule, lang, source, trimmed, semantics);
                out.push(Finding {
                    rule_id:    rule.id.clone(),
                    title:      rule.title.clone(),
                    severity:   rule.severity,
                    message:    rule.message.clone(),
                    file:       PathBuf::from(path),
                    line:       line_ix + 1,
                    column:     m.start() + 1,
                    end_line:   line_ix + 1,
                    end_column: m.end() + 1,
                    fingerprint: String::new(),
                    start_byte: line_start + m.start(),
                    end_byte:   line_start + m.end(),
                    snippet:    trimmed.trim().to_string(),
                    fix_recipe: rule.fix_recipe.clone(),
                    fix:        rule.fix.clone(),
                    cwe:        rule.cwe.clone(),
                    evidence,
                    reachability,
                });
            }
            line_start += line.len();
        }
    }

    if out.is_empty() {
        out.extend(special_case_findings(rule, lang, path, source, semantics));
    }
    out
}

fn needs_multiline_matching(pattern: &str) -> bool {
    pattern.contains('\n')
}

fn byte_to_line_col(source: &str, byte_idx: usize) -> (usize, usize) {
    let clamped = byte_idx.min(source.len());
    let prefix = &source[..clamped];
    let line = prefix.bytes().filter(|b| *b == b'\n').count() + 1;
    let col = prefix.rsplit('\n').next().map(|s| s.chars().count()).unwrap_or(0) + 1;
    (line, col)
}

fn special_case_findings(
    rule: &Rule,
    lang: Lang,
    path: &Path,
    source: &str,
    semantics: &FileSemantics,
) -> Vec<Finding> {
    match (rule.id.as_str(), lang) {
        ("CBR-JAVA-SPRING_UNVALIDATED_REDIRECT", Lang::Java) => {
            let re = Regex::new(r#"return\s+"redirect:"\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)"#).unwrap();
            special_case_source_regex(rule, lang, path, source, semantics, &re)
        }
        ("CBR-JAVA-SPEL_INJECTION", Lang::Java) => {
            let re = Regex::new(r#"[A-Za-z_][A-Za-z0-9_]*\.parseExpression\(\s*([A-Za-z_][A-Za-z0-9_]*)"#).unwrap();
            special_case_source_regex(rule, lang, path, source, semantics, &re)
        }
        ("CBR-JAVA-SCRIPT_ENGINE_INJECTION", Lang::Java) => {
            let re = Regex::new(r#"[A-Za-z_][A-Za-z0-9_]*\.eval\(\s*([A-Za-z_][A-Za-z0-9_]*)"#).unwrap();
            special_case_source_regex(rule, lang, path, source, semantics, &re)
        }
        ("CBR-JAVA-FIND_SQL_STRING_CONCATENATION", Lang::Java) => {
            let re = Regex::new(r#"prepareStatement\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)"#).unwrap();
            special_case_source_regex(rule, lang, path, source, semantics, &re)
        }
        _ => Vec::new(),
    }
}

fn special_case_source_regex(
    rule: &Rule,
    lang: Lang,
    path: &Path,
    source: &str,
    semantics: &FileSemantics,
    re: &Regex,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for caps in re.captures_iter(source) {
        let Some(m) = caps.get(0) else { continue };
        let (line, column) = byte_to_line_col(source, m.start());
        let (end_line, end_column) = byte_to_line_col(source, m.end());
        let snippet = m.as_str().lines().next().unwrap_or("").trim().to_string();
        let (mut evidence, reachability) = annotate_regex_finding(rule, lang, source, m.as_str(), semantics);

        if let Some(arg) = caps.get(1).map(|m| m.as_str()) {
            if evidence.get("source_kind").is_none() {
                if let Some(kind) = semantics.tainted_identifiers.get(arg) {
                    evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                    evidence.insert("source_kind".into(), serde_json::json!(kind));
                }
            }
        }
        out.push(Finding {
            rule_id:    rule.id.clone(),
            title:      rule.title.clone(),
            severity:   rule.severity,
            message:    rule.message.clone(),
            file:       PathBuf::from(path),
            line,
            column,
            end_line,
            end_column,
            fingerprint: String::new(),
            start_byte: m.start(),
            end_byte:   m.end(),
            snippet,
            fix_recipe: rule.fix_recipe.clone(),
            fix:        rule.fix.clone(),
            cwe:        rule.cwe.clone(),
            evidence,
            reachability,
        });
    }
    out
}

fn annotate_regex_finding(
    rule: &Rule,
    lang: Lang,
    _source: &str,
    snippet: &str,
    semantics: &FileSemantics,
) -> (HashMap<String, serde_json::Value>, Option<String>) {
    let mut evidence = HashMap::new();
    evidence.insert("matcher_kind".into(), serde_json::json!("regex"));

    let sink_kind = match rule.id.as_str() {
        "CBR-JS-REACT-DANGEROUS-HTML" => Some("react.dangerously_set_inner_html"),
        "CBR-RUBY-AVOID_RAW" => Some("rails.raw"),
        "CBR-RUBY-AVOID_HTML_SAFE" => Some("rails.html_safe"),
        "CBR-RUBY-AVOID_RENDER_TEXT" => Some("rails.render_text"),
        "CBR-RUBY-AVOID_RENDER_INLINE" => Some("rails.render_inline"),
        "CBR-RUBY-AVOID_CONTENT_TAG" => Some("rails.content_tag"),
        "CBR-JAVA-SPRING_UNVALIDATED_REDIRECT" => Some("spring.redirect"),
        "CBR-JAVA-SPEL_INJECTION" => Some("spring.spel.parse_expression"),
        "CBR-JAVA-SCRIPT_ENGINE_INJECTION" => Some("java.script_engine.eval"),
        "CBR-JAVA-FIND_SQL_STRING_CONCATENATION" => Some("java.sql.prepare_statement"),
        "CBR-PYTH-EVAL_INJECTION" => Some("python.eval"),
        "CBR-PYTH-EXEC_INJECTION" => Some("python.exec"),
        "CBR-PYTH-SSRF_REQUESTS" => Some("python.requests"),
        "CBR-PYTH-OS_SYSTEM_INJECTION" => Some("python.os_system"),
        "CBR-PYTH-MAKE_RESPONSE_WITH_UNKNOWN_CON" => Some("flask.make_response"),
        "CBR-PYTH-RENDER_TEMPLATE_STRING" => Some("flask.render_template_string"),
        "CBR-PYTH-DANGEROUS_TEMPLATE_STRING" => Some("flask.render_template_string"),
        "CBR-PYTH-RESPONSE_CONTAINS_UNSANITIZED_" => Some("flask.make_response"),
        "CBR-PYTH-SQLALCHEMY_EXECUTE_RAW_QUERY" => Some("python.sqlalchemy.execute"),
        _ => None,
    };

    if let Some(sink_kind) = sink_kind {
        evidence.insert("sink_kind".into(), serde_json::json!(sink_kind));
    }

    match rule.id.as_str() {
        "CBR-JS-REACT-DANGEROUS-HTML" => {
            evidence.insert("framework".into(), serde_json::json!("react"));
            if let Some(sanitizer_kind) = regex_sanitizer_kind(rule.id.as_str(), snippet) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("guarded"));
                evidence.insert("sanitizer_kind".into(), serde_json::json!(sanitizer_kind));
                return (evidence, Some("unknown".into()));
            }
            if let Some(source_kind) = regex_source_kind(lang, snippet, semantics) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                return (evidence, Some("reachable".into()));
            }
            evidence.insert("path_sensitivity".into(), serde_json::json!("no_source_detected"));
            return (evidence, Some("unknown".into()));
        }
        "CBR-RUBY-AVOID_RAW"
        | "CBR-RUBY-AVOID_HTML_SAFE"
        | "CBR-RUBY-AVOID_RENDER_TEXT"
        | "CBR-RUBY-AVOID_RENDER_INLINE"
        | "CBR-RUBY-AVOID_CONTENT_TAG" => {
            evidence.insert("framework".into(), serde_json::json!("rails"));
            if let Some(sanitizer_kind) = regex_sanitizer_kind(rule.id.as_str(), snippet) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("guarded"));
                evidence.insert("sanitizer_kind".into(), serde_json::json!(sanitizer_kind));
                return (evidence, Some("unknown".into()));
            }
            if let Some(source_kind) = regex_source_kind(lang, snippet, semantics) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                return (evidence, Some("reachable".into()));
            }
            evidence.insert("path_sensitivity".into(), serde_json::json!("no_source_detected"));
            return (evidence, Some("unknown".into()));
        }
        "CBR-JAVA-SPRING_UNVALIDATED_REDIRECT"
        | "CBR-JAVA-SPEL_INJECTION"
        | "CBR-JAVA-SCRIPT_ENGINE_INJECTION"
        | "CBR-JAVA-FIND_SQL_STRING_CONCATENATION" => {
            evidence.insert("framework".into(), serde_json::json!("spring"));
            if let Some(sanitizer_kind) = regex_sanitizer_kind(rule.id.as_str(), snippet) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("guarded"));
                evidence.insert("sanitizer_kind".into(), serde_json::json!(sanitizer_kind));
                return (evidence, Some("unknown".into()));
            }
            if let Some(source_kind) = regex_source_kind(lang, snippet, semantics) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                return (evidence, Some("reachable".into()));
            }
            if semantics.frameworks.contains("spring") {
                evidence.insert("path_sensitivity".into(), serde_json::json!("no_source_detected"));
                return (evidence, Some("unknown".into()));
            }
        }
        "CBR-PYTH-MAKE_RESPONSE_WITH_UNKNOWN_CON"
        | "CBR-PYTH-EVAL_INJECTION"
        | "CBR-PYTH-EXEC_INJECTION"
        | "CBR-PYTH-SSRF_REQUESTS"
        | "CBR-PYTH-OS_SYSTEM_INJECTION"
        | "CBR-PYTH-RENDER_TEMPLATE_STRING"
        | "CBR-PYTH-DANGEROUS_TEMPLATE_STRING"
        | "CBR-PYTH-RESPONSE_CONTAINS_UNSANITIZED_"
        | "CBR-PYTH-SQLALCHEMY_EXECUTE_RAW_QUERY" => {
            if semantics.frameworks.contains("django") {
                evidence.insert("framework".into(), serde_json::json!("django"));
            } else {
                evidence.insert("framework".into(), serde_json::json!("flask"));
            }
            if let Some(sanitizer_kind) = regex_sanitizer_kind(rule.id.as_str(), snippet) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("guarded"));
                evidence.insert("sanitizer_kind".into(), serde_json::json!(sanitizer_kind));
                return (evidence, Some("unknown".into()));
            }
            if let Some(source_kind) = regex_source_kind(lang, snippet, semantics) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                return (evidence, Some("reachable".into()));
            }
            evidence.insert("path_sensitivity".into(), serde_json::json!("no_source_detected"));
            return (evidence, Some("unknown".into()));
        }
        _ => {}
    }

    (evidence, None)
}

fn regex_sanitizer_kind(rule_id: &str, snippet: &str) -> Option<&'static str> {
    match rule_id {
        "CBR-JS-REACT-DANGEROUS-HTML" => {
            if snippet.contains("DOMPurify.sanitize(") {
                return Some("dompurify");
            }
            if snippet.contains("escapeHtml(") || snippet.contains("he.encode(") {
                return Some("html_escape");
            }
        }
        "CBR-RUBY-AVOID_RAW"
        | "CBR-RUBY-AVOID_HTML_SAFE"
        | "CBR-RUBY-AVOID_RENDER_TEXT"
        | "CBR-RUBY-AVOID_RENDER_INLINE"
        | "CBR-RUBY-AVOID_CONTENT_TAG" => {
            if snippet.contains("sanitize(") {
                return Some("rails.sanitize");
            }
            if snippet.contains("strip_tags(") {
                return Some("rails.strip_tags");
            }
            if snippet.contains("ERB::Util.html_escape(") || snippet.contains("h(") {
                return Some("rails.html_escape");
            }
        }
        "CBR-PYTH-MAKE_RESPONSE_WITH_UNKNOWN_CON"
        | "CBR-PYTH-RENDER_TEMPLATE_STRING"
        | "CBR-PYTH-DANGEROUS_TEMPLATE_STRING"
        | "CBR-PYTH-RESPONSE_CONTAINS_UNSANITIZED_" => {
            if snippet.contains("format_html(") {
                return Some("django.format_html");
            }
            if snippet.contains("conditional_escape(") {
                return Some("django.conditional_escape");
            }
            if snippet.contains("flask.escape(") {
                return Some("flask.escape");
            }
            if snippet.contains("markupsafe.escape(") {
                return Some("markupsafe.escape");
            }
            if snippet.contains("django.utils.html.escape(") || snippet.contains("html.escape(") {
                return Some("html.escape");
            }
            if rule_id == "CBR-PYTH-MAKE_RESPONSE_WITH_UNKNOWN_CON" && snippet.contains("jsonify(") {
                return Some("flask.jsonify");
            }
        }
        "CBR-JAVA-SPRING_UNVALIDATED_REDIRECT" => {
            if snippet.contains("UriUtils.encode(") || snippet.contains("URLEncoder.encode(") {
                return Some("spring.url_encode");
            }
            if snippet.contains("UriComponentsBuilder.") {
                return Some("spring.uri_components_builder");
            }
        }
        "CBR-JAVA-SPEL_INJECTION" => {
            if snippet.contains("SimpleEvaluationContext") {
                return Some("spring.simple_evaluation_context");
            }
        }
        "CBR-JAVA-FIND_SQL_STRING_CONCATENATION" => {
            if snippet.contains('?') && snippet.contains("prepareStatement(") {
                return Some("java.prepared_statement_parameterization");
            }
        }
        _ => {}
    }
    None
}

fn regex_source_kind(
    lang: Lang,
    snippet: &str,
    semantics: &FileSemantics,
) -> Option<String> {
    if let Some(kind) = direct_regex_source_kind(lang, snippet) {
        return Some(kind.into());
    }

    for token in snippet.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' || c == '$')) {
        if let Some(kind) = semantics.tainted_identifiers.get(token) {
            return Some(kind.clone());
        }
    }
    None
}

fn direct_regex_source_kind(lang: Lang, snippet: &str) -> Option<&'static str> {
    match lang {
        Lang::Javascript | Lang::Typescript => {
            let compact: String = snippet.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.contains("req.query.") || compact.contains("request.query.") {
                return Some("express.req.query");
            }
            if compact.contains("req.params.") || compact.contains("request.params.") {
                return Some("express.req.params");
            }
            if compact.contains("req.body.") || compact.contains("request.body.") {
                return Some("express.req.body");
            }
        }
        Lang::Ruby => {
            if snippet.contains("params[") || snippet.contains("params.") {
                return Some("rails.params");
            }
        }
        Lang::Java => {
            if snippet.contains("request.getParameter(") {
                return Some("spring.http_request_parameter");
            }
        }
        Lang::Python => {
            let compact: String = snippet.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.contains("request.args.get(") || compact.contains("flask.request.args.get(") {
                return Some("flask.request.args");
            }
            if compact.contains("request.form.get(") || compact.contains("flask.request.form.get(") {
                return Some("flask.request.form");
            }
            if compact.contains("request.GET.get(") || compact.contains("request.GET[") {
                return Some("django.request.GET");
            }
            if compact.contains("request.POST.get(") || compact.contains("request.POST[") {
                return Some("django.request.POST");
            }
            if compact.contains("input(") {
                return Some("python.input");
            }
        }
        _ => {}
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::semantics;

    #[test]
    fn spring_spel_annotation_uses_request_param_taint() {
        let rule = Rule {
            id: "CBR-JAVA-SPEL_INJECTION".into(),
            title: "Spel Injection".into(),
            severity: crate::finding::Severity::High,
            languages: vec![Lang::Java],
            query: None,
            regex: None,
            pattern: Some("$X $METHOD(...) { ... $PARSER.parseExpression(...); ... }".into()),
            message: "msg".into(),
            fix_recipe: None,
            fix: None,
            dependency: None,
            cwe: vec!["CWE-94".into()],
            frameworks: vec![],
            source: None,
            cia: None,
        };
        let source = "import org.springframework.web.bind.annotation.RequestParam;\nclass Controller { String go(@RequestParam String expr) { parser.parseExpression(expr); return expr; } }\n";
        let semantics = semantics::extract(Lang::Java, source);
        let (evidence, reachability) = annotate_regex_finding(
            &rule,
            Lang::Java,
            source,
            "parser.parseExpression(expr);",
            &semantics,
        );

        assert_eq!(reachability.as_deref(), Some("reachable"));
        assert_eq!(evidence.get("framework").and_then(|v| v.as_str()), Some("spring"));
        assert_eq!(evidence.get("sink_kind").and_then(|v| v.as_str()), Some("spring.spel.parse_expression"));
        assert_eq!(evidence.get("source_kind").and_then(|v| v.as_str()), Some("spring.request_param"));
    }

    #[test]
    fn python_eval_annotation_uses_flask_request_taint() {
        let rule = Rule {
            id: "CBR-PYTH-EVAL_INJECTION".into(),
            title: "Eval Injection".into(),
            severity: crate::finding::Severity::Critical,
            languages: vec![Lang::Python],
            query: None,
            regex: None,
            pattern: Some("eval(..., <... flask.request.$W.get(...) ...>, ...)".into()),
            message: "msg".into(),
            fix_recipe: None,
            fix: None,
            dependency: None,
            cwe: vec!["CWE-95".into()],
            frameworks: vec![],
            source: None,
            cia: None,
        };
        let source = "import flask\npayload = flask.request.args.get('code')\n";
        let semantics = semantics::extract(Lang::Python, source);
        let (evidence, reachability) = annotate_regex_finding(
            &rule,
            Lang::Python,
            source,
            "eval(payload)",
            &semantics,
        );

        assert_eq!(reachability.as_deref(), Some("reachable"));
        assert_eq!(evidence.get("framework").and_then(|v| v.as_str()), Some("flask"));
        assert_eq!(evidence.get("sink_kind").and_then(|v| v.as_str()), Some("python.eval"));
        assert_eq!(evidence.get("source_kind").and_then(|v| v.as_str()), Some("flask.request.args"));
    }

    #[test]
    fn byte_to_line_col_maps_offsets() {
        let source = "one\ntwo\nthree";
        assert_eq!(byte_to_line_col(source, 0), (1, 1));
        assert_eq!(byte_to_line_col(source, 4), (2, 1));
        assert_eq!(byte_to_line_col(source, source.len()), (3, 6));
    }

    #[test]
    fn spring_redirect_special_case_matches_annotated_param() {
        let rule = Rule {
            id: "CBR-JAVA-SPRING_UNVALIDATED_REDIRECT".into(),
            title: "Spring Unvalidated Redirect".into(),
            severity: crate::finding::Severity::High,
            languages: vec![Lang::Java],
            query: None,
            regex: None,
            pattern: Some("$X $METHOD(...,String $URL,...) { return \"redirect:\" + $URL; }".into()),
            message: "msg".into(),
            fix_recipe: None,
            fix: None,
            dependency: None,
            cwe: vec!["CWE-601".into()],
            frameworks: vec![],
            source: None,
            cia: None,
        };
        let source = "import org.springframework.web.bind.annotation.RequestParam;\nclass Controller { String go(@RequestParam String next) { return \"redirect:\" + next; } }\n";
        let semantics = semantics::extract(Lang::Java, source);
        let findings = special_case_findings(&rule, Lang::Java, Path::new("Controller.java"), source, &semantics);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence.get("source_kind").and_then(|v| v.as_str()), Some("spring.request_param"));
    }

    #[test]
    fn spring_script_engine_special_case_matches_annotated_param() {
        let rule = Rule {
            id: "CBR-JAVA-SCRIPT_ENGINE_INJECTION".into(),
            title: "Script Engine Injection".into(),
            severity: crate::finding::Severity::High,
            languages: vec![Lang::Java],
            query: None,
            regex: None,
            pattern: Some("$SE.eval(...)".into()),
            message: "msg".into(),
            fix_recipe: None,
            fix: None,
            dependency: None,
            cwe: vec!["CWE-94".into()],
            frameworks: vec![],
            source: None,
            cia: None,
        };
        let source = "import org.springframework.web.bind.annotation.RequestParam;\nclass Controller { String go(@RequestParam String expr) { engine.eval(expr); return expr; } }\n";
        let semantics = semantics::extract(Lang::Java, source);
        let findings = special_case_findings(&rule, Lang::Java, Path::new("Controller.java"), source, &semantics);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence.get("source_kind").and_then(|v| v.as_str()), Some("spring.request_param"));
        assert_eq!(findings[0].evidence.get("sink_kind").and_then(|v| v.as_str()), Some("java.script_engine.eval"));
    }

    #[test]
    fn spring_sql_prepare_statement_special_case_uses_tainted_query() {
        let rule = Rule {
            id: "CBR-JAVA-FIND_SQL_STRING_CONCATENATION".into(),
            title: "SQL string concatenation".into(),
            severity: crate::finding::Severity::Critical,
            languages: vec![Lang::Java],
            query: None,
            regex: None,
            pattern: Some("PreparedStatement $PS = $SESSION.connection().prepareStatement($QUERY);".into()),
            message: "msg".into(),
            fix_recipe: None,
            fix: None,
            dependency: None,
            cwe: vec!["CWE-89".into()],
            frameworks: vec![],
            source: None,
            cia: None,
        };
        let source = "import org.springframework.web.bind.annotation.RequestParam;\nclass Controller {\n  void run(@RequestParam String user, Connection conn) throws Exception {\n    String query = \"select * from t where user='\" + user + \"'\";\n    PreparedStatement ps = conn.prepareStatement(query);\n  }\n}\n";
        let semantics = semantics::extract(Lang::Java, source);
        let findings = special_case_findings(&rule, Lang::Java, Path::new("Controller.java"), source, &semantics);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence.get("source_kind").and_then(|v| v.as_str()), Some("spring.request_param"));
        assert_eq!(findings[0].evidence.get("sink_kind").and_then(|v| v.as_str()), Some("java.sql.prepare_statement"));
    }

    #[test]
    fn spring_redirect_sanitizer_is_recognized() {
        assert_eq!(
            regex_sanitizer_kind("CBR-JAVA-SPRING_UNVALIDATED_REDIRECT", r#"return "redirect:" + URLEncoder.encode(next)"#),
            Some("spring.url_encode")
        );
    }

    #[test]
    fn django_format_html_sanitizer_is_recognized() {
        assert_eq!(
            regex_sanitizer_kind("CBR-PYTH-MAKE_RESPONSE_WITH_UNKNOWN_CON", r#"flask.make_response(format_html("{}", value))"#),
            Some("django.format_html")
        );
    }
}
