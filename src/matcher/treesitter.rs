//! Tree-sitter matcher. One Parser per call — tree-sitter Parsers aren't
//! Sync-safe, so we don't try to share them across threads.

use std::path::{Path, PathBuf};
use std::collections::HashMap;

use anyhow::{Context, Result};
use regex::Regex;
use tree_sitter::{Parser, Query, QueryCursor, Tree};

use crate::{finding::Finding, lang::Lang, rule::Rule};

use super::semantics::FileSemantics;

#[derive(Debug, Clone)]
struct PathSensitivity {
    reachability: Option<String>,
    evidence: HashMap<String, serde_json::Value>,
}

enum PythonTaintOutcome {
    Tainted(String, Option<String>),
    Guarded(String),
    NoSource,
}

pub fn parse(lang: Lang, source: &str) -> Result<Tree> {
    let mut parser = Parser::new();
    let grammar = lang.tree_sitter()
        .with_context(|| format!("no tree-sitter grammar for {lang}"))?;
    parser.set_language(&grammar)
        .with_context(|| format!("setting tree-sitter language {lang}"))?;
    parser.parse(source, None)
        .context("tree-sitter parse returned None")
}

pub fn match_rule(
    rule:   &Rule,
    lang:   Lang,
    path:   &Path,
    source: &str,
    tree:   &Tree,
    semantics: &FileSemantics,
) -> Vec<Finding> {
    let Some(q_str) = rule.query.as_deref() else { return Vec::new() };

    let Some(grammar) = lang.tree_sitter() else { return Vec::new() };
    let query = match Query::new(&grammar, q_str) {
        Ok(q)  => q,
        Err(e) => {
            log::warn!("rule {}: query compile failed: {e}", rule.id);
            return Vec::new();
        }
    };

    let bytes = source.as_bytes();
    let mut cursor = QueryCursor::new();
    let mut out = Vec::new();

    for m in cursor.matches(&query, tree.root_node(), bytes) {
        // Report on the first captured node — rules author the query
        // so the first capture is the "problem" node. For queries with
        // multiple captures we take the primary.
        let Some(cap) = select_primary_capture(&query, &m.captures) else { continue };
        let node     = cap.node;
        let start    = node.start_position();
        let end      = node.end_position();
        let snippet  = node.utf8_text(bytes).unwrap_or("").lines().next()
            .unwrap_or("").trim().to_string();
        let mut evidence = HashMap::new();
        evidence.insert("matcher_kind".into(), serde_json::json!("tree_sitter"));
        let mut captures = HashMap::new();
        for capture in m.captures {
            let name = query.capture_names()[capture.index as usize].to_string();
            if let Ok(text) = capture.node.utf8_text(bytes) {
                captures.entry(name.clone()).or_insert_with(|| text.to_string());
                evidence.entry(name).or_insert_with(|| serde_json::json!(text));
            }
        }

        if !semantic_guard(rule, semantics, &captures) {
            continue;
        }

        let path_sensitivity = analyze_path_sensitivity(rule, lang, source, node, &captures, semantics);
        evidence.extend(path_sensitivity.evidence);
        evidence.extend(base_semantic_evidence(rule, semantics));

        out.push(Finding {
            rule_id:    rule.id.clone(),
            title:      rule.title.clone(),
            severity:   rule.severity,
            message:    rule.message.clone(),
            file:       PathBuf::from(path),
            line:       start.row + 1,
            column:     start.column + 1,
            end_line:   end.row + 1,
            end_column: end.column + 1,
            fingerprint: String::new(),
            start_byte: node.start_byte(),
            end_byte:   node.end_byte(),
            snippet,
            fix_recipe: rule.fix_recipe.clone(),
            fix:        rule.fix.clone(),
            cwe:        rule.cwe.clone(),
            evidence,
            reachability: path_sensitivity.reachability,
        });
    }
    out
}

fn base_semantic_evidence(
    rule: &Rule,
    semantics: &FileSemantics,
) -> HashMap<String, serde_json::Value> {
    let mut evidence = HashMap::new();

    if let Some(sink_kind) = match rule.id.as_str() {
        "CBR-PY-CODE-EVAL" => Some("python.eval"),
        "CBR-PY-PICKLE-LOADS" => Some("python.pickle.loads"),
        "CBR-PY-SQLI-STRING-CONCAT" => Some("python.db.execute"),
        "CBR-JS-CODE-EVAL" => Some("javascript.eval"),
        "CBR-JS-XSS-INNER-HTML" => Some("dom.inner_html"),
        "CBR-JS-DOCUMENT-WRITE" => Some("dom.document_write"),
        "CBR-CSHA-SQL_INJECTION" => Some("dotnet.sql.execute"),
        "CBR-CSHA-XSS_HTML_RAW" => Some("aspnet.html_raw"),
        "CBR-CSHA-COMMAND_INJECTION" => Some("dotnet.process_start"),
        _ => None,
    } {
        evidence.insert("sink_kind".into(), serde_json::json!(sink_kind));
    }

    if let Some(framework) = pick_framework_from_rule(rule, semantics) {
        evidence.insert("framework".into(), serde_json::json!(framework));
    }

    evidence
}

fn semantic_guard(
    rule: &Rule,
    semantics: &FileSemantics,
    captures: &HashMap<String, String>,
) -> bool {
    match rule.id.as_str() {
        "CBR-PY-PICKLE-LOADS" => {
            let Some(object) = captures.get("obj") else { return false };
            let object = object.trim();
            if object == "pickle" && semantics.imported_modules.contains("pickle") {
                return true;
            }
            if semantics.alias_to_module.get(object).map(String::as_str) == Some("pickle") {
                return true;
            }
            semantics.imported_symbols.get(object)
                .map(String::as_str)
                .is_some_and(|sym| sym == "pickle.loads" || sym == "pickle.load")
        }
        "CBR-PY-SQLI-STRING-CONCAT" => {
            let Some(object) = captures.get("obj") else { return true };
            let object = object.trim();
            if object == "cursor" || object == "db" || object == "conn" || object == "connection" {
                return true;
            }
            if semantics.alias_to_module.contains_key(object) {
                return false;
            }
            if let Some(module) = semantics.python_from_import_modules.get(object) {
                return !module.starts_with("sqlalchemy");
            }
            true
        }
        "CBR-JS-XSS-INNER-HTML" => {
            let Some(object) = captures.get("obj") else { return true };
            let object = object.trim();
            if object == "document" || object == "el" || object == "node" || object == "element" {
                return true;
            }
            if let Some(module) = semantics.js_namespace_imports.get(object) {
                return module != "react";
            }
            true
        }
        _ => true,
    }
}

fn analyze_path_sensitivity(
    rule: &Rule,
    lang: Lang,
    source: &str,
    node: tree_sitter::Node<'_>,
    captures: &HashMap<String, String>,
    semantics: &FileSemantics,
) -> PathSensitivity {
    if let Some(reason) = dead_code_reason(source, node) {
        let mut evidence = HashMap::new();
        evidence.insert("path_sensitivity".into(), serde_json::json!("dead_code"));
        evidence.insert("path_sensitivity_reason".into(), serde_json::json!(reason));
        return PathSensitivity {
            reachability: Some("unreachable".into()),
            evidence,
        };
    }

    if let Some(reason) = guarded_reason(rule, lang, source, node, captures) {
        let mut evidence = HashMap::new();
        evidence.insert("path_sensitivity".into(), serde_json::json!("guarded"));
        evidence.insert("path_sensitivity_reason".into(), serde_json::json!(reason));
        return PathSensitivity {
            reachability: Some("unknown".into()),
            evidence,
        };
    }

    if let Some(outcome) = python_intra_function_taint(rule, lang, source, node, captures, semantics) {
        let mut evidence = HashMap::new();
        match outcome {
            PythonTaintOutcome::Tainted(source_kind, framework) => {
                evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                evidence.insert("path_sensitivity_reason".into(), serde_json::json!("python_intra_function_taint"));
                evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                if let Some(framework) = framework {
                    evidence.insert("framework".into(), serde_json::json!(framework));
                }
                return PathSensitivity {
                    reachability: Some("reachable".into()),
                    evidence,
                };
            }
            PythonTaintOutcome::Guarded(reason) => {
                evidence.insert("path_sensitivity".into(), serde_json::json!("guarded"));
                evidence.insert("path_sensitivity_reason".into(), serde_json::json!(reason));
                return PathSensitivity {
                    reachability: Some("unknown".into()),
                    evidence,
                };
            }
            PythonTaintOutcome::NoSource => {
                evidence.insert("path_sensitivity".into(), serde_json::json!("no_source_detected"));
                evidence.insert("path_sensitivity_reason".into(), serde_json::json!("python_intra_function_no_source"));
                return PathSensitivity {
                    reachability: Some("unknown".into()),
                    evidence,
                };
            }
        }
    }

    if let Some((source_kind, framework)) = taint_reason(rule, lang, source, node, captures, semantics) {
        let mut evidence = HashMap::new();
        evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
        evidence.insert("source_kind".into(), serde_json::json!(source_kind));
        if let Some(framework) = framework {
            evidence.insert("framework".into(), serde_json::json!(framework));
        }
        return PathSensitivity {
            reachability: Some("reachable".into()),
            evidence,
        };
    }

    if requires_attacker_control(rule.id.as_str()) {
        let mut evidence = HashMap::new();
        evidence.insert("path_sensitivity".into(), serde_json::json!("no_source_detected"));
        return PathSensitivity {
            reachability: Some("unknown".into()),
            evidence,
        };
    }

    let mut evidence = HashMap::new();
    evidence.insert("path_sensitivity".into(), serde_json::json!("reachable"));
    PathSensitivity {
        reachability: Some("reachable".into()),
        evidence,
    }
}

fn dead_code_reason(source: &str, node: tree_sitter::Node<'_>) -> Option<String> {
    let mut current = node.parent();
    while let Some(parent) = current {
        match parent.kind() {
            "if_statement" => {
                let condition = parent.child_by_field_name("condition");
                let consequence = parent.child_by_field_name("consequence")
                    .or_else(|| parent.child_by_field_name("body"));
                if let (Some(cond), Some(body)) = (condition, consequence) {
                    if contains_node(body, node) && falsey_text(cond.utf8_text(source.as_bytes()).ok()?) {
                        return Some("dead_branch_false_condition".into());
                    }
                }
            }
            "while_statement" => {
                let condition = parent.child_by_field_name("condition");
                let body = parent.child_by_field_name("body")
                    .or_else(|| parent.child_by_field_name("consequence"));
                if let (Some(cond), Some(body)) = (condition, body) {
                    if contains_node(body, node) && falsey_text(cond.utf8_text(source.as_bytes()).ok()?) {
                        return Some("dead_loop_false_condition".into());
                    }
                }
            }
            _ => {}
        }
        current = parent.parent();
    }
    None
}

fn python_intra_function_taint(
    rule: &Rule,
    lang: Lang,
    source: &str,
    node: tree_sitter::Node<'_>,
    captures: &HashMap<String, String>,
    semantics: &FileSemantics,
) -> Option<PythonTaintOutcome> {
    if lang != Lang::Python || !requires_attacker_control(rule.id.as_str()) {
        return None;
    }

    let scope_prefix = python_scope_prefix(source, node)?;
    let assign_re = Regex::new(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$").unwrap();
    let mut tainted = HashMap::<String, String>::new();
    let mut sanitized = HashMap::<String, String>::new();

    for raw_line in scope_prefix.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some(caps) = assign_re.captures(line) else { continue };
        let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
        let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
        if ident.is_empty() || rhs.is_empty() {
            continue;
        }

        if let Some(source_kind) = python_direct_source_kind(rhs) {
            tainted.insert(ident.clone(), source_kind.to_string());
            sanitized.remove(&ident);
            continue;
        }

        if let Some(reason) = python_sanitizer_reason(rhs, &tainted) {
            tainted.remove(&ident);
            sanitized.insert(ident, reason);
            continue;
        }

        if let Some(source_kind) = taint_from_tokens(rhs, &tainted) {
            tainted.insert(ident.clone(), source_kind);
            sanitized.remove(&ident);
            continue;
        }

        tainted.remove(&ident);
        sanitized.remove(&ident);
    }

    let node_text = node.utf8_text(source.as_bytes()).ok()?.trim();
    let mut candidate_texts: Vec<&str> = vec![node_text];
    for key in ["concat", "call", "write", "arg"] {
        if let Some(value) = captures.get(key) {
            candidate_texts.push(value.as_str());
        }
    }

    for candidate in &candidate_texts {
        if let Some(reason) = python_sanitizer_reason(candidate, &tainted) {
            return Some(PythonTaintOutcome::Guarded(reason));
        }
        if let Some(reason) = identifier_reason(candidate, &sanitized) {
            return Some(PythonTaintOutcome::Guarded(reason));
        }
    }

    for candidate in &candidate_texts {
        if let Some(source_kind) = taint_from_tokens(candidate, &tainted) {
            return Some(PythonTaintOutcome::Tainted(
                source_kind.clone(),
                pick_framework(semantics, &source_kind),
            ));
        }
    }

    if candidate_texts.iter().any(|candidate| {
        contains_identifier(candidate, &tainted)
            || contains_identifier(candidate, &sanitized)
            || contains_nonliteral_python_identifier(candidate)
    }) {
        return Some(PythonTaintOutcome::NoSource);
    }

    None
}

fn python_scope_prefix(source: &str, node: tree_sitter::Node<'_>) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    let sink_row = node.start_position().row;
    if sink_row == 0 || sink_row as usize > lines.len() {
        return Some(String::new());
    }

    let sink_index = sink_row as usize;
    let sink_indent = leading_indent(lines.get(sink_index).copied().unwrap_or_default());
    let mut start_line = 0usize;

    for idx in (0..sink_index).rev() {
        let line = lines[idx];
        let trimmed = line.trim_start();
        let indent = leading_indent(line);
        if trimmed.starts_with("def ") && indent < sink_indent {
            start_line = idx + 1;
            break;
        }
    }

    Some(lines[start_line..sink_index].join("\n"))
}

fn leading_indent(line: &str) -> usize {
    line.chars().take_while(|c| c.is_whitespace()).count()
}

fn python_direct_source_kind(text: &str) -> Option<&'static str> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
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
    None
}

fn python_sanitizer_reason(text: &str, tainted: &HashMap<String, String>) -> Option<String> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let has_tainted_input = contains_identifier(&compact, tainted);
    if !has_tainted_input {
        return None;
    }
    if compact.contains("html.escape(") || compact.contains("django.utils.html.escape(") {
        return Some("escaped_input".into());
    }
    if compact.contains("markupsafe.escape(") || compact.contains("flask.escape(") {
        return Some("html_escaped".into());
    }
    if compact.contains("ast.literal_eval(") {
        return Some("literal_eval_guard".into());
    }
    None
}

fn taint_from_tokens(text: &str, tainted: &HashMap<String, String>) -> Option<String> {
    for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.')) {
        if let Some(kind) = tainted.get(token) {
            return Some(kind.clone());
        }
    }
    None
}

fn contains_identifier(text: &str, values: &HashMap<String, String>) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .any(|token| values.contains_key(token))
}

fn identifier_reason(text: &str, values: &HashMap<String, String>) -> Option<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .find_map(|token| values.get(token).cloned())
}

fn contains_nonliteral_python_identifier(text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
        .any(|token| {
            !token.is_empty()
                && token.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && !matches!(token, "eval" | "exec" | "request" | "args" | "form" | "GET" | "POST" | "input" | "html" | "django" | "utils" | "escape" | "literal_eval")
        })
}

fn guarded_reason(
    rule: &Rule,
    lang: Lang,
    source: &str,
    node: tree_sitter::Node<'_>,
    captures: &HashMap<String, String>,
) -> Option<String> {
    let text = node.utf8_text(source.as_bytes()).ok()?.trim();
    match rule.id.as_str() {
        "CBR-JS-XSS-INNER-HTML" | "CBR-JS-DOCUMENT-WRITE" if matches!(lang, Lang::Javascript | Lang::Typescript) => {
            if text.contains("DOMPurify.sanitize(") {
                return Some("dompurify_sanitized".into());
            }
            if text.contains("escapeHtml(") || text.contains("he.encode(") {
                return Some("html_escaped".into());
            }
        }
        "CBR-PY-CODE-EVAL" if lang == Lang::Python => {
            if text.contains("ast.literal_eval(") {
                return Some("literal_eval_guard".into());
            }
            if text.contains("html.escape(") || text.contains("django.utils.html.escape(") {
                return Some("escaped_input".into());
            }
        }
        "CBR-PY-SQLI-STRING-CONCAT" if lang == Lang::Python => {
            if text.contains("format_html(") || text.contains("conditional_escape(") {
                return Some("html_safe_render_builder".into());
            }
        }
        _ if lang == Lang::Java => {
            if text.contains("HtmlUtils.htmlEscape(") || text.contains("ESAPI.encoder().encodeForHTML(") {
                return Some("java_html_encoded".into());
            }
        }
        _ if lang == Lang::Ruby => {
            if text.contains("sanitize(") || text.contains("strip_tags(") {
                return Some("rails_sanitized".into());
            }
            if text.contains("html_escape(") || text.contains("h(") {
                return Some("rails_html_encoded".into());
            }
        }
        "CBR-JS-CODE-EVAL" if matches!(lang, Lang::Javascript | Lang::Typescript) => {
            if call_uses_only_literal_payload(text) {
                return Some("constant_string_payload".into());
            }
        }
        "CBR-PY-CODE-EVAL" | "CBR-PY-PICKLE-LOADS" if lang == Lang::Python => {
            if call_uses_only_literal_payload(text) {
                return Some("constant_literal_payload".into());
            }
        }
        "CBR-PY-SQLI-STRING-CONCAT" if lang == Lang::Python => {
            if captures.get("concat").is_some_and(|s| concat_is_literal_only(s)) {
                return Some("constant_query_concatenation".into());
            }
        }
        _ => {}
    }
    None
}

fn taint_reason(
    rule: &Rule,
    lang: Lang,
    source: &str,
    node: tree_sitter::Node<'_>,
    captures: &HashMap<String, String>,
    semantics: &FileSemantics,
) -> Option<(String, Option<String>)> {
    let text = node.utf8_text(source.as_bytes()).ok()?.trim();
    if !requires_attacker_control(rule.id.as_str()) {
        return None;
    }

    if let Some(kind) = direct_source_kind(lang, text) {
        return Some((kind.to_string(), pick_framework(semantics, &kind)));
    }

    let mut candidate_texts: Vec<&str> = vec![text];
    for key in ["concat", "call", "write", "arg"] {
        if let Some(value) = captures.get(key) {
            candidate_texts.push(value.as_str());
        }
    }

    for candidate in candidate_texts {
        for token in candidate.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '$')) {
            if let Some(kind) = semantics.tainted_identifiers.get(token) {
                return Some((kind.clone(), pick_framework(semantics, kind)));
            }
        }
    }
    None
}

fn direct_source_kind(lang: Lang, text: &str) -> Option<&'static str> {
    match lang {
        Lang::Python => {
            if text.contains("request.args.get(") || text.contains("flask.request.args.get(") {
                return Some("flask.request.args");
            }
            if text.contains("request.form.get(") || text.contains("flask.request.form.get(") {
                return Some("flask.request.form");
            }
            if text.contains("request.GET.get(") || text.contains("request.GET[") {
                return Some("django.request.GET");
            }
            if text.contains("request.POST.get(") || text.contains("request.POST[") {
                return Some("django.request.POST");
            }
            if text.contains("input(") {
                return Some("python.input");
            }
        }
        Lang::Javascript | Lang::Typescript => {
            if text.contains("req.query.") || text.contains("request.query.") {
                return Some("express.req.query");
            }
            if text.contains("req.params.") || text.contains("request.params.") {
                return Some("express.req.params");
            }
            if text.contains("req.body.") || text.contains("request.body.") {
                return Some("express.req.body");
            }
        }
        Lang::Csharp => {
            if text.contains("Request.Query[") || text.contains("Request.Query.Get(") {
                return Some("aspnet.request_query");
            }
            if text.contains("Request.Form[") || text.contains("Request.Form.Get(") {
                return Some("aspnet.request_form");
            }
            if text.contains("Request.Headers[") {
                return Some("aspnet.request_headers");
            }
            if text.contains("Request.Cookies[") {
                return Some("aspnet.request_cookies");
            }
        }
        Lang::Java => {
            if text.contains("request.getParameter(") || text.contains("request.getQueryString(") {
                return Some("spring.http_request_parameter");
            }
        }
        Lang::Ruby => {
            if text.contains("params[") || text.contains("params.") {
                return Some("rails.params");
            }
        }
        _ => {}
    }
    None
}

fn pick_framework(semantics: &FileSemantics, source_kind: &str) -> Option<String> {
    if source_kind.starts_with("django.") {
        return Some("django".into());
    }
    if source_kind.starts_with("flask.") {
        return Some("flask".into());
    }
    if source_kind.starts_with("express.") {
        return Some("express".into());
    }
    semantics.frameworks.iter().next().cloned()
}

fn pick_framework_from_rule(rule: &Rule, semantics: &FileSemantics) -> Option<String> {
    match rule.id.as_str() {
        "CBR-JS-XSS-INNER-HTML" | "CBR-JS-DOCUMENT-WRITE" | "CBR-JS-CODE-EVAL" => {
            if semantics.frameworks.contains("react") {
                return Some("react".into());
            }
            if semantics.frameworks.contains("express") {
                return Some("express".into());
            }
        }
        "CBR-PY-CODE-EVAL" | "CBR-PY-PICKLE-LOADS" | "CBR-PY-SQLI-STRING-CONCAT" => {
            if semantics.frameworks.contains("django") {
                return Some("django".into());
            }
            if semantics.frameworks.contains("flask") {
                return Some("flask".into());
            }
        }
        "CBR-CSHA-SQL_INJECTION" | "CBR-CSHA-XSS_HTML_RAW" | "CBR-CSHA-OPEN_REDIRECT" => {
            if semantics.frameworks.contains("aspnet") {
                return Some("aspnet".into());
            }
        }
        _ => {}
    }
    None
}

fn requires_attacker_control(rule_id: &str) -> bool {
    matches!(
        rule_id,
        "CBR-PY-CODE-EVAL"
            | "CBR-PY-PICKLE-LOADS"
            | "CBR-PY-SQLI-STRING-CONCAT"
            | "CBR-JS-CODE-EVAL"
            | "CBR-JS-XSS-INNER-HTML"
            | "CBR-JS-DOCUMENT-WRITE"
            | "CBR-CSHA-SQL_INJECTION"
            | "CBR-CSHA-XSS_HTML_RAW"
            | "CBR-CSHA-COMMAND_INJECTION"
            | "CBR-CSHA-OPEN_REDIRECT"
            | "CBR-CSHA-PATH_TRAVERSAL"
            | "CBR-GO-SQL_INJECTION"
            | "CBR-GO-COMMAND_INJECTION"
            | "CBR-JS-PROTOTYPE_POLLUTION"
            | "CBR-JS-NODE_COMMAND_INJECTION"
            | "CBR-JS-INSECURE_DOM_XSS"
            | "CBR-PY-SUBPROCESS_SHELL_TRUE"
    )
}

fn contains_node(container: tree_sitter::Node<'_>, child: tree_sitter::Node<'_>) -> bool {
    child.start_byte() >= container.start_byte() && child.end_byte() <= container.end_byte()
}

fn falsey_text(text: &str) -> bool {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    matches!(compact.as_str(), "False" | "false" | "0" | "None" | "null" | "undefined")
}

fn call_uses_only_literal_payload(text: &str) -> bool {
    let Some(open) = text.find('(') else { return false };
    let Some(close) = text.rfind(')') else { return false };
    if close <= open + 1 {
        return false;
    }
    let first_arg = text[open + 1..close].split(',').next().unwrap_or("").trim();
    is_literal_like(first_arg)
}

fn concat_is_literal_only(text: &str) -> bool {
    text.split('+').map(str::trim).all(is_literal_like)
}

fn is_literal_like(text: &str) -> bool {
    let t = text.trim();
    if t.is_empty() {
        return false;
    }
    (t.starts_with('"') && t.ends_with('"'))
        || (t.starts_with('\'') && t.ends_with('\''))
        || (t.starts_with("b\"") && t.ends_with('"'))
        || (t.starts_with("b'") && t.ends_with('\''))
        || matches!(t, "True" | "False" | "None" | "null" | "undefined")
        || t.parse::<f64>().is_ok()
}

fn select_primary_capture<'a>(
    query: &Query,
    captures: &'a [tree_sitter::QueryCapture<'a>],
) -> Option<&'a tree_sitter::QueryCapture<'a>> {
    const PREFERRED: &[&str] = &["match", "target", "sink", "vuln", "issue", "danger"];

    for preferred in PREFERRED {
        if let Some(capture) = captures.iter().find(|capture| {
            query.capture_names()[capture.index as usize] == *preferred
        }) {
            return Some(capture);
        }
    }

    captures.first()
}
