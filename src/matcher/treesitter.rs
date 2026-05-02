//! Tree-sitter matcher. One Parser per call — tree-sitter Parsers aren't
//! Sync-safe, so we don't try to share them across threads.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};
use tree_sitter::{Parser, Query, QueryCursor, Tree};

use crate::{finding::Finding, lang::Lang, rule::Rule};

use super::{
    dsl::{metavariable_comparisons_match, metavariable_types_match, CaptureMeta},
    semantics::FileSemantics,
};

#[derive(Debug, Clone)]
struct PathSensitivity {
    reachability: Option<String>,
    evidence: HashMap<String, serde_json::Value>,
}

enum IntraFileTaintOutcome {
    Tainted(String, Option<String>, String),
    Guarded(String, String),
    NoSource(String),
}

pub fn parse(lang: Lang, source: &str) -> Result<Tree> {
    let mut parser = Parser::new();
    let grammar = lang
        .tree_sitter()
        .with_context(|| format!("no tree-sitter grammar for {lang}"))?;
    parser
        .set_language(&grammar)
        .with_context(|| format!("setting tree-sitter language {lang}"))?;
    parser
        .parse(source, None)
        .context("tree-sitter parse returned None")
}

pub fn match_rule(
    rule: &Rule,
    lang: Lang,
    path: &Path,
    source: &str,
    tree: &Tree,
    semantics: &FileSemantics,
) -> Vec<Finding> {
    let Some(q_str) = rule.query.as_deref() else {
        return Vec::new();
    };

    let Some(grammar) = lang.tree_sitter() else {
        return Vec::new();
    };
    let query = match Query::new(&grammar, q_str) {
        Ok(q) => q,
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
        let Some(cap) = select_primary_capture(&query, &m.captures) else {
            continue;
        };
        let node = cap.node;
        let start = node.start_position();
        let end = node.end_position();
        let snippet = node
            .utf8_text(bytes)
            .unwrap_or("")
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let mut evidence = HashMap::new();
        evidence.insert("matcher_kind".into(), serde_json::json!("tree_sitter"));
        let mut captures = HashMap::new();
        for capture in m.captures {
            let name = query.capture_names()[capture.index as usize].to_string();
            if let Ok(text) = capture.node.utf8_text(bytes) {
                captures
                    .entry(name.clone())
                    .or_insert_with(|| text.to_string());
                evidence
                    .entry(name)
                    .or_insert_with(|| serde_json::json!(text));
            }
        }

        if !semantic_guard(rule, semantics, &captures) {
            continue;
        }
        if !dsl_pattern_filters_match(rule, source, node, &query, &m.captures, &captures) {
            continue;
        }

        let path_sensitivity =
            analyze_path_sensitivity(rule, lang, source, node, &captures, semantics);
        evidence.extend(path_sensitivity.evidence);
        evidence.extend(base_semantic_evidence(rule, semantics));

        out.push(Finding {
            rule_id: rule.id.clone(),
            title: rule.title.clone(),
            severity: rule.severity,
            message: rule.message.clone(),
            file: PathBuf::from(path),
            line: start.row + 1,
            column: start.column + 1,
            end_line: end.row + 1,
            end_column: end.column + 1,
            fingerprint: String::new(),
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            snippet,
            fix_recipe: rule.fix_recipe.clone(),
            fix: rule.fix.clone(),
            cwe: rule.cwe.clone(),
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
            let Some(object) = captures.get("obj") else {
                return false;
            };
            let object = object.trim();
            if object == "pickle" && semantics.imported_modules.contains("pickle") {
                return true;
            }
            if semantics.alias_to_module.get(object).map(String::as_str) == Some("pickle") {
                return true;
            }
            semantics
                .imported_symbols
                .get(object)
                .map(String::as_str)
                .is_some_and(|sym| sym == "pickle.loads" || sym == "pickle.load")
        }
        "CBR-PY-SQLI-STRING-CONCAT" => {
            let Some(object) = captures.get("obj") else {
                return true;
            };
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
            let Some(object) = captures.get("obj") else {
                return true;
            };
            let object = object.trim();
            if object == "document" || object == "el" || object == "node" || object == "element" {
                return true;
            }
            if let Some(module) = semantics.js_namespace_imports.get(object) {
                return module != "react";
            }
            true
        }
        "CBR-CSHA-SQL_INJECTION" => {
            let Some(object) = captures.get("obj") else {
                return false;
            };
            csharp_receiver_is_db_command(object, semantics)
        }
        _ => true,
    }
}

fn dsl_pattern_filters_match(
    rule: &Rule,
    source: &str,
    node: tree_sitter::Node<'_>,
    query: &Query,
    raw_captures: &[tree_sitter::QueryCapture<'_>],
    captures: &HashMap<String, String>,
) -> bool {
    let node_text = node.utf8_text(source.as_bytes()).ok().unwrap_or_default();
    let mut candidate_texts: Vec<&str> = vec![node_text];
    for value in captures.values() {
        if !candidate_texts.iter().any(|seen| *seen == value.as_str()) {
            candidate_texts.push(value.as_str());
        }
    }

    let positive_patterns = tree_positive_patterns(rule);
    if !positive_patterns.is_empty() {
        let compiled: Vec<Regex> = positive_patterns
            .into_iter()
            .filter_map(compile_tree_filter_regex)
            .collect();
        if compiled.is_empty() {
            return false;
        }
        if !compiled
            .iter()
            .all(|re| candidate_texts.iter().any(|text| re.is_match(text)))
        {
            return false;
        }
    }

    let either_patterns = tree_either_patterns(rule);
    if !either_patterns.is_empty() {
        let compiled: Vec<Regex> = either_patterns
            .into_iter()
            .filter_map(compile_tree_filter_regex)
            .collect();
        if compiled.is_empty() {
            return false;
        }
        if !compiled
            .iter()
            .any(|re| candidate_texts.iter().any(|text| re.is_match(text)))
        {
            return false;
        }
    }

    let either_groups = tree_either_groups(rule);
    if !either_groups.is_empty() {
        let compiled_groups: Vec<Vec<Regex>> = either_groups
            .into_iter()
            .map(|group| {
                group
                    .into_iter()
                    .filter_map(compile_tree_filter_regex)
                    .collect::<Vec<_>>()
            })
            .filter(|group| !group.is_empty())
            .collect();
        if compiled_groups.is_empty() {
            return false;
        }
        if !compiled_groups.iter().any(|group| {
            group
                .iter()
                .all(|re| candidate_texts.iter().any(|text| re.is_match(text)))
        }) {
            return false;
        }
    }

    if let Some(pattern_not) = rule.pattern_not.as_deref() {
        if let Some(re) = compile_tree_filter_regex(pattern_not) {
            if re.is_match(node_text) {
                return false;
            }
            if captures.values().any(|value| re.is_match(value)) {
                return false;
            }
        }
    }

    if !rule.pattern_not_inside.is_empty() {
        let not_inside: Vec<Regex> = rule
            .pattern_not_inside
            .iter()
            .filter_map(|pattern| compile_tree_filter_regex(pattern))
            .collect();
        if not_inside.is_empty() {
            return false;
        }
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.parent().is_none() {
                current = parent.parent();
                continue;
            }
            if let Ok(text) = parent.utf8_text(source.as_bytes()) {
                if not_inside.iter().any(|re| re.is_match(text)) {
                    return false;
                }
            }
            current = parent.parent();
        }
    }

    let capture_meta = build_capture_meta(source, query, raw_captures, node_text, captures);

    if let Some(pattern_inside) = rule.pattern_inside.as_deref() {
        let Some(re) = compile_tree_filter_regex(pattern_inside) else {
            return false;
        };
        let mut current = node.parent();
        while let Some(parent) = current {
            if parent.parent().is_none() {
                current = parent.parent();
                continue;
            }
            if let Ok(text) = parent.utf8_text(source.as_bytes()) {
                if re.is_match(text) {
                    return true;
                }
            }
            current = parent.parent();
        }
        return false;
    }

    if !metavariable_comparisons_match(
        &rule.metavariable_comparisons,
        rule.metavariable_comparison.as_deref(),
        &capture_meta,
    ) {
        return false;
    }

    if !metavariable_types_match(&rule.metavariable_types, &capture_meta) {
        return false;
    }

    true
}

fn tree_positive_patterns(rule: &Rule) -> Vec<&str> {
    if !rule.patterns.is_empty() {
        return rule.patterns.iter().map(String::as_str).collect();
    }
    rule.pattern
        .as_deref()
        .map(|pat| vec![pat.trim()])
        .unwrap_or_default()
}

fn tree_either_patterns(rule: &Rule) -> Vec<&str> {
    rule.pattern_either.iter().map(String::as_str).collect()
}

fn tree_either_groups(rule: &Rule) -> Vec<Vec<&str>> {
    rule.pattern_either_groups
        .iter()
        .map(|group| group.iter().map(String::as_str).collect())
        .collect()
}

fn build_capture_meta<'a>(
    source: &'a str,
    query: &Query,
    raw_captures: &[tree_sitter::QueryCapture<'a>],
    node_text: &'a str,
    captures: &'a HashMap<String, String>,
) -> HashMap<String, CaptureMeta<'a>> {
    let mut meta = HashMap::new();
    meta.insert(
        "MATCH".into(),
        CaptureMeta {
            text: node_text,
            kind: Some("match"),
        },
    );
    for capture in raw_captures {
        let name = query.capture_names()[capture.index as usize].to_string();
        let text = capture.node.utf8_text(source.as_bytes()).ok().unwrap_or("");
        meta.entry(name).or_insert(CaptureMeta {
            text,
            kind: Some(capture.node.kind()),
        });
    }
    for (name, value) in captures {
        meta.entry(name.clone()).or_insert(CaptureMeta {
            text: value.as_str(),
            kind: None,
        });
    }
    meta
}

fn compile_tree_filter_regex(pattern: &str) -> Option<Regex> {
    let converted = super::regex::semgrep_to_regex(pattern.trim());
    if converted.trim().is_empty() {
        return None;
    }
    RegexBuilder::new(&converted)
        .dot_matches_new_line(true)
        .multi_line(true)
        .build()
        .ok()
}

fn csharp_receiver_is_db_command(object: &str, semantics: &FileSemantics) -> bool {
    let object = object.trim();
    if object.is_empty() {
        return false;
    }

    if let Some(ty) = semantics.variable_types.get(object) {
        return csharp_is_db_command_type(ty);
    }

    let compact: String = object.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("newSqlCommand(")
        || compact.contains("newMicrosoft.Data.SqlClient.SqlCommand(")
        || compact.contains("newSystem.Data.SqlClient.SqlCommand(")
        || compact.contains("newNpgsqlCommand(")
        || compact.contains("newMySqlCommand(")
        || compact.contains("newOracleCommand(")
        || compact.contains("newSqliteCommand(")
        || compact.contains("newSQLiteCommand(")
        || compact.contains(".CreateCommand(")
    {
        return true;
    }

    false
}

fn csharp_is_db_command_type(ty: &str) -> bool {
    matches!(
        ty.rsplit('.').next().unwrap_or(ty).trim(),
        "SqlCommand"
            | "DbCommand"
            | "SqliteCommand"
            | "SQLiteCommand"
            | "NpgsqlCommand"
            | "MySqlCommand"
            | "OracleCommand"
    )
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

    if let Some(outcome) = intra_file_taint(rule, lang, source, node, captures, semantics) {
        let mut evidence = HashMap::new();
        match outcome {
            IntraFileTaintOutcome::Tainted(source_kind, framework, reason) => {
                evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                evidence.insert("path_sensitivity_reason".into(), serde_json::json!(reason));
                evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                if let Some(framework) = framework {
                    evidence.insert("framework".into(), serde_json::json!(framework));
                }
                return PathSensitivity {
                    reachability: Some("reachable".into()),
                    evidence,
                };
            }
            IntraFileTaintOutcome::Guarded(reason, detail) => {
                evidence.insert("path_sensitivity".into(), serde_json::json!("guarded"));
                evidence.insert("path_sensitivity_reason".into(), serde_json::json!(reason));
                evidence.insert("sanitizer_kind".into(), serde_json::json!(detail));
                return PathSensitivity {
                    reachability: Some("unknown".into()),
                    evidence,
                };
            }
            IntraFileTaintOutcome::NoSource(reason) => {
                evidence.insert(
                    "path_sensitivity".into(),
                    serde_json::json!("no_source_detected"),
                );
                evidence.insert("path_sensitivity_reason".into(), serde_json::json!(reason));
                return PathSensitivity {
                    reachability: Some("unknown".into()),
                    evidence,
                };
            }
        }
    }

    if let Some((source_kind, framework)) =
        taint_reason(rule, lang, source, node, captures, semantics)
    {
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
        evidence.insert(
            "path_sensitivity".into(),
            serde_json::json!("no_source_detected"),
        );
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
                let consequence = parent
                    .child_by_field_name("consequence")
                    .or_else(|| parent.child_by_field_name("body"));
                if let (Some(cond), Some(body)) = (condition, consequence) {
                    if contains_node(body, node)
                        && falsey_text(cond.utf8_text(source.as_bytes()).ok()?)
                    {
                        return Some("dead_branch_false_condition".into());
                    }
                }
            }
            "while_statement" => {
                let condition = parent.child_by_field_name("condition");
                let body = parent
                    .child_by_field_name("body")
                    .or_else(|| parent.child_by_field_name("consequence"));
                if let (Some(cond), Some(body)) = (condition, body) {
                    if contains_node(body, node)
                        && falsey_text(cond.utf8_text(source.as_bytes()).ok()?)
                    {
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

fn intra_file_taint(
    rule: &Rule,
    lang: Lang,
    source: &str,
    node: tree_sitter::Node<'_>,
    captures: &HashMap<String, String>,
    semantics: &FileSemantics,
) -> Option<IntraFileTaintOutcome> {
    if !requires_attacker_control(rule.id.as_str()) {
        return None;
    }

    let scope_prefix = scope_prefix(lang, source, node)?;
    let assign_re = assignment_regex(lang)?;
    let mut tainted = semantics.tainted_identifiers.clone();
    let mut sanitized = semantics.sanitized_identifiers.clone();

    for raw_line in scope_prefix.lines() {
        let line = strip_comments(lang, raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let Some(caps) = assign_re.captures(line) else {
            continue;
        };
        let ident = normalize_access_path(caps.get(1).map(|m| m.as_str()).unwrap_or(""));
        let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
        if ident.is_empty() || rhs.is_empty() {
            continue;
        }

        let uses_call_summary = semantics
            .call_assignments
            .iter()
            .any(|call| call.ident == ident);
        if uses_call_summary && rhs.contains('(') && rhs.contains(')') {
            if let Some(reason) = semantics.sanitized_identifiers.get(&ident).cloned() {
                tainted.remove(&ident);
                sanitized.insert(ident, reason);
                continue;
            }
            if let Some(source_kind) = semantics.tainted_identifiers.get(&ident).cloned() {
                tainted.insert(ident.clone(), source_kind);
                sanitized.remove(&ident);
                continue;
            }
        }

        if let Some(reason) = sanitizer_kind(lang, rhs, &tainted) {
            tainted.remove(&ident);
            sanitized.insert(ident, reason);
            continue;
        }

        if let Some(source_kind) = direct_source_kind(lang, rhs) {
            tainted.insert(ident.clone(), source_kind.to_string());
            sanitized.remove(&ident);
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
    for value in captures.values() {
        if !candidate_texts.iter().any(|seen| *seen == value.as_str()) {
            candidate_texts.push(value.as_str());
        }
    }

    for candidate in &candidate_texts {
        if let Some(reason) = sanitizer_kind(lang, candidate, &tainted) {
            return Some(IntraFileTaintOutcome::Guarded(
                guarded_reason_label(lang),
                reason,
            ));
        }
        if let Some(reason) = identifier_reason(candidate, &sanitized) {
            return Some(IntraFileTaintOutcome::Guarded(
                guarded_reason_label(lang),
                reason,
            ));
        }
    }

    for candidate in &candidate_texts {
        if let Some(source_kind) = direct_source_kind(lang, candidate) {
            return Some(IntraFileTaintOutcome::Tainted(
                source_kind.to_string(),
                pick_framework(semantics, source_kind),
                intra_file_reason(lang),
            ));
        }
        if let Some(source_kind) = taint_from_tokens(candidate, &tainted) {
            return Some(IntraFileTaintOutcome::Tainted(
                source_kind.clone(),
                pick_framework(semantics, &source_kind),
                intra_file_reason(lang),
            ));
        }
    }

    if candidate_texts.iter().any(|candidate| {
        contains_identifier(candidate, &tainted)
            || contains_identifier(candidate, &sanitized)
            || contains_nonliteral_identifier(lang, candidate)
    }) {
        return Some(IntraFileTaintOutcome::NoSource(no_source_reason(lang)));
    }

    None
}

fn scope_prefix(lang: Lang, source: &str, node: tree_sitter::Node<'_>) -> Option<String> {
    if lang == Lang::Python {
        return python_scope_prefix(source, node);
    }
    block_scope_prefix(source, node)
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

fn block_scope_prefix(source: &str, node: tree_sitter::Node<'_>) -> Option<String> {
    let mut current = Some(node);
    while let Some(cursor) = current {
        let kind = cursor.kind();
        if matches!(
            kind,
            "statement_block" | "block" | "body_statement" | "do_block"
        ) {
            let start = cursor.start_byte().min(node.start_byte());
            let end = node.start_byte().min(source.len());
            return source.get(start..end).map(str::to_string);
        }
        current = cursor.parent();
    }
    Some(String::new())
}

fn leading_indent(line: &str) -> usize {
    line.chars().take_while(|c| c.is_whitespace()).count()
}

fn sanitizer_kind(lang: Lang, text: &str, tainted: &HashMap<String, String>) -> Option<String> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let has_tainted_input =
        contains_identifier(&compact, tainted) || direct_source_kind(lang, text).is_some();
    if !has_tainted_input {
        return None;
    }
    match lang {
        Lang::Python => {
            if compact.contains("html.escape(") || compact.contains("django.utils.html.escape(") {
                return Some("escaped_input".into());
            }
            if compact.contains("markupsafe.escape(") || compact.contains("flask.escape(") {
                return Some("html_escaped".into());
            }
            if compact.contains("ast.literal_eval(") {
                return Some("literal_eval_guard".into());
            }
        }
        Lang::Javascript | Lang::Typescript => {
            if compact.contains("DOMPurify.sanitize(") {
                return Some("dompurify_sanitized".into());
            }
            if compact.contains("escapeHtml(") || compact.contains("he.encode(") {
                return Some("html_escaped".into());
            }
        }
        Lang::Csharp => {
            if compact.contains("HttpUtility.HtmlEncode(")
                || compact.contains("WebUtility.HtmlEncode(")
                || compact.contains("HtmlEncoder.Default.Encode(")
                || compact.contains("AntiXssEncoder.HtmlEncode(")
            {
                return Some("aspnet.html_encoded".into());
            }
            if compact.contains("Uri.EscapeDataString(")
                || compact.contains("HttpUtility.UrlEncode(")
                || compact.contains("WebUtility.UrlEncode(")
            {
                return Some("aspnet.url_encoded".into());
            }
        }
        Lang::Java => {
            if compact.contains("HtmlUtils.htmlEscape(")
                || compact.contains("ESAPI.encoder().encodeForHTML(")
            {
                return Some("java_html_encoded".into());
            }
            if compact.contains("UriUtils.encode(") || compact.contains("URLEncoder.encode(") {
                return Some("java_url_encoded".into());
            }
        }
        Lang::Ruby => {
            if compact.contains("sanitize(") {
                return Some("rails.sanitize".into());
            }
            if compact.contains("strip_tags(") {
                return Some("rails.strip_tags".into());
            }
            if compact.contains("ERB::Util.html_escape(") || compact.contains("html_escape(") {
                return Some("rails.html_escape".into());
            }
        }
        Lang::Go => {
            if compact.contains("template.HTMLEscapeString(") {
                return Some("go.html_escape".into());
            }
            if compact.contains("url.QueryEscape(") || compact.contains("template.URLQueryEscaper(")
            {
                return Some("go.url_escape".into());
            }
        }
        _ => {}
    }
    None
}

fn taint_from_tokens(text: &str, tainted: &HashMap<String, String>) -> Option<String> {
    for token in semantic_candidates(text) {
        for candidate in hierarchical_path_candidates(&token) {
            if let Some(kind) = tainted.get(&candidate) {
                return Some(kind.clone());
            }
        }
    }
    None
}

fn contains_identifier(text: &str, values: &HashMap<String, String>) -> bool {
    semantic_candidates(text).into_iter().any(|token| {
        hierarchical_path_candidates(&token)
            .into_iter()
            .any(|candidate| values.contains_key(&candidate))
    })
}

fn identifier_reason(text: &str, values: &HashMap<String, String>) -> Option<String> {
    for token in semantic_candidates(text) {
        for candidate in hierarchical_path_candidates(&token) {
            if let Some(reason) = values.get(&candidate) {
                return Some(reason.clone());
            }
        }
    }
    None
}

fn contains_nonliteral_identifier(lang: Lang, text: &str) -> bool {
    semantic_candidates(text).into_iter().any(|token| {
        !token.is_empty()
            && token
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && !is_ignored_identifier(lang, &token)
    })
}

fn normalize_access_path(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '[' if i + 2 < chars.len() && (chars[i + 1] == '"' || chars[i + 1] == '\'') => {
                let quote = chars[i + 1];
                i += 2;
                let start = i;
                while i < chars.len() && chars[i] != quote {
                    i += 1;
                }
                if i < chars.len() {
                    let key: String = chars[start..i].iter().collect();
                    if !out.ends_with('.') && !out.is_empty() {
                        out.push('.');
                    }
                    out.push_str(&key);
                    i += 1;
                    if i < chars.len() && chars[i] == ']' {
                        i += 1;
                    }
                }
            }
            '[' if i + 1 < chars.len() => {
                i += 1;
                let start = i;
                while i < chars.len() && chars[i] != ']' {
                    i += 1;
                }
                let key: String = chars[start..i].iter().collect();
                if !key.is_empty() {
                    if !out.ends_with('.') && !out.is_empty() {
                        out.push('.');
                    }
                    out.push_str(&key);
                }
                if i < chars.len() && chars[i] == ']' {
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    while out.contains("..") {
        out = out.replace("..", ".");
    }
    out.trim_matches('.').to_string()
}

fn semantic_candidates(text: &str) -> Vec<String> {
    let normalized = normalize_access_path(text);
    normalized
        .split(|c: char| {
            !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' || c == '$')
        })
        .filter(|token| !token.is_empty())
        .map(str::to_string)
        .collect()
}

fn hierarchical_path_candidates(token: &str) -> Vec<String> {
    let normalized = normalize_access_path(token);
    if normalized.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut current = normalized.as_str();
    loop {
        out.push(current.to_string());
        let Some((parent, _)) = current.rsplit_once('.') else {
            break;
        };
        current = parent;
    }
    out
}

fn is_ignored_identifier(lang: Lang, token: &str) -> bool {
    match lang {
        Lang::Python => matches!(
            token,
            "eval"
                | "exec"
                | "request"
                | "args"
                | "form"
                | "GET"
                | "POST"
                | "input"
                | "html"
                | "django"
                | "utils"
                | "escape"
                | "literal_eval"
        ),
        Lang::Javascript | Lang::Typescript => matches!(
            token,
            "eval"
                | "req"
                | "request"
                | "query"
                | "params"
                | "body"
                | "setTimeout"
                | "setInterval"
                | "DOMPurify"
                | "sanitize"
                | "escapeHtml"
                | "he"
                | "encode"
                | "innerHTML"
                | "outerHTML"
                | "document"
                | "write"
        ),
        Lang::Csharp => matches!(
            token,
            "Request"
                | "Query"
                | "Form"
                | "Headers"
                | "Cookies"
                | "Html"
                | "Raw"
                | "Process"
                | "Start"
                | "HttpUtility"
                | "WebUtility"
                | "HtmlEncode"
                | "UrlEncode"
                | "HtmlEncoder"
                | "AntiXssEncoder"
                | "Uri"
                | "EscapeDataString"
        ),
        Lang::Java => matches!(
            token,
            "request"
                | "getParameter"
                | "getQueryString"
                | "HtmlUtils"
                | "htmlEscape"
                | "ESAPI"
                | "encodeForHTML"
                | "UriUtils"
                | "encode"
                | "URLEncoder"
        ),
        Lang::Ruby => matches!(
            token,
            "params" | "raw" | "sanitize" | "strip_tags" | "html_escape" | "ERB" | "Util"
        ),
        Lang::Go => matches!(
            token,
            "Query"
                | "Param"
                | "FormValue"
                | "HTMLEscapeString"
                | "QueryEscape"
                | "template"
                | "url"
        ),
        Lang::Rust => matches!(
            token,
            "std" | "env" | "args" | "args_os" | "var" | "var_os" | "nth" | "next" | "unwrap"
        ),
        _ => false,
    }
}

fn assignment_regex(lang: Lang) -> Option<Regex> {
    match lang {
        Lang::Python => Some(Regex::new(r#"^\s*([A-Za-z_][A-Za-z0-9_]*(?:(?:\.[A-Za-z_][A-Za-z0-9_]*)|\[(?:"[^"]+"|'[^']+'|\d+)\])*)\s*=\s*(.+?)\s*$"#).unwrap()),
        Lang::Javascript | Lang::Typescript => Some(Regex::new(r#"^\s*(?:const|let|var)?\s*([A-Za-z_$][A-Za-z0-9_$]*(?:(?:\.[A-Za-z_$][A-Za-z0-9_$]*)|\[(?:"[^"]+"|'[^']+'|\d+)\])*)\s*=\s*(.+?)\s*;?\s*$"#).unwrap()),
        Lang::Csharp | Lang::Java => Some(Regex::new(r#"^\s*(?:[A-Za-z_][A-Za-z0-9_<>\[\]\.?]*\s+)?([A-Za-z_][A-Za-z0-9_]*(?:(?:\.[A-Za-z_][A-Za-z0-9_]*)|\[(?:"[^"]+"|'[^']+'|\d+)\])*)\s*=\s*(.+?)\s*;?\s*$"#).unwrap()),
        Lang::Ruby => Some(Regex::new(r#"^\s*([A-Za-z_][A-Za-z0-9_]*(?:(?:\.[A-Za-z_][A-Za-z0-9_]*)|\[(?:"[^"]+"|'[^']+'|\d+)\])*)\s*=\s*(.+?)\s*$"#).unwrap()),
        Lang::Go => Some(Regex::new(r#"^\s*([A-Za-z_][A-Za-z0-9_]*(?:(?:\.[A-Za-z_][A-Za-z0-9_]*)|\[(?:"[^"]+"|'[^']+'|\d+)\])*)\s*(?::=|=)\s*(.+?)\s*$"#).unwrap()),
        Lang::Rust => Some(Regex::new(r#"^\s*(?:let\s+(?:mut\s+)?)?([A-Za-z_][A-Za-z0-9_]*(?:(?:\.[A-Za-z_][A-Za-z0-9_]*)|\[(?:"[^"]+"|'[^']+'|\d+)\])*)\s*(?::[^=]+)?=\s*(.+?)\s*;?\s*$"#).unwrap()),
        _ => None,
    }
}

fn strip_comments(lang: Lang, raw_line: &str) -> &str {
    match lang {
        Lang::Python | Lang::Ruby => raw_line.split('#').next().unwrap_or(""),
        _ => raw_line.split("//").next().unwrap_or(""),
    }
}

fn intra_file_reason(lang: Lang) -> String {
    match lang {
        Lang::Python => "python_intra_function_taint",
        Lang::Javascript | Lang::Typescript => "javascript_intra_function_taint",
        Lang::Csharp => "csharp_intra_function_taint",
        Lang::Java => "java_intra_function_taint",
        Lang::Ruby => "ruby_intra_function_taint",
        Lang::Go => "go_intra_function_taint",
        Lang::Rust => "rust_intra_function_taint",
        _ => "intra_file_taint",
    }
    .into()
}

fn no_source_reason(lang: Lang) -> String {
    match lang {
        Lang::Python => "python_intra_function_no_source",
        Lang::Javascript | Lang::Typescript => "javascript_intra_function_no_source",
        Lang::Csharp => "csharp_intra_function_no_source",
        Lang::Java => "java_intra_function_no_source",
        Lang::Ruby => "ruby_intra_function_no_source",
        Lang::Go => "go_intra_function_no_source",
        Lang::Rust => "rust_intra_function_no_source",
        _ => "intra_file_no_source",
    }
    .into()
}

fn guarded_reason_label(lang: Lang) -> String {
    match lang {
        Lang::Python => "escaped_input",
        Lang::Javascript | Lang::Typescript => "javascript_sanitized_input",
        Lang::Csharp => "csharp_sanitized_input",
        Lang::Java => "java_sanitized_input",
        Lang::Ruby => "ruby_sanitized_input",
        Lang::Go => "go_sanitized_input",
        Lang::Rust => "rust_sanitized_input",
        _ => "sanitized_input",
    }
    .into()
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
        "CBR-JS-XSS-INNER-HTML" | "CBR-JS-DOCUMENT-WRITE"
            if matches!(lang, Lang::Javascript | Lang::Typescript) =>
        {
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
            if text.contains("HtmlUtils.htmlEscape(")
                || text.contains("ESAPI.encoder().encodeForHTML(")
            {
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
            if captures
                .get("concat")
                .is_some_and(|s| concat_is_literal_only(s))
            {
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
        if let Some(kind) = direct_source_kind(lang, candidate) {
            return Some((kind.to_string(), pick_framework(semantics, &kind)));
        }
        for token in semantic_candidates(candidate) {
            if let Some(kind) = semantics.tainted_identifiers.get(&token) {
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
        Lang::Go => {
            if text.contains(".Query(") || text.contains(".URL.Query().Get(") {
                return Some("go.http.query");
            }
            if text.contains(".Param(") {
                return Some("go.http.param");
            }
            if text.contains(".FormValue(") {
                return Some("go.http.form");
            }
        }
        Lang::Rust => {
            if text.contains("std::env::args()")
                || text.contains("std::env::args().nth(")
                || text.contains("std::env::args().next(")
            {
                return Some("rust.env.args");
            }
            if text.contains("std::env::args_os()")
                || text.contains("std::env::args_os().nth(")
                || text.contains("std::env::args_os().next(")
            {
                return Some("rust.env.args_os");
            }
            if text.contains("std::env::var(") || text.contains("std::env::var_os(") {
                return Some("rust.env.var");
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
    if source_kind.starts_with("aspnet.") {
        return Some("aspnet".into());
    }
    if source_kind.starts_with("spring.") {
        return Some("spring".into());
    }
    if source_kind.starts_with("rails.") {
        return Some("rails".into());
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
            | "CBR-JAVA-SCRIPT_ENGINE_INJECTION"
            | "CBR-JAVA-FIND_SQL_STRING_CONCATENATION"
            | "CBR-JAVA-SPRING_UNVALIDATED_REDIRECT"
            | "CBR-JAVA-SPEL_INJECTION"
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
    matches!(
        compact.as_str(),
        "False" | "false" | "0" | "None" | "null" | "undefined"
    )
}

fn call_uses_only_literal_payload(text: &str) -> bool {
    let Some(open) = text.find('(') else {
        return false;
    };
    let Some(close) = text.rfind(')') else {
        return false;
    };
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
        if let Some(capture) = captures
            .iter()
            .find(|capture| query.capture_names()[capture.index as usize] == *preferred)
        {
            return Some(capture);
        }
    }

    captures.first()
}
