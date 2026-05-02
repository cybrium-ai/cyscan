//! Tree-sitter matcher. One Parser per call — tree-sitter Parsers aren't
//! Sync-safe, so we don't try to share them across threads.

use std::path::{Path, PathBuf};
use std::collections::HashMap;

use anyhow::{Context, Result};
use regex::Regex;
use tree_sitter::{Parser, Query, QueryCursor, Tree};

use crate::{finding::Finding, lang::Lang, rule::Rule};

use super::dsl::{
    metavariable_analysis_passes, metavariable_comparisons_match,
    metavariable_pattern_ast_match, metavariable_pattern_match,
    metavariable_receiver_type_match, metavariable_regex_match,
    metavariable_types_match, pattern_not_regex_passes,
    pattern_where_match, CaptureMeta,
};
use super::semantics::FileSemantics;

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
    rule:      &Rule,
    lang:      Lang,
    path:      &Path,
    source:    &str,
    tree:      &Tree,
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

    // Pre-compile DSL filters once per rule.
    let either_groups = compile_either_groups(&rule.pattern_either_groups);
    let not_inside    = compile_not_inside_regexes(&rule.pattern_not_inside);

    for m in cursor.matches(&query, tree.root_node(), bytes) {
        // Report on the first captured node — rules author the query
        // so the first capture is the "problem" node. For queries with
        // multiple captures we take the primary.
        let Some(cap) = m.captures.first() else { continue };
        let node     = cap.node;
        let start    = node.start_position();
        let end      = node.end_position();
        let snippet  = node.utf8_text(bytes).unwrap_or("").lines().next()
            .unwrap_or("").trim().to_string();

        // Build the per-match capture map: {capture_name -> {text, kind}}.
        // dsl::metavariable_* uses kind for type checks (e.g. `arg: identifier`).
        let mut captures: HashMap<String, CaptureMeta<'_>> = HashMap::new();
        for c in m.captures.iter() {
            let name = query.capture_names()[c.index as usize].to_string();
            if let Ok(text) = c.node.utf8_text(bytes) {
                captures.insert(name, CaptureMeta { text, kind: Some(c.node.kind()) });
            }
        }

        // pattern_either_groups: at least one full group must match
        // somewhere in the snippet's enclosing function/block. We use the
        // simplest scope — the captured node's text — which keeps this
        // cheap and predictable.
        if !either_groups.is_empty() {
            let scope_text = node.utf8_text(bytes).unwrap_or("");
            if !either_groups.iter().any(|g| g.iter().all(|r| r.is_match(scope_text))) {
                continue;
            }
        }

        // pattern_not_inside: walk parents, drop if any matches.
        if !not_inside.is_empty() {
            let mut suppressed = false;
            let mut cur = node.parent();
            while let Some(p) = cur {
                if p.parent().is_none() { break } // skip the root document
                if let Ok(text) = p.utf8_text(bytes) {
                    if not_inside.iter().any(|r| r.is_match(text)) {
                        suppressed = true;
                        break;
                    }
                }
                cur = p.parent();
            }
            if suppressed { continue }
        }

        // metavariable_comparison(s) + metavariable_types
        if !metavariable_comparisons_match(
            &rule.metavariable_comparisons,
            rule.metavariable_comparison.as_deref(),
            &captures,
        ) {
            continue;
        }
        if !rule.metavariable_types.is_empty()
            && !metavariable_types_match(&rule.metavariable_types, &captures)
        {
            continue;
        }
        // Semgrep-max DSL parity (Phase B): per-capture regex +
        // sub-pattern, plus matched-span negative regex.
        if !metavariable_regex_match(&rule.metavariable_regex, &captures) {
            continue;
        }
        if !metavariable_pattern_match(&rule.metavariable_pattern, &captures) {
            continue;
        }
        // Per-capture analyzer (Semgrep Pro `metavariable-analysis`
        // parity — redos / entropy).
        if !metavariable_analysis_passes(&rule.metavariable_analysis, &captures) {
            continue;
        }
        // Nested AST / cross-language sub-pattern.
        if !metavariable_pattern_ast_match(&rule.metavariable_pattern_ast, &captures) {
            continue;
        }
        // Compound boolean — Semgrep beta `pattern-where`.
        if !pattern_where_match(rule.pattern_where.as_deref(), &captures) {
            continue;
        }
        // Resolved-receiver-type — Checkmarx-style semantic
        // disambiguation. `db.execute(...)` only fires when `db`
        // resolves (via FileSemantics) to one of the listed types.
        if !metavariable_receiver_type_match(
            &rule.metavariable_receiver_type,
            &captures,
            semantics,
        ) {
            continue;
        }
        let span_text = node.utf8_text(bytes).unwrap_or("");
        if !pattern_not_regex_passes(&rule.pattern_not_regex, span_text) {
            continue;
        }

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
            start_byte: node.start_byte(),
            end_byte:   node.end_byte(),
            snippet,
            fix_recipe: rule.fix_recipe.clone(),
            fix:        rule.fix.clone(),
            cwe:        rule.cwe.clone(),
                evidence: HashMap::new(),
                reachability: None,
            fingerprint: String::new(),
        });
    }
    out
}

// ── DSL helpers (Gap 3 / B1) ────────────────────────────────────────────────

fn compile_either_groups(groups: &[Vec<String>]) -> Vec<Vec<Regex>> {
    groups
        .iter()
        .map(|group| {
            group
                .iter()
                .filter_map(|p| Regex::new(&format!("(?s){}", regex::escape(p.trim()))).ok())
                .collect::<Vec<_>>()
        })
        .filter(|g| !g.is_empty())
        .collect()
}

fn compile_not_inside_regexes(patterns: &[String]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|p| Regex::new(&format!("(?s){}", regex::escape(p.trim()))).ok())
        .collect()
}
