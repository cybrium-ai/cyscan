//! Tree-sitter matcher. One Parser per call — tree-sitter Parsers aren't
//! Sync-safe, so we don't try to share them across threads.

use std::path::{Path, PathBuf};
use std::collections::HashMap;

use anyhow::{Context, Result};
use tree_sitter::{Parser, Query, QueryCursor, Tree};

use crate::{finding::Finding, lang::Lang, rule::Rule};

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
        let Some(cap) = m.captures.first() else { continue };
        let node     = cap.node;
        let start    = node.start_position();
        let end      = node.end_position();
        let snippet  = node.utf8_text(bytes).unwrap_or("").lines().next()
            .unwrap_or("").trim().to_string();

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
