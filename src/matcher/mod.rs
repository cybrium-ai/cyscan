//! Matcher dispatch — picks regex vs tree-sitter per rule, emits findings.

pub mod regex;
pub mod treesitter;

use std::path::Path;

use crate::{finding::Finding, lang::Lang, rule::Rule};

/// Run every rule that applies to `lang` against `source`, collecting
/// findings. Rules whose `languages` list doesn't include `lang` are
/// skipped cheaply.
pub fn run_rules<'a>(
    rules: &'a [Rule],
    lang: Lang,
    path: &Path,
    source: &str,
) -> Vec<Finding> {
    let applicable: Vec<&Rule> = rules.iter()
        .filter(|r| r.languages.contains(&lang))
        .collect();

    if applicable.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    // Parse once per file for every tree-sitter rule. Parse lazily so
    // regex-only rule packs don't pay the tree-sitter cost.
    let mut parsed: Option<(tree_sitter::Tree, ())> = None;

    for rule in applicable {
        if rule.query.is_some() {
            if parsed.is_none() {
                match treesitter::parse(lang, source) {
                    Ok(tree) => parsed = Some((tree, ())),
                    Err(err) => {
                        log::warn!("parse failed for {}: {err}", path.display());
                        continue;
                    }
                }
            }
            let (tree, _) = parsed.as_ref().unwrap();
            findings.extend(treesitter::match_rule(rule, lang, path, source, tree));
        } else if rule.regex.is_some() {
            findings.extend(regex::match_rule(rule, path, source));
        }
    }
    findings
}
