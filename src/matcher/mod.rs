//! Matcher dispatch — picks regex vs tree-sitter per rule, emits findings.

pub mod dsl;
pub mod entropy;
pub mod regex;
pub mod semantics;
pub mod treesitter;
pub mod verify;

use std::path::Path;

use crate::{finding::Finding, lang::Lang, rule::Rule};

/// Run every rule that applies to `lang` against `source`, collecting
/// findings. Rules whose `languages` list doesn't include `lang` are
/// skipped cheaply. Extracts FileSemantics once per file (Gap 2 / A5)
/// so framework-tagged rules (Gap 5 / B2) and capture-aware DSL filters
/// can resolve types, imports, and inferred variable kinds.
pub fn run_rules<'a>(
    rules: &'a [Rule],
    lang: Lang,
    path: &Path,
    source: &str,
) -> Vec<Finding> {
    let applicable: Vec<&Rule> = rules.iter()
        .filter(|r| r.languages.contains(&lang) || r.languages.contains(&Lang::Generic))
        .collect();

    if applicable.is_empty() {
        return Vec::new();
    }

    // Extract per-file semantics once (Gap 2 / A5). Default for
    // unsupported languages; cheap for supported ones because every
    // extractor is a single regex pass over the source.
    let file_semantics = semantics::extract(lang, source);

    let mut findings = Vec::new();

    // Parse once per file for every tree-sitter rule. Parse lazily so
    // regex-only rule packs don't pay the tree-sitter cost.
    let mut parsed: Option<(tree_sitter::Tree, ())> = None;

    for rule in applicable {
        // Framework filter (Gap 5 / B2). When a rule lists frameworks,
        // it only applies to files where at least one of those frameworks
        // was detected. Empty `frameworks` = applies everywhere.
        if !rule.frameworks.is_empty()
            && !rule.frameworks.iter().any(|fw| file_semantics.frameworks.contains(fw))
        {
            continue;
        }

        let new_findings: Vec<Finding> = if rule.query.is_some() {
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
            treesitter::match_rule(rule, lang, path, source, tree)
        } else if rule.regex.is_some() || rule.pattern.is_some() {
            regex::match_rule(rule, path, source)
        } else {
            Vec::new()
        };

        // Tag each finding with the framework that fired it (when known)
        // so reviewers see *why* the rule applied. Only set when the rule
        // declared frameworks to keep evidence noise low.
        for mut f in new_findings {
            if !rule.frameworks.is_empty() {
                let matched: Vec<&String> = rule.frameworks.iter()
                    .filter(|fw| file_semantics.frameworks.contains(*fw))
                    .collect();
                if !matched.is_empty() {
                    f.evidence.insert(
                        "framework".into(),
                        serde_json::json!(matched.iter().map(|s| s.as_str()).collect::<Vec<_>>()),
                    );
                }
            }
            findings.push(f);
        }
    }

    // Entropy-based secret detection — runs on every file regardless of rules.
    // Catches secrets that don't match any known pattern.
    findings.extend(entropy::scan_file(path, source));

    findings
}
