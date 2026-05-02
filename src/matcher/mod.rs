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
    run_rules_with_project(rules, lang, path, source, None)
}

/// Variant of `run_rules` that accepts an optional cross-file
/// `ProjectSemantics` (Gap A4). When provided, rules with a
/// `dataflow:` block consult the project taint graph to decide whether
/// the match is reachable from a source. Findings get
/// `evidence.dataflow_reachable` and (when reachable)
/// `evidence.dataflow_path`. The non-project path stays cheap for
/// single-file scans and tests.
pub fn run_rules_with_project<'a>(
    rules: &'a [Rule],
    lang: Lang,
    path: &Path,
    source: &str,
    project: Option<&crate::dataflow::ProjectSemantics>,
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

            // Inter-procedural dataflow gate (Gap A4). When the rule
            // carries a `dataflow:` block AND the project pre-pass ran,
            // we resolve the function enclosing this match and ask the
            // project taint graph whether any source reaches it.
            if let (Some(spec), Some(proj)) = (rule.dataflow.as_ref(), project) {
                let enclosing = enclosing_function_name(source, f.line, &file_semantics);
                let reachable = enclosing
                    .as_deref()
                    .map(|fn_name| proj.is_reachable_from_source(fn_name))
                    .unwrap_or(false);

                if spec.require_reachable && !reachable {
                    // Suppress this finding entirely.
                    continue;
                }

                f.evidence.insert("dataflow_reachable".into(), serde_json::json!(reachable));
                if let Some(fn_name) = enclosing.as_deref() {
                    f.evidence.insert("dataflow_function".into(), serde_json::json!(fn_name));
                    if reachable {
                        let path_chain = proj.dataflow_path_to(fn_name);
                        if !path_chain.is_empty() {
                            f.evidence.insert(
                                "dataflow_path".into(),
                                serde_json::json!(path_chain),
                            );
                            f.evidence.insert(
                                "dataflow_path_string".into(),
                                serde_json::json!(path_chain.join(" → ")),
                            );
                        }
                    }
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

/// Best-effort: find the name of the function that contains `line` by
/// walking the source for `def name(...)` / `function name(...)` /
/// `fn name(...)` headers. Returns the most recent header at or above
/// `line`. Used by the dataflow gate to look the enclosing function up
/// in `ProjectSemantics`.
fn enclosing_function_name(source: &str, line: usize, _sem: &semantics::FileSemantics) -> Option<String> {
    if line == 0 { return None }
    // Cheap multi-language regex — covers the languages our extractors
    // actually support. Skips lambdas/anonymous fns by design.
    use std::sync::OnceLock;
    static RE: OnceLock<::regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        ::regex::Regex::new(
            r"(?m)^[\s]*(?:async\s+)?(?:pub\s+)?(?:def|function|fn|func|sub|public|private|protected|internal|static|void)\s+([A-Za-z_][A-Za-z_0-9]*)\s*\("
        ).unwrap()
    });
    let mut current: Option<String> = None;
    let mut current_line = 0;
    for (idx, raw) in source.lines().enumerate() {
        let lineno = idx + 1;
        if lineno > line { break; }
        if let Some(c) = re.captures(raw) {
            if let Some(name) = c.get(1).map(|m| m.as_str().to_string()) {
                current = Some(name);
                current_line = lineno;
            }
        }
    }
    let _ = current_line;
    current
}
