//! Regex matcher. Runs the compiled regex line-by-line, so column/row
//! reporting is straightforward. Multiline anchors aren't supported —
//! if a rule needs that, upgrade to tree-sitter.

use std::path::{Path, PathBuf};
use std::collections::HashMap;

use regex::Regex;

use crate::{finding::Finding, rule::Rule};

use super::dsl::{metavariable_comparisons_match, metavariable_types_match, CaptureMeta};

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

pub fn match_rule(rule: &Rule, path: &Path, source: &str) -> Vec<Finding> {
    // YAML block literal `|` keeps a trailing newline, which the regex
    // crate treats as a literal \n requirement. Trim any surrounding
    // whitespace so rule authors don't have to remember `|-` every time.
    let raw = rule.regex.as_deref().or(rule.pattern.as_deref());
    let Some(pat) = raw.map(str::trim) else {
        // Even with no primary pattern, the rule may use only the new
        // Semgrep-DSL aggregate sources (patterns/pattern_either/...).
        // Fall through to the DSL-driven match path in that case.
        if rule.patterns.is_empty()
            && rule.pattern_either.is_empty()
            && rule.pattern_either_groups.is_empty()
        {
            return Vec::new();
        }
        return dsl_only_match(rule, path, source);
    };
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

    // ── DSL prep: pattern_either_groups, pattern_not_inside, metavar filters ──
    let either_groups = compile_either_groups(&rule.pattern_either_groups);
    let not_inside_ranges = compile_not_inside_ranges(&rule.pattern_not_inside, source);
    let metavar_singular = rule.metavariable_comparison.as_deref();
    let metavar_multi    = &rule.metavariable_comparisons;
    let metavar_types    = &rule.metavariable_types;

    let mut out = Vec::new();
    // Track byte offset of each line start so we can report absolute byte
    // ranges for the fixer. `source.lines()` strips newlines, so we walk
    // the source manually to keep offsets honest on \r\n and \n alike.
    let mut line_start = 0usize;
    for (line_ix, line) in source.split_inclusive('\n').enumerate() {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        for m in re.find_iter(trimmed) {
            let abs_start = line_start + m.start();
            let abs_end   = line_start + m.end();
            // pattern_not_inside: drop if absolute span lives inside a
            // forbidden context block.
            if not_inside_ranges.iter().any(|(s, e)| abs_start >= *s && abs_end <= *e) {
                continue;
            }
            // pattern_either_groups: at least one full group must hit
            // somewhere in the source (cheap: any-of-all-of on the buffer).
            if !either_groups.is_empty()
                && !either_groups.iter().any(|group| group.iter().all(|r| r.is_match(source)))
            {
                continue;
            }
            // metavariable_comparison(s) + metavariable_types — captures
            // are per-match snippet; for regex we expose only `text`.
            let captures = single_match_captures(&m.as_str());
            if !metavariable_comparisons_match(metavar_multi, metavar_singular, &captures) {
                continue;
            }
            if !metavar_types.is_empty() && !metavariable_types_match(metavar_types, &captures) {
                continue;
            }
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
                start_byte: line_start + m.start(),
                end_byte:   line_start + m.end(),
                snippet:    trimmed.trim().to_string(),
                fix_recipe: rule.fix_recipe.clone(),
                fix:        rule.fix.clone(),
                cwe:        rule.cwe.clone(),
                evidence: HashMap::new(),
                reachability: None,
                fingerprint: String::new(),
            });
        }
        line_start += line.len();
    }
    out
}

// ── DSL helper functions (Gap 3 / B1) ───────────────────────────────────────

/// Compile a list of pattern groups into regex groups. Empty groups (all
/// patterns failed to compile) are dropped — caller treats an empty result
/// as "no constraint" rather than "must fail".
fn compile_either_groups(groups: &[Vec<String>]) -> Vec<Vec<Regex>> {
    groups
        .iter()
        .map(|group| {
            group
                .iter()
                .filter_map(|p| Regex::new(&semgrep_to_regex(p.trim())).ok())
                .collect::<Vec<_>>()
        })
        .filter(|g| !g.is_empty())
        .collect()
}

/// Resolve `pattern_not_inside` patterns to a set of byte ranges in the
/// source. A finding whose match span is contained in any of these ranges
/// is suppressed. The match start is treated as the *start* of the
/// forbidden block, and the block extends to the next blank line (\n\n)
/// or end-of-file — same heuristic Semgrep uses to scope context blocks
/// in regex-only mode.
fn compile_not_inside_ranges(patterns: &[String], source: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for raw in patterns {
        let p = raw.trim();
        if p.is_empty() { continue }
        let pat = format!("(?s){}", semgrep_to_regex(p));
        let Ok(re) = Regex::new(&pat) else { continue };
        for m in re.find_iter(source) {
            let tail = &source[m.end()..];
            let block_end = tail
                .find("\n\n")
                .map(|idx| m.end() + idx)
                .unwrap_or(source.len());
            ranges.push((m.start(), block_end));
        }
    }
    ranges
}

/// Build a HashMap with a single synthetic `match` capture so DSL
/// comparison/type checks have *something* to evaluate against in the
/// regex matcher (which has no AST captures of its own).
fn single_match_captures(text: &str) -> HashMap<String, CaptureMeta<'_>> {
    let mut h = HashMap::new();
    h.insert(
        "match".to_string(),
        CaptureMeta { text, kind: None },
    );
    h
}

/// Path used when the rule has no primary regex/pattern but uses only
/// the new aggregate sources (patterns / pattern_either /
/// pattern_either_groups). We OR every supplied pattern into a single
/// alternation regex and run the standard line-by-line scan.
fn dsl_only_match(rule: &Rule, path: &Path, source: &str) -> Vec<Finding> {
    let mut all: Vec<&str> = Vec::new();
    all.extend(rule.patterns.iter().map(String::as_str));
    all.extend(rule.pattern_either.iter().map(String::as_str));
    all.extend(rule.pattern_either_groups.iter().flat_map(|g| g.iter().map(String::as_str)));
    let alternation = all
        .iter()
        .filter_map(|p| {
            let trimmed = p.trim();
            if trimmed.is_empty() { return None }
            Some(semgrep_to_regex(trimmed))
        })
        .map(|p| format!("(?:{})", p))
        .collect::<Vec<_>>()
        .join("|");
    if alternation.is_empty() { return Vec::new() }

    // Recurse via a synthetic rule that has the alternation as `regex`.
    let mut synthetic = rule.clone();
    synthetic.regex = Some(alternation);
    synthetic.patterns.clear();
    synthetic.pattern_either.clear();
    synthetic.pattern_either_groups.clear();
    match_rule(&synthetic, path, source)
}
