//! Regex matcher. Runs the compiled regex line-by-line, so column/row
//! reporting is straightforward. Multiline anchors aren't supported —
//! if a rule needs that, upgrade to tree-sitter.

use std::path::{Path, PathBuf};
use std::collections::HashMap;

use regex::Regex;

use crate::{finding::Finding, rule::Rule};

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
    // Track byte offset of each line start so we can report absolute byte
    // ranges for the fixer. `source.lines()` strips newlines, so we walk
    // the source manually to keep offsets honest on \r\n and \n alike.
    let mut line_start = 0usize;
    for (line_ix, line) in source.split_inclusive('\n').enumerate() {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        for m in re.find_iter(trimmed) {
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
