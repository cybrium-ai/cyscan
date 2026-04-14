//! Regex matcher. Runs the compiled regex line-by-line, so column/row
//! reporting is straightforward. Multiline anchors aren't supported —
//! if a rule needs that, upgrade to tree-sitter.

use std::path::{Path, PathBuf};

use regex::Regex;

use crate::{finding::Finding, rule::Rule};

pub fn match_rule(rule: &Rule, path: &Path, source: &str) -> Vec<Finding> {
    // YAML block literal `|` keeps a trailing newline, which the regex
    // crate treats as a literal \n requirement. Trim any surrounding
    // whitespace so rule authors don't have to remember `|-` every time.
    let Some(pat) = rule.regex.as_deref().map(str::trim) else { return Vec::new() };
    if pat.is_empty() { return Vec::new() }

    let re = match Regex::new(pat) {
        Ok(r)  => r,
        Err(e) => {
            log::warn!("rule {}: regex compile failed: {e}", rule.id);
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
            });
        }
        line_start += line.len();
    }
    out
}
