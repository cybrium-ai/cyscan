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
    for (line_ix, line) in source.lines().enumerate() {
        for m in re.find_iter(line) {
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
                snippet:    line.trim().to_string(),
                fix_recipe: rule.fix_recipe.clone(),
                cwe:        rule.cwe.clone(),
            });
        }
    }
    out
}
