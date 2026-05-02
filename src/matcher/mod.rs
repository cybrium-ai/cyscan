//! Matcher dispatch — picks regex vs tree-sitter per rule, emits findings.

pub mod dsl;
pub mod entropy;
pub mod regex;
pub mod semantics;
pub mod treesitter;
pub mod verify;

use std::collections::HashSet;
use std::path::Path;

use crate::{finding::Finding, lang::Lang, rule::Rule};

/// Run every rule that applies to `lang` against `source`, collecting
/// findings. Rules whose `languages` list doesn't include `lang` are
/// skipped cheaply.
pub fn run_rules<'a>(
    rules: &'a [Rule],
    lang: Lang,
    frameworks: &HashSet<String>,
    path: &Path,
    source: &str,
    base_path: Option<&Path>,
) -> Vec<Finding> {
    let semantics = semantics::extract(lang, source);
    run_rules_with_semantics(rules, lang, frameworks, path, source, base_path, &semantics)
}

pub fn run_rules_with_semantics<'a>(
    rules: &'a [Rule],
    lang: Lang,
    frameworks: &HashSet<String>,
    path: &Path,
    source: &str,
    base_path: Option<&Path>,
    semantics: &semantics::FileSemantics,
) -> Vec<Finding> {
    let applicable: Vec<&Rule> = rules
        .iter()
        .filter(|r| {
            (r.languages.contains(&lang) || r.languages.contains(&Lang::Generic))
                && rule_matches_frameworks(r, frameworks)
        })
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
            findings.extend(treesitter::match_rule(
                rule, lang, path, source, tree, semantics,
            ));
        } else if rule.regex.is_some()
            || rule.pattern.is_some()
            || !rule.patterns.is_empty()
            || !rule.pattern_either.is_empty()
            || !rule.pattern_either_groups.is_empty()
        {
            findings.extend(regex::match_rule(rule, lang, path, source, semantics));
        }
    }

    // Entropy-based secret detection — runs on every file regardless of rules.
    // Catches secrets that don't match any known pattern.
    findings.extend(entropy::scan_file(path, source));

    enrich_precision(&mut findings);

    for f in &mut findings {
        f.fingerprint = Finding::compute_fingerprint(&f.rule_id, &f.file, &f.snippet, base_path);
    }

    findings
}

fn rule_matches_frameworks(rule: &Rule, frameworks: &HashSet<String>) -> bool {
    if rule.frameworks.is_empty() {
        return true;
    }

    rule.frameworks
        .iter()
        .any(|fw| frameworks.contains(&normalise_framework_name(fw)))
}

pub fn normalise_framework_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

fn enrich_precision(findings: &mut [Finding]) {
    for finding in findings {
        if let Some(wrapper_kind) = safe_wrapper_kind(&finding.snippet) {
            finding
                .evidence
                .entry("safe_wrapper_kind".into())
                .or_insert_with(|| serde_json::json!(wrapper_kind));
        }
        let (label, score, reason) = confidence_for_finding(finding);
        finding
            .evidence
            .entry("confidence".into())
            .or_insert_with(|| serde_json::json!(label));
        finding
            .evidence
            .entry("confidence_score".into())
            .or_insert_with(|| serde_json::json!(score));
        finding
            .evidence
            .entry("confidence_reason".into())
            .or_insert_with(|| serde_json::json!(reason));
    }
}

fn confidence_for_finding(finding: &Finding) -> (&'static str, f64, &'static str) {
    let matcher_kind = finding
        .evidence
        .get("matcher_kind")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let has_source = finding.evidence.contains_key("source_kind");
    let has_sink = finding.evidence.contains_key("sink_kind");
    let has_framework = finding.evidence.contains_key("framework");
    let has_sanitizer = finding.evidence.contains_key("sanitizer_kind");
    let has_safe_wrapper = finding.evidence.contains_key("safe_wrapper_kind");
    let path_sensitivity = finding
        .evidence
        .get("path_sensitivity")
        .and_then(|v| v.as_str());

    if finding.evidence.get("verified").and_then(|v| v.as_bool()) == Some(true) {
        return ("high", 0.99, "verified");
    }

    match finding.reachability.as_deref() {
        Some("unreachable") => return ("low", 0.15, "dead_code"),
        Some("unknown") if has_sanitizer || path_sensitivity == Some("guarded") => {
            return ("low", 0.30, "guarded_or_sanitized");
        }
        _ => {}
    }

    if has_safe_wrapper && !has_source {
        return ("low", 0.35, "safe_wrapper_context");
    }

    if has_source && has_sink && finding.reachability.as_deref() == Some("reachable") {
        return match matcher_kind {
            "tree_sitter" => ("high", 0.95, "ast_source_to_sink"),
            "regex" => ("high", 0.86, "source_to_sink"),
            "entropy" => ("medium", 0.72, "entropy_heuristic"),
            _ => ("high", 0.84, "source_to_sink"),
        };
    }

    if has_sink && has_framework {
        return match matcher_kind {
            "tree_sitter" => ("medium", 0.78, "ast_framework_sink"),
            "regex" => ("medium", 0.68, "framework_sink"),
            _ => ("medium", 0.65, "framework_sink"),
        };
    }

    if has_sink || has_source {
        return match matcher_kind {
            "tree_sitter" => ("medium", 0.72, "ast_semantic_signal"),
            "regex" => ("medium", 0.62, "semantic_signal"),
            "entropy" => ("medium", 0.70, "entropy_signal"),
            _ => ("medium", 0.60, "semantic_signal"),
        };
    }

    match matcher_kind {
        "entropy" => ("medium", 0.74, "entropy_match"),
        "tree_sitter" => ("medium", 0.66, "ast_match"),
        "regex" => ("low", 0.52, "regex_match"),
        _ => ("low", 0.50, "generic_match"),
    }
}

fn safe_wrapper_kind(snippet: &str) -> Option<&'static str> {
    let compact: String = snippet.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains("HttpUtility.HtmlEncode(") || compact.contains("WebUtility.HtmlEncode(") {
        return Some("aspnet.html_encode");
    }
    if compact.contains("HtmlEncoder.Default.Encode(")
        || compact.contains("IHtmlHelper.Encode(")
        || compact.contains("Html.Encode(")
    {
        return Some("aspnet.html_encode");
    }
    if compact.contains("JavaScriptEncoder.Default.Encode(") {
        return Some("aspnet.js_encode");
    }
    if compact.contains("UrlEncoder.Default.Encode(")
        || compact.contains("Uri.EscapeDataString(")
        || compact.contains("HttpUtility.UrlEncode(")
        || compact.contains("WebUtility.UrlEncode(")
    {
        return Some("aspnet.url_encode");
    }
    if compact.contains("AntiXssEncoder.UrlEncode(") {
        return Some("aspnet.antixss_url_encode");
    }
    if compact.contains("AntiXssEncoder.HtmlEncode(") {
        return Some("aspnet.antixss_html_encode");
    }
    if compact.contains("MvcHtmlString.Create(")
        || compact.contains("HtmlString(")
        || compact.contains("IHtmlContent")
    {
        return Some("aspnet.typed_html_wrapper");
    }
    if compact.contains("TagBuilder") && compact.contains(".InnerHtml.Append(") {
        return Some("aspnet.tagbuilder_append");
    }
    if compact.contains("HtmlEncoder.Default.Encode(") {
        return Some("dotnet.html_encoder");
    }
    if compact.contains("format_html(") {
        return Some("django.format_html");
    }
    if compact.contains("conditional_escape(") {
        return Some("django.conditional_escape");
    }
    if compact.contains("HtmlUtils.htmlEscape(") || compact.contains("HtmlUtils.htmlEscapeDecimal(")
    {
        return Some("spring.html_escape");
    }
    if compact.contains("ESAPI.encoder().encodeForHTML(") {
        return Some("esapi.html_encode");
    }
    if compact.contains("sanitize(") {
        return Some("rails.sanitize");
    }
    if compact.contains("strip_tags(") {
        return Some("rails.strip_tags");
    }
    if compact.contains("html_escape(") || compact.contains(".html_safe") || compact.contains("h(")
    {
        return Some("rails.html_escape");
    }
    if compact.contains("flask.escape(") || compact.contains("markupsafe.escape(") {
        return Some("python.html_escape");
    }
    if compact.contains("DOMPurify.sanitize(") {
        return Some("dompurify");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};
    use std::{collections::HashMap, path::PathBuf};

    #[test]
    fn aspnet_safe_wrapper_is_recognized() {
        assert_eq!(
            safe_wrapper_kind("return HttpUtility.HtmlEncode(userInput);"),
            Some("aspnet.html_encode")
        );
        assert_eq!(
            safe_wrapper_kind("var x = JavaScriptEncoder.Default.Encode(payload);"),
            Some("aspnet.js_encode")
        );
    }

    #[test]
    fn safe_wrapper_lowers_confidence_for_generic_match() {
        let mut findings = vec![Finding {
            rule_id: "CBR-TEST".into(),
            title: "test".into(),
            severity: Severity::High,
            message: "msg".into(),
            file: PathBuf::from("Controller.cs"),
            line: 1,
            column: 1,
            end_line: 1,
            end_column: 10,
            fingerprint: String::new(),
            start_byte: 0,
            end_byte: 0,
            snippet: "return HttpUtility.HtmlEncode(userInput);".into(),
            fix_recipe: None,
            fix: None,
            cwe: vec![],
            evidence: HashMap::from([
                ("matcher_kind".into(), serde_json::json!("regex")),
                ("sink_kind".into(), serde_json::json!("generic.output")),
            ]),
            reachability: Some("unknown".into()),
        }];

        enrich_precision(&mut findings);

        assert_eq!(
            findings[0]
                .evidence
                .get("safe_wrapper_kind")
                .and_then(|v| v.as_str()),
            Some("aspnet.html_encode")
        );
        assert_eq!(
            findings[0]
                .evidence
                .get("confidence")
                .and_then(|v| v.as_str()),
            Some("low")
        );
    }
}
