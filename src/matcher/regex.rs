//! Regex matcher. Runs the compiled regex line-by-line, so column/row
//! reporting is straightforward. Multiline anchors aren't supported —
//! if a rule needs that, upgrade to tree-sitter.

use std::path::{Path, PathBuf};
use std::collections::HashMap;

use regex::{Regex, RegexBuilder};

use crate::{finding::Finding, lang::Lang, rule::Rule};

use super::semantics::FileSemantics;

/// Convert semgrep-style AST pattern to regex.
///
/// Semgrep uses `$VAR` for metavariables and `...` for wildcards.
/// We convert these to regex equivalents so imported rules work
/// without a full semgrep engine.
pub(super) fn semgrep_to_regex(pattern: &str) -> String {
    // If pattern already looks like valid regex (no $VAR or ...), return as-is
    if !pattern.contains('$') && !pattern.contains("...") {
        return pattern.to_string();
    }

    let mut result = String::with_capacity(pattern.len() * 2);
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            c if c.is_whitespace() => {
                while i < chars.len() && chars[i].is_whitespace() {
                    i += 1;
                }
                result.push_str(r"\s+");
            }
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
            '.' => { result.push_str(r"\."); i += 1; }
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

pub fn match_rule(
    rule: &Rule,
    lang: Lang,
    path: &Path,
    source: &str,
    semantics: &FileSemantics,
) -> Vec<Finding> {
    let positive_patterns = rule_positive_patterns(rule);
    if positive_patterns.is_empty() {
        return Vec::new();
    }

    let compiled_patterns: Vec<Regex> = positive_patterns.iter()
        .filter_map(|pat| compile_semgrep_like_regex(rule.id.as_str(), pat, false))
        .collect();
    if compiled_patterns.is_empty() {
        return Vec::new();
    }
    let multiline = positive_patterns.iter().any(|pat| needs_multiline_matching(pat))
        || rule.pattern_inside.as_deref().is_some_and(needs_multiline_matching);
    let inside_ranges = rule.pattern_inside.as_deref()
        .and_then(|pat| compile_semgrep_like_regex(rule.id.as_str(), pat, true))
        .map(|re| context_ranges(source, &re))
        .unwrap_or_default();
    let pattern_not = rule.pattern_not.as_deref()
        .and_then(|pat| compile_semgrep_like_regex(rule.id.as_str(), pat, multiline));

    let mut out = Vec::new();
    if multiline {
        let primary = &compiled_patterns[0];
        for m in primary.find_iter(source) {
            if !all_patterns_match_range(&compiled_patterns[1..], source, m.start(), m.end()) {
                continue;
            }
                if pattern_not_matches(
                    rule.pattern_not.as_deref(),
                    pattern_not.as_ref(),
                    &source[m.start()..m.end()],
                ) {
                    continue;
                }
            if !inside_ranges.is_empty() && !inside_ranges.iter().any(|(start, end)| m.start() >= *start && m.end() <= *end) {
                continue;
            }
            let (line, column) = byte_to_line_col(source, m.start());
            let (end_line, end_column) = byte_to_line_col(source, m.end());
            let snippet = source[m.start()..m.end()]
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            let (evidence, reachability) =
                annotate_regex_finding(rule, lang, source, m.start(), &source[m.start()..m.end()], semantics);

            out.push(Finding {
                rule_id:    rule.id.clone(),
                title:      rule.title.clone(),
                severity:   rule.severity,
                message:    rule.message.clone(),
                file:       PathBuf::from(path),
                line,
                column,
                end_line,
                end_column,
                fingerprint: String::new(),
                start_byte: m.start(),
                end_byte:   m.end(),
                snippet,
                fix_recipe: rule.fix_recipe.clone(),
                fix:        rule.fix.clone(),
                cwe:        rule.cwe.clone(),
                evidence,
                reachability,
                });
        }
    } else {
        let primary = &compiled_patterns[0];
        // Track byte offset of each line start so we can report absolute byte
        // ranges for the fixer. `source.lines()` strips newlines, so we walk
        // the source manually to keep offsets honest on \r\n and \n alike.
        let mut line_start = 0usize;
        for (line_ix, line) in source.split_inclusive('\n').enumerate() {
            let trimmed = line.trim_end_matches(['\r', '\n']);
            for m in primary.find_iter(trimmed) {
                if !compiled_patterns[1..].iter().all(|re| re.is_match(trimmed)) {
                    continue;
                }
                if pattern_not_matches(rule.pattern_not.as_deref(), pattern_not.as_ref(), trimmed) {
                    continue;
                }
                let abs_start = line_start + m.start();
                let abs_end = line_start + m.end();
                if !inside_ranges.is_empty() && !inside_ranges.iter().any(|(start, end)| abs_start >= *start && abs_end <= *end) {
                    continue;
                }
                let (evidence, reachability) = annotate_regex_finding(rule, lang, source, abs_start, trimmed, semantics);
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
                    fingerprint: String::new(),
                    start_byte: abs_start,
                    end_byte:   abs_end,
                    snippet:    trimmed.trim().to_string(),
                    fix_recipe: rule.fix_recipe.clone(),
                    fix:        rule.fix.clone(),
                    cwe:        rule.cwe.clone(),
                    evidence,
                    reachability,
                });
            }
            line_start += line.len();
        }
    }

    if out.is_empty() {
        out.extend(special_case_findings(rule, lang, path, source, semantics));
    }
    out
}

fn needs_multiline_matching(pattern: &str) -> bool {
    pattern.contains('\n')
}

fn rule_positive_patterns(rule: &Rule) -> Vec<&str> {
    if !rule.patterns.is_empty() {
        return rule.patterns.iter().map(String::as_str).collect();
    }
    rule.regex.as_deref().or(rule.pattern.as_deref())
        .map(|pat| vec![pat.trim()])
        .unwrap_or_default()
}

fn compile_semgrep_like_regex(rule_id: &str, pattern: &str, multiline: bool) -> Option<Regex> {
    let pat = pattern.trim();
    if pat.is_empty() {
        return None;
    }
    let converted = semgrep_to_regex(pat);
    let meaningful = converted.replace(r"\w+", "").replace(".*", "").replace(r"\s+", "");
    if meaningful.trim().len() < 3 {
        return None;
    }
    let builder = RegexBuilder::new(&converted)
        .dot_matches_new_line(multiline)
        .multi_line(multiline)
        .build();
    match builder {
        Ok(re) => Some(re),
        Err(e) => {
            log::debug!("rule {}: pattern compile failed: {e}", rule_id);
            None
        }
    }
}

fn all_patterns_match_range(patterns: &[Regex], source: &str, start: usize, end: usize) -> bool {
    let snippet = &source[start..end];
    patterns.iter().all(|re| re.is_match(snippet))
}

fn context_ranges(source: &str, re: &Regex) -> Vec<(usize, usize)> {
    re.find_iter(source)
        .map(|m| {
            let tail = &source[m.end()..];
            let block_end = tail.find("\n\n").map(|idx| m.end() + idx).unwrap_or(source.len());
            (m.start(), block_end)
        })
        .collect()
}

fn pattern_not_matches(raw: Option<&str>, compiled: Option<&Regex>, text: &str) -> bool {
    compiled.is_some_and(|re| re.is_match(text))
        || raw.is_some_and(|pat| compact_code(text).contains(&compact_code(pat)))
}

fn compact_code(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

fn byte_to_line_col(source: &str, byte_idx: usize) -> (usize, usize) {
    let clamped = byte_idx.min(source.len());
    let prefix = &source[..clamped];
    let line = prefix.bytes().filter(|b| *b == b'\n').count() + 1;
    let col = prefix.rsplit('\n').next().map(|s| s.chars().count()).unwrap_or(0) + 1;
    (line, col)
}

fn special_case_findings(
    rule: &Rule,
    lang: Lang,
    path: &Path,
    source: &str,
    semantics: &FileSemantics,
) -> Vec<Finding> {
    match (rule.id.as_str(), lang) {
        ("CBR-JAVA-SPRING_UNVALIDATED_REDIRECT", Lang::Java) => {
            let re = Regex::new(r#"return\s+"redirect:"\s*\+\s*([A-Za-z_][A-Za-z0-9_]*)"#).unwrap();
            special_case_source_regex(rule, lang, path, source, semantics, &re)
        }
        ("CBR-JAVA-SPEL_INJECTION", Lang::Java) => {
            let re = Regex::new(r#"[A-Za-z_][A-Za-z0-9_]*\.parseExpression\(\s*([A-Za-z_][A-Za-z0-9_]*)"#).unwrap();
            special_case_source_regex(rule, lang, path, source, semantics, &re)
        }
        ("CBR-JAVA-SCRIPT_ENGINE_INJECTION", Lang::Java) => {
            let re = Regex::new(r#"[A-Za-z_][A-Za-z0-9_]*\.eval\(\s*([A-Za-z_][A-Za-z0-9_]*)"#).unwrap();
            special_case_source_regex(rule, lang, path, source, semantics, &re)
        }
        ("CBR-JAVA-FIND_SQL_STRING_CONCATENATION", Lang::Java) => {
            let re = Regex::new(r#"prepareStatement\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)"#).unwrap();
            special_case_source_regex(rule, lang, path, source, semantics, &re)
        }
        _ => Vec::new(),
    }
}

fn special_case_source_regex(
    rule: &Rule,
    lang: Lang,
    path: &Path,
    source: &str,
    semantics: &FileSemantics,
    re: &Regex,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for caps in re.captures_iter(source) {
        let Some(m) = caps.get(0) else { continue };
        let (line, column) = byte_to_line_col(source, m.start());
        let (end_line, end_column) = byte_to_line_col(source, m.end());
        let snippet = m.as_str().lines().next().unwrap_or("").trim().to_string();
        let (mut evidence, reachability) = annotate_regex_finding(rule, lang, source, m.start(), m.as_str(), semantics);

        if let Some(arg) = caps.get(1).map(|m| m.as_str()) {
            if evidence.get("source_kind").is_none() {
                if let Some(kind) = semantics.tainted_identifiers.get(arg) {
                    evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                    evidence.insert("source_kind".into(), serde_json::json!(kind));
                }
            }
        }
        out.push(Finding {
            rule_id:    rule.id.clone(),
            title:      rule.title.clone(),
            severity:   rule.severity,
            message:    rule.message.clone(),
            file:       PathBuf::from(path),
            line,
            column,
            end_line,
            end_column,
            fingerprint: String::new(),
            start_byte: m.start(),
            end_byte:   m.end(),
            snippet,
            fix_recipe: rule.fix_recipe.clone(),
            fix:        rule.fix.clone(),
            cwe:        rule.cwe.clone(),
            evidence,
            reachability,
        });
    }
    out
}

fn annotate_regex_finding(
    rule: &Rule,
    lang: Lang,
    source: &str,
    match_start: usize,
    snippet: &str,
    semantics: &FileSemantics,
) -> (HashMap<String, serde_json::Value>, Option<String>) {
    let mut evidence = HashMap::new();
    evidence.insert("matcher_kind".into(), serde_json::json!("regex"));

    let sink_kind = match rule.id.as_str() {
        "CBR-PHP-ASSERT_USE_AUDIT" => Some("php.assert"),
        "CBR-PHP-BACKTICKS_USE" => Some("php.backticks"),
        "CBR-PHP-EVAL_USE" => Some("php.eval"),
        "CBR-PHP-EXEC_USE" => Some("php.exec"),
        "CBR-PHP-FTP_USE" => Some("php.ftp"),
        "CBR-PHP-MB_EREG_REPLACE_EVAL" => Some("php.mb_ereg_replace"),
        "CBR-PHP-OPENSSL_DECRYPT_VALIDATE" => Some("php.openssl_decrypt"),
        "CBR-PHP-PHP_PERMISSIVE_CORS" => Some("php.header"),
        "CBR-PHP-PHPINFO_USE" => Some("php.phpinfo"),
        "CBR-PHP-SYMFONY_NON_LITERAL_REDIRECT" => Some("php.redirect"),
        "CBR-PHP-UNLINK_USE" => Some("php.unlink"),
        "CBR-PHP-UNSERIALIZE_USE" => Some("php.unserialize"),
        "CBR-PHP-WP_OPEN_REDIRECT_AUDIT" => Some("wordpress.redirect"),
        "CBR-SWIF-DETECT_APPLE_CORE_ML" => Some("swift.coreml"),
        "CBR-SWIF-DETECT_GEMINI" => Some("swift.gemini"),
        "CBR-SWIF-INSECURE_RANDOM" => Some("swift.random"),
        "CBR-SWIF-SWIFT_WEBVIEW_CONFIG_ALLOWS_JS" => Some("swift.webkit.preferences"),
        "CBR-SCAL-DANGEROUS_SEQ_RUN" => Some("scala.process.seq"),
        "CBR-SCAL-DANGEROUS_SHELL_RUN" => Some("scala.process.shell"),
        "CBR-SCAL-DISPATCH_SSRF" => Some("scala.dispatch.url"),
        "CBR-SCAL-INSECURE_RANDOM" => Some("scala.random"),
        "CBR-SCAL-NO_NULL_CIPHER" => Some("scala.null_cipher"),
        "CBR-SCAL-RSA_PADDING_SET" => Some("scala.cipher.get_instance"),
        "CBR-SCAL-SCALA_JWT_HARDCODED_SECRET" => Some("scala.jwt.hmac256"),
        "CBR-SCAL-SCALA_SLICK_OVERRIDESQL_LITERA" => Some("scala.slick.override_sql"),
        "CBR-SCAL-SCALA_SLICK_SQL_NON_LITERAL" => Some("scala.slick.sql"),
        "CBR-SCAL-SCALAJ_HTTP_SSRF" => Some("scala.scalaj.http"),
        "CBR-SCAL-WEBSERVICE_SSRF" => Some("scala.ws.url"),
        "CBR-C-C_STRING_EQUALITY" => Some("c.string_pointer_equality"),
        "CBR-C-DOUBLE_GOTO" => Some("c.goto"),
        "CBR-C-INCORRECT_USE_ATO_FN" => Some("c.atoi"),
        "CBR-C-INCORRECT_USE_SSCANF_FN" => Some("c.sscanf"),
        "CBR-C-INFO_LEAK_ON_NON_FORMATED_STRI" => Some("c.printf"),
        "CBR-C-INSECURE_USE_GETS_FN" => Some("c.gets"),
        "CBR-C-INSECURE_USE_MEMSET" => Some("c.memset"),
        "CBR-C-INSECURE_USE_SCANF_FN" => Some("c.scanf"),
        "CBR-C-INSECURE_USE_STRCAT_FN" => Some("c.strcat"),
        "CBR-C-INSECURE_USE_STRING_COPY_FN" => Some("c.strcpy"),
        "CBR-C-INSECURE_USE_STRTOK_FN" => Some("c.strtok"),
        "CBR-BASH-HOOKS_NO_INPUT_VALIDATION_BASH" => Some("bash.eval"),
        "CBR-BASH-HOOKS_RELATIVE_SCRIPT_PATH_BAS" => Some("bash.relative_script"),
        "CBR-BASH-HOOKS_UNQUOTED_VARIABLE_BASH_E" => Some("bash.eval"),
        "CBR-BASH-IFS_TAMPERING" => Some("bash.ifs"),
        "CBR-BASH-ITERATION_OVER_LS_OUTPUT" => Some("bash.for_loop"),
        "CBR-BASH-UNQUOTED_COMMAND_SUBSTITUTION_" => Some("bash.command_substitution"),
        "CBR-BASH-USELESS_CAT" => Some("bash.cat"),
        "CBR-JS-REACT-DANGEROUS-HTML" => Some("react.dangerously_set_inner_html"),
        "CBR-RUST-ARGS" => Some("rust.env.args"),
        "CBR-RUST-ARGS_OS" => Some("rust.env.args_os"),
        "CBR-RUST-CURRENT_EXE" => Some("rust.env.current_exe"),
        "CBR-RUST-INSECURE_HASHES" => Some("rust.crypto.insecure_hash"),
        "CBR-RUST-REQWEST_ACCEPT_INVALID" => Some("rust.reqwest.danger_accept_invalid_hostnames"),
        "CBR-RUST-REQWEST_SET_SENSITIVE" => Some("rust.reqwest.header_insert"),
        "CBR-RUST-RUSTLS_DANGEROUS" => Some("rust.rustls.dangerous_client_config"),
        "CBR-RUST-SSL_VERIFY_NONE" => Some("rust.openssl.ssl_verify_none"),
        "CBR-RUST-TEMP_DIR" => Some("rust.env.temp_dir"),
        "CBR-RUST-UNSAFE_USAGE" => Some("rust.unsafe_block"),
        "CBR-RUBY-AVOID_RAW" => Some("rails.raw"),
        "CBR-RUBY-AVOID_HTML_SAFE" => Some("rails.html_safe"),
        "CBR-RUBY-AVOID_RENDER_TEXT" => Some("rails.render_text"),
        "CBR-RUBY-AVOID_RENDER_INLINE" => Some("rails.render_inline"),
        "CBR-RUBY-AVOID_CONTENT_TAG" => Some("rails.content_tag"),
        "CBR-JAVA-SPRING_UNVALIDATED_REDIRECT" => Some("spring.redirect"),
        "CBR-JAVA-SPEL_INJECTION" => Some("spring.spel.parse_expression"),
        "CBR-JAVA-SCRIPT_ENGINE_INJECTION" => Some("java.script_engine.eval"),
        "CBR-JAVA-FIND_SQL_STRING_CONCATENATION" => Some("java.sql.prepare_statement"),
        "CBR-PYTH-EVAL_INJECTION" => Some("python.eval"),
        "CBR-PYTH-EXEC_INJECTION" => Some("python.exec"),
        "CBR-PYTH-SSRF_REQUESTS" => Some("python.requests"),
        "CBR-PYTH-OS_SYSTEM_INJECTION" => Some("python.os_system"),
        "CBR-PYTH-MAKE_RESPONSE_WITH_UNKNOWN_CON" => Some("flask.make_response"),
        "CBR-PYTH-RENDER_TEMPLATE_STRING" => Some("flask.render_template_string"),
        "CBR-PYTH-DANGEROUS_TEMPLATE_STRING" => Some("flask.render_template_string"),
        "CBR-PYTH-RESPONSE_CONTAINS_UNSANITIZED_" => Some("flask.make_response"),
        "CBR-PYTH-SQLALCHEMY_EXECUTE_RAW_QUERY" => Some("python.sqlalchemy.execute"),
        _ => None,
    };

    if let Some(sink_kind) = sink_kind {
        evidence.insert("sink_kind".into(), serde_json::json!(sink_kind));
    }

    match rule.id.as_str() {
        "CBR-PHP-ASSERT_USE_AUDIT"
        | "CBR-PHP-BACKTICKS_USE"
        | "CBR-PHP-EVAL_USE"
        | "CBR-PHP-EXEC_USE"
        | "CBR-PHP-FTP_USE"
        | "CBR-PHP-MB_EREG_REPLACE_EVAL"
        | "CBR-PHP-OPENSSL_DECRYPT_VALIDATE"
        | "CBR-PHP-PHP_PERMISSIVE_CORS"
        | "CBR-PHP-PHPINFO_USE"
        | "CBR-PHP-SYMFONY_NON_LITERAL_REDIRECT"
        | "CBR-PHP-UNLINK_USE"
        | "CBR-PHP-UNSERIALIZE_USE"
        | "CBR-PHP-WP_OPEN_REDIRECT_AUDIT" => {
            if semantics.frameworks.contains("laravel") {
                evidence.insert("framework".into(), serde_json::json!("laravel"));
            } else if semantics.frameworks.contains("symfony") {
                evidence.insert("framework".into(), serde_json::json!("symfony"));
            } else if semantics.frameworks.contains("wordpress") {
                evidence.insert("framework".into(), serde_json::json!("wordpress"));
            }
            if let Some(source_kind) = regex_source_kind(lang, snippet, semantics) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                return (evidence, Some("reachable".into()));
            }
            evidence.insert("path_sensitivity".into(), serde_json::json!("reachable"));
            return (evidence, Some("reachable".into()));
        }
        "CBR-SWIF-DETECT_APPLE_CORE_ML"
        | "CBR-SWIF-DETECT_GEMINI"
        | "CBR-SWIF-INSECURE_RANDOM"
        | "CBR-SWIF-SWIFT_WEBVIEW_CONFIG_ALLOWS_JS" => {
            if semantics.frameworks.contains("gemini") {
                evidence.insert("framework".into(), serde_json::json!("gemini"));
            } else if semantics.frameworks.contains("apple_coreml") {
                evidence.insert("framework".into(), serde_json::json!("apple_coreml"));
            } else if semantics.frameworks.contains("webkit") {
                evidence.insert("framework".into(), serde_json::json!("webkit"));
            }
            evidence.insert("path_sensitivity".into(), serde_json::json!("reachable"));
            return (evidence, Some("reachable".into()));
        }
        "CBR-SCAL-DANGEROUS_SEQ_RUN"
        | "CBR-SCAL-DANGEROUS_SHELL_RUN"
        | "CBR-SCAL-DISPATCH_SSRF"
        | "CBR-SCAL-INSECURE_RANDOM"
        | "CBR-SCAL-NO_NULL_CIPHER"
        | "CBR-SCAL-RSA_PADDING_SET"
        | "CBR-SCAL-SCALA_JWT_HARDCODED_SECRET"
        | "CBR-SCAL-SCALA_SLICK_OVERRIDESQL_LITERA"
        | "CBR-SCAL-SCALA_SLICK_SQL_NON_LITERAL"
        | "CBR-SCAL-SCALAJ_HTTP_SSRF"
        | "CBR-SCAL-WEBSERVICE_SSRF" => {
            if let Some(source_kind) = regex_source_kind(lang, snippet, semantics) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                return (evidence, Some("reachable".into()));
            }
            if semantics.frameworks.contains("play") {
                evidence.insert("framework".into(), serde_json::json!("play"));
            } else if semantics.frameworks.contains("dispatch") {
                evidence.insert("framework".into(), serde_json::json!("dispatch"));
            } else if semantics.frameworks.contains("scalaj") {
                evidence.insert("framework".into(), serde_json::json!("scalaj"));
            }
            evidence.insert("path_sensitivity".into(), serde_json::json!("reachable"));
            return (evidence, Some("reachable".into()));
        }
        "CBR-C-C_STRING_EQUALITY"
        | "CBR-C-DOUBLE_GOTO"
        | "CBR-C-INCORRECT_USE_ATO_FN"
        | "CBR-C-INCORRECT_USE_SSCANF_FN"
        | "CBR-C-INFO_LEAK_ON_NON_FORMATED_STRI"
        | "CBR-C-INSECURE_USE_GETS_FN"
        | "CBR-C-INSECURE_USE_MEMSET"
        | "CBR-C-INSECURE_USE_SCANF_FN"
        | "CBR-C-INSECURE_USE_STRCAT_FN"
        | "CBR-C-INSECURE_USE_STRING_COPY_FN"
        | "CBR-C-INSECURE_USE_STRTOK_FN"
        | "CBR-BASH-HOOKS_NO_INPUT_VALIDATION_BASH"
        | "CBR-BASH-HOOKS_RELATIVE_SCRIPT_PATH_BAS"
        | "CBR-BASH-HOOKS_UNQUOTED_VARIABLE_BASH_E"
        | "CBR-BASH-IFS_TAMPERING"
        | "CBR-BASH-ITERATION_OVER_LS_OUTPUT"
        | "CBR-BASH-UNQUOTED_COMMAND_SUBSTITUTION_"
        | "CBR-BASH-USELESS_CAT" => {
            if let Some(source_kind) = regex_source_kind(lang, snippet, semantics) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                return (evidence, Some("reachable".into()));
            }
            evidence.insert("path_sensitivity".into(), serde_json::json!("reachable"));
            return (evidence, Some("reachable".into()));
        }
        "CBR-RUST-ARGS"
        | "CBR-RUST-ARGS_OS"
        | "CBR-RUST-CURRENT_EXE"
        | "CBR-RUST-INSECURE_HASHES"
        | "CBR-RUST-REQWEST_ACCEPT_INVALID"
        | "CBR-RUST-REQWEST_SET_SENSITIVE"
        | "CBR-RUST-RUSTLS_DANGEROUS"
        | "CBR-RUST-SSL_VERIFY_NONE"
        | "CBR-RUST-TEMP_DIR"
        | "CBR-RUST-UNSAFE_USAGE" => {
            if semantics.frameworks.contains("reqwest") {
                evidence.insert("framework".into(), serde_json::json!("reqwest"));
            } else if semantics.frameworks.contains("axum") {
                evidence.insert("framework".into(), serde_json::json!("axum"));
            } else if semantics.frameworks.contains("actix") {
                evidence.insert("framework".into(), serde_json::json!("actix"));
            } else if semantics.frameworks.contains("rocket") {
                evidence.insert("framework".into(), serde_json::json!("rocket"));
            }
            evidence.insert("path_sensitivity".into(), serde_json::json!("reachable"));
            return (evidence, Some("reachable".into()));
        }
        "CBR-JS-REACT-DANGEROUS-HTML" => {
            evidence.insert("framework".into(), serde_json::json!("react"));
            if let Some(sanitizer_kind) = regex_sanitizer_kind(rule.id.as_str(), snippet) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("guarded"));
                evidence.insert("sanitizer_kind".into(), serde_json::json!(sanitizer_kind));
                return (evidence, Some("unknown".into()));
            }
            if let Some(source_kind) = regex_source_kind(lang, snippet, semantics) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                return (evidence, Some("reachable".into()));
            }
            evidence.insert("path_sensitivity".into(), serde_json::json!("no_source_detected"));
            return (evidence, Some("unknown".into()));
        }
        "CBR-RUBY-AVOID_RAW"
        | "CBR-RUBY-AVOID_HTML_SAFE"
        | "CBR-RUBY-AVOID_RENDER_TEXT"
        | "CBR-RUBY-AVOID_RENDER_INLINE"
        | "CBR-RUBY-AVOID_CONTENT_TAG" => {
            evidence.insert("framework".into(), serde_json::json!("rails"));
            if let Some(sanitizer_kind) = regex_sanitizer_kind(rule.id.as_str(), snippet) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("guarded"));
                evidence.insert("sanitizer_kind".into(), serde_json::json!(sanitizer_kind));
                return (evidence, Some("unknown".into()));
            }
            if let Some((source_kind, guarded_kind, reason)) =
                regex_intra_file_flow(rule.id.as_str(), lang, source, match_start, snippet, semantics)
            {
                evidence.insert("path_sensitivity".into(), serde_json::json!(reason));
                match (source_kind, guarded_kind) {
                    (Some(source_kind), None) => {
                        evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                        return (evidence, Some("reachable".into()));
                    }
                    (None, Some(sanitizer_kind)) => {
                        evidence.insert("sanitizer_kind".into(), serde_json::json!(sanitizer_kind));
                        return (evidence, Some("unknown".into()));
                    }
                    _ => {
                        return (evidence, Some("unknown".into()));
                    }
                }
            }
            if let Some(source_kind) = regex_source_kind(lang, snippet, semantics) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                return (evidence, Some("reachable".into()));
            }
            evidence.insert("path_sensitivity".into(), serde_json::json!("no_source_detected"));
            return (evidence, Some("unknown".into()));
        }
        "CBR-JAVA-SPRING_UNVALIDATED_REDIRECT"
        | "CBR-JAVA-SPEL_INJECTION"
        | "CBR-JAVA-SCRIPT_ENGINE_INJECTION"
        | "CBR-JAVA-FIND_SQL_STRING_CONCATENATION" => {
            evidence.insert("framework".into(), serde_json::json!("spring"));
            if let Some(sanitizer_kind) = regex_sanitizer_kind(rule.id.as_str(), snippet) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("guarded"));
                evidence.insert("sanitizer_kind".into(), serde_json::json!(sanitizer_kind));
                return (evidence, Some("unknown".into()));
            }
            if let Some((source_kind, guarded_kind, reason)) =
                regex_intra_file_flow(rule.id.as_str(), lang, source, match_start, snippet, semantics)
            {
                evidence.insert("path_sensitivity".into(), serde_json::json!(reason));
                match (source_kind, guarded_kind) {
                    (Some(source_kind), None) => {
                        evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                        return (evidence, Some("reachable".into()));
                    }
                    (None, Some(sanitizer_kind)) => {
                        evidence.insert("sanitizer_kind".into(), serde_json::json!(sanitizer_kind));
                        return (evidence, Some("unknown".into()));
                    }
                    _ => {
                        return (evidence, Some("unknown".into()));
                    }
                }
            }
            if let Some(source_kind) = regex_source_kind(lang, snippet, semantics) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                return (evidence, Some("reachable".into()));
            }
            if semantics.frameworks.contains("spring") {
                evidence.insert("path_sensitivity".into(), serde_json::json!("no_source_detected"));
                return (evidence, Some("unknown".into()));
            }
        }
        "CBR-PYTH-MAKE_RESPONSE_WITH_UNKNOWN_CON"
        | "CBR-PYTH-EVAL_INJECTION"
        | "CBR-PYTH-EXEC_INJECTION"
        | "CBR-PYTH-SSRF_REQUESTS"
        | "CBR-PYTH-OS_SYSTEM_INJECTION"
        | "CBR-PYTH-RENDER_TEMPLATE_STRING"
        | "CBR-PYTH-DANGEROUS_TEMPLATE_STRING"
        | "CBR-PYTH-RESPONSE_CONTAINS_UNSANITIZED_"
        | "CBR-PYTH-SQLALCHEMY_EXECUTE_RAW_QUERY" => {
            if semantics.frameworks.contains("django") {
                evidence.insert("framework".into(), serde_json::json!("django"));
            } else {
                evidence.insert("framework".into(), serde_json::json!("flask"));
            }
            if let Some(sanitizer_kind) = regex_sanitizer_kind(rule.id.as_str(), snippet) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("guarded"));
                evidence.insert("sanitizer_kind".into(), serde_json::json!(sanitizer_kind));
                return (evidence, Some("unknown".into()));
            }
            if let Some(source_kind) = regex_source_kind(lang, snippet, semantics) {
                evidence.insert("path_sensitivity".into(), serde_json::json!("tainted"));
                evidence.insert("source_kind".into(), serde_json::json!(source_kind));
                return (evidence, Some("reachable".into()));
            }
            evidence.insert("path_sensitivity".into(), serde_json::json!("no_source_detected"));
            return (evidence, Some("unknown".into()));
        }
        _ => {}
    }

    (evidence, None)
}

fn regex_intra_file_flow(
    rule_id: &str,
    lang: Lang,
    source: &str,
    match_start: usize,
    snippet: &str,
    semantics: &FileSemantics,
) -> Option<(Option<String>, Option<String>, &'static str)> {
    let assign_re = regex_assignment_regex(lang)?;
    let mut tainted = semantics.tainted_identifiers.clone();
    let mut sanitized = semantics.sanitized_identifiers.clone();
    let prefix = &source[..match_start.min(source.len())];

    for raw_line in prefix.lines() {
        let line = regex_strip_comments(lang, raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let Some(caps) = assign_re.captures(line) else { continue };
        let ident = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
        let rhs = caps.get(2).map(|m| m.as_str()).unwrap_or("").trim();
        if ident.is_empty() || rhs.is_empty() {
            continue;
        }

        if let Some(source_kind) = direct_regex_source_kind(lang, rhs) {
            tainted.insert(ident.clone(), source_kind.to_string());
            sanitized.remove(&ident);
            continue;
        }

        if let Some(sanitizer_kind) = regex_local_sanitizer_kind(rule_id, lang, rhs, &tainted) {
            tainted.remove(&ident);
            sanitized.insert(ident, sanitizer_kind);
            continue;
        }

        if rhs.contains('(') && rhs.contains(')') {
            if let Some(sanitizer_kind) = semantics.sanitized_identifiers.get(&ident).cloned() {
                tainted.remove(&ident);
                sanitized.insert(ident, sanitizer_kind);
                continue;
            }
        }

        if let Some(source_kind) = regex_taint_from_tokens(rhs, &tainted) {
            tainted.insert(ident.clone(), source_kind);
            sanitized.remove(&ident);
            continue;
        }

        tainted.remove(&ident);
        sanitized.remove(&ident);
    }

    if let Some(source_kind) = direct_regex_source_kind(lang, snippet) {
        return Some((Some(source_kind.into()), None, "tainted"));
    }
    if let Some(sanitizer_kind) = regex_local_sanitizer_kind(rule_id, lang, snippet, &tainted) {
        return Some((None, Some(sanitizer_kind), "guarded"));
    }
    if let Some(sanitizer_kind) = regex_identifier_reason(snippet, &sanitized) {
        return Some((None, Some(sanitizer_kind), "guarded"));
    }
    if let Some(source_kind) = regex_taint_from_tokens(snippet, &tainted) {
        return Some((Some(source_kind), None, "tainted"));
    }
    if regex_contains_identifier(snippet, &tainted)
        || regex_contains_identifier(snippet, &sanitized)
        || regex_contains_nonliteral_identifier(lang, snippet)
    {
        return Some((None, None, "no_source_detected"));
    }
    None
}

fn regex_sanitizer_kind(rule_id: &str, snippet: &str) -> Option<&'static str> {
    match rule_id {
        "CBR-JS-REACT-DANGEROUS-HTML" => {
            if snippet.contains("DOMPurify.sanitize(") {
                return Some("dompurify");
            }
            if snippet.contains("escapeHtml(") || snippet.contains("he.encode(") {
                return Some("html_escape");
            }
        }
        "CBR-RUBY-AVOID_RAW"
        | "CBR-RUBY-AVOID_HTML_SAFE"
        | "CBR-RUBY-AVOID_RENDER_TEXT"
        | "CBR-RUBY-AVOID_RENDER_INLINE"
        | "CBR-RUBY-AVOID_CONTENT_TAG" => {
            if snippet.contains("sanitize(") {
                return Some("rails.sanitize");
            }
            if snippet.contains("strip_tags(") {
                return Some("rails.strip_tags");
            }
            if snippet.contains("ERB::Util.html_escape(") || snippet.contains("h(") {
                return Some("rails.html_escape");
            }
        }
        "CBR-PYTH-MAKE_RESPONSE_WITH_UNKNOWN_CON"
        | "CBR-PYTH-RENDER_TEMPLATE_STRING"
        | "CBR-PYTH-DANGEROUS_TEMPLATE_STRING"
        | "CBR-PYTH-RESPONSE_CONTAINS_UNSANITIZED_" => {
            if snippet.contains("format_html(") {
                return Some("django.format_html");
            }
            if snippet.contains("conditional_escape(") {
                return Some("django.conditional_escape");
            }
            if snippet.contains("flask.escape(") {
                return Some("flask.escape");
            }
            if snippet.contains("markupsafe.escape(") {
                return Some("markupsafe.escape");
            }
            if snippet.contains("django.utils.html.escape(") || snippet.contains("html.escape(") {
                return Some("html.escape");
            }
            if rule_id == "CBR-PYTH-MAKE_RESPONSE_WITH_UNKNOWN_CON" && snippet.contains("jsonify(") {
                return Some("flask.jsonify");
            }
        }
        "CBR-JAVA-SPRING_UNVALIDATED_REDIRECT" => {
            if snippet.contains("UriUtils.encode(") || snippet.contains("URLEncoder.encode(") {
                return Some("spring.url_encode");
            }
            if snippet.contains("UriComponentsBuilder.") {
                return Some("spring.uri_components_builder");
            }
        }
        "CBR-JAVA-SPEL_INJECTION" => {
            if snippet.contains("SimpleEvaluationContext") {
                return Some("spring.simple_evaluation_context");
            }
        }
        "CBR-JAVA-FIND_SQL_STRING_CONCATENATION" => {
            if snippet.contains('?') && snippet.contains("prepareStatement(") {
                return Some("java.prepared_statement_parameterization");
            }
        }
        _ => {}
    }
    None
}

fn regex_source_kind(
    lang: Lang,
    snippet: &str,
    semantics: &FileSemantics,
) -> Option<String> {
    if let Some(kind) = direct_regex_source_kind(lang, snippet) {
        return Some(kind.into());
    }

    for token in snippet.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' || c == '$')) {
        if let Some(kind) = semantics.tainted_identifiers.get(token) {
            return Some(kind.clone());
        }
    }
    None
}

fn direct_regex_source_kind(lang: Lang, snippet: &str) -> Option<&'static str> {
    match lang {
        Lang::Javascript | Lang::Typescript => {
            let compact: String = snippet.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.contains("req.query.") || compact.contains("request.query.") {
                return Some("express.req.query");
            }
            if compact.contains("req.params.") || compact.contains("request.params.") {
                return Some("express.req.params");
            }
            if compact.contains("req.body.") || compact.contains("request.body.") {
                return Some("express.req.body");
            }
        }
        Lang::Ruby => {
            if snippet.contains("params[") || snippet.contains("params.") {
                return Some("rails.params");
            }
        }
        Lang::Java => {
            if snippet.contains("request.getParameter(") {
                return Some("spring.http_request_parameter");
            }
        }
        Lang::Go => {
            let compact: String = snippet.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.contains(".Query(") || compact.contains(".URL.Query().Get(") {
                return Some("go.http.query");
            }
            if compact.contains(".Param(") {
                return Some("go.http.param");
            }
            if compact.contains(".FormValue(") {
                return Some("go.http.form");
            }
        }
        Lang::Python => {
            let compact: String = snippet.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.contains("request.args.get(") || compact.contains("flask.request.args.get(") {
                return Some("flask.request.args");
            }
            if compact.contains("request.form.get(") || compact.contains("flask.request.form.get(") {
                return Some("flask.request.form");
            }
            if compact.contains("request.GET.get(") || compact.contains("request.GET[") {
                return Some("django.request.GET");
            }
            if compact.contains("request.POST.get(") || compact.contains("request.POST[") {
                return Some("django.request.POST");
            }
            if compact.contains("input(") {
                return Some("python.input");
            }
        }
        Lang::Rust => {
            let compact: String = snippet.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.contains("std::env::args()") {
                return Some("rust.env.args");
            }
            if compact.contains("std::env::args_os()") {
                return Some("rust.env.args_os");
            }
            if compact.contains("std::env::var(") || compact.contains("std::env::var_os(") {
                return Some("rust.env.var");
            }
        }
        Lang::Php => {
            let compact: String = snippet.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.contains("$_GET[") || compact.contains("$_GET") {
                return Some("php.request.get");
            }
            if compact.contains("$_POST[") || compact.contains("$_POST") {
                return Some("php.request.post");
            }
            if compact.contains("$_REQUEST[") || compact.contains("$_REQUEST") {
                return Some("php.request.request");
            }
            if compact.contains("$_COOKIE[") || compact.contains("$_COOKIE") {
                return Some("php.request.cookie");
            }
        }
        Lang::Scala => {
            let compact: String = snippet.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.contains("request.getParameter(") || compact.contains("request.getQueryString(") {
                return Some("scala.http.request_parameter");
            }
            if compact.contains("request.queryString") {
                return Some("scala.http.query_string");
            }
        }
        Lang::C => {
            let compact: String = snippet.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.contains("argv[") {
                return Some("c.argv");
            }
            if compact.contains("getenv(") {
                return Some("c.getenv");
            }
        }
        Lang::Bash => {
            let compact: String = snippet.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.contains("$1") || compact.contains("${1}") {
                return Some("bash.positional_arg");
            }
            if compact.contains("$@") || compact.contains("$*") {
                return Some("bash.positional_args");
            }
        }
        _ => {}
    }
    None
}

fn regex_assignment_regex(lang: Lang) -> Option<Regex> {
    match lang {
        Lang::Ruby => Some(Regex::new(r#"^\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*=\s*(.+?)\s*$"#).unwrap()),
        Lang::Java => Some(Regex::new(r#"^\s*(?:[A-Za-z_][A-Za-z0-9_<>\[\]\.?]*\s+)?([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*=\s*(.+?)\s*;?\s*$"#).unwrap()),
        Lang::Go => Some(Regex::new(r#"^\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*(?::=|=)\s*(.+?)\s*$"#).unwrap()),
        _ => None,
    }
}

fn regex_strip_comments(lang: Lang, raw_line: &str) -> &str {
    match lang {
        Lang::Ruby => raw_line.split('#').next().unwrap_or(""),
        _ => raw_line.split("//").next().unwrap_or(""),
    }
}

fn regex_local_sanitizer_kind(
    rule_id: &str,
    lang: Lang,
    text: &str,
    tainted: &HashMap<String, String>,
) -> Option<String> {
    if !regex_contains_identifier(text, tainted) {
        return None;
    }
    if let Some(kind) = regex_sanitizer_kind(rule_id, text) {
        return Some(kind.into());
    }
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    match lang {
        Lang::Java => {
            if compact.contains("HtmlUtils.htmlEscape(") || compact.contains("ESAPI.encoder().encodeForHTML(") {
                return Some("java_html_encoded".into());
            }
        }
        Lang::Ruby => {
            if compact.contains("ERB::Util.html_escape(") || compact.contains("html_escape(") || compact.contains("h(") {
                return Some("rails.html_escape".into());
            }
        }
        Lang::Go => {
            if compact.contains("template.HTMLEscapeString(") {
                return Some("go.html_escape".into());
            }
            if compact.contains("url.QueryEscape(") || compact.contains("template.URLQueryEscaper(") {
                return Some("go.url_escape".into());
            }
        }
        _ => {}
    }
    None
}

fn regex_taint_from_tokens(text: &str, tainted: &HashMap<String, String>) -> Option<String> {
    for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' || c == '$')) {
        if let Some(kind) = tainted.get(token) {
            return Some(kind.clone());
        }
    }
    None
}

fn regex_contains_identifier(text: &str, values: &HashMap<String, String>) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' || c == '$'))
        .any(|token| values.contains_key(token))
}

fn regex_identifier_reason(text: &str, values: &HashMap<String, String>) -> Option<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' || c == '$'))
        .find_map(|token| values.get(token).cloned())
}

fn regex_contains_nonliteral_identifier(lang: Lang, text: &str) -> bool {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' || c == '$'))
        .any(|token| {
            !token.is_empty()
                && token.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && !regex_ignored_identifier(lang, token)
        })
}

fn regex_ignored_identifier(lang: Lang, token: &str) -> bool {
    match lang {
        Lang::Java => matches!(token, "return" | "redirect" | "request" | "getParameter" | "HtmlUtils" | "htmlEscape" | "ESAPI" | "encodeForHTML" | "URLEncoder" | "encode" | "UriUtils" | "prepareStatement" | "eval"),
        Lang::Ruby => matches!(token, "raw" | "params" | "content_tag" | "render" | "inline" | "text" | "sanitize" | "strip_tags" | "html_escape" | "ERB" | "Util" | "html_safe"),
        Lang::Go => matches!(token, "exec" | "Command" | "CommandContext" | "Query" | "QueryRow" | "Exec" | "fmt" | "Sprintf" | "template" | "url"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::semantics;

    #[test]
    fn spring_spel_annotation_uses_request_param_taint() {
        let rule = Rule {
            id: "CBR-JAVA-SPEL_INJECTION".into(),
            title: "Spel Injection".into(),
            severity: crate::finding::Severity::High,
            languages: vec![Lang::Java],
            query: None,
            regex: None,
            pattern: Some("$X $METHOD(...) { ... $PARSER.parseExpression(...); ... }".into()),
            message: "msg".into(),
            fix_recipe: None,
            fix: None,
            dependency: None,
            cwe: vec!["CWE-94".into()],
            frameworks: vec![],
            source: None,
            patterns: vec![],
            pattern_not: None,
            pattern_inside: None,
            cia: None,
        };
        let source = "import org.springframework.web.bind.annotation.RequestParam;\nclass Controller { String go(@RequestParam String expr) { parser.parseExpression(expr); return expr; } }\n";
        let semantics = semantics::extract(Lang::Java, source);
        let (evidence, reachability) = annotate_regex_finding(
            &rule,
            Lang::Java,
            source,
            source.find("parser.parseExpression(expr);").unwrap_or(0),
            "parser.parseExpression(expr);",
            &semantics,
        );

        assert_eq!(reachability.as_deref(), Some("reachable"));
        assert_eq!(evidence.get("framework").and_then(|v| v.as_str()), Some("spring"));
        assert_eq!(evidence.get("sink_kind").and_then(|v| v.as_str()), Some("spring.spel.parse_expression"));
        assert_eq!(evidence.get("source_kind").and_then(|v| v.as_str()), Some("spring.request_param"));
    }

    #[test]
    fn python_eval_annotation_uses_flask_request_taint() {
        let rule = Rule {
            id: "CBR-PYTH-EVAL_INJECTION".into(),
            title: "Eval Injection".into(),
            severity: crate::finding::Severity::Critical,
            languages: vec![Lang::Python],
            query: None,
            regex: None,
            pattern: Some("eval(..., <... flask.request.$W.get(...) ...>, ...)".into()),
            message: "msg".into(),
            fix_recipe: None,
            fix: None,
            dependency: None,
            cwe: vec!["CWE-95".into()],
            frameworks: vec![],
            source: None,
            patterns: vec![],
            pattern_not: None,
            pattern_inside: None,
            cia: None,
        };
        let source = "import flask\npayload = flask.request.args.get('code')\n";
        let semantics = semantics::extract(Lang::Python, source);
        let (evidence, reachability) = annotate_regex_finding(
            &rule,
            Lang::Python,
            source,
            0,
            "eval(payload)",
            &semantics,
        );

        assert_eq!(reachability.as_deref(), Some("reachable"));
        assert_eq!(evidence.get("framework").and_then(|v| v.as_str()), Some("flask"));
        assert_eq!(evidence.get("sink_kind").and_then(|v| v.as_str()), Some("python.eval"));
        assert_eq!(evidence.get("source_kind").and_then(|v| v.as_str()), Some("flask.request.args"));
    }

    #[test]
    fn byte_to_line_col_maps_offsets() {
        let source = "one\ntwo\nthree";
        assert_eq!(byte_to_line_col(source, 0), (1, 1));
        assert_eq!(byte_to_line_col(source, 4), (2, 1));
        assert_eq!(byte_to_line_col(source, source.len()), (3, 6));
    }

    #[test]
    fn spring_redirect_special_case_matches_annotated_param() {
        let rule = Rule {
            id: "CBR-JAVA-SPRING_UNVALIDATED_REDIRECT".into(),
            title: "Spring Unvalidated Redirect".into(),
            severity: crate::finding::Severity::High,
            languages: vec![Lang::Java],
            query: None,
            regex: None,
            pattern: Some("$X $METHOD(...,String $URL,...) { return \"redirect:\" + $URL; }".into()),
            message: "msg".into(),
            fix_recipe: None,
            fix: None,
            dependency: None,
            cwe: vec!["CWE-601".into()],
            frameworks: vec![],
            source: None,
            patterns: vec![],
            pattern_not: None,
            pattern_inside: None,
            cia: None,
        };
        let source = "import org.springframework.web.bind.annotation.RequestParam;\nclass Controller { String go(@RequestParam String next) { return \"redirect:\" + next; } }\n";
        let semantics = semantics::extract(Lang::Java, source);
        let findings = special_case_findings(&rule, Lang::Java, Path::new("Controller.java"), source, &semantics);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence.get("source_kind").and_then(|v| v.as_str()), Some("spring.request_param"));
    }

    #[test]
    fn spring_script_engine_special_case_matches_annotated_param() {
        let rule = Rule {
            id: "CBR-JAVA-SCRIPT_ENGINE_INJECTION".into(),
            title: "Script Engine Injection".into(),
            severity: crate::finding::Severity::High,
            languages: vec![Lang::Java],
            query: None,
            regex: None,
            pattern: Some("$SE.eval(...)".into()),
            message: "msg".into(),
            fix_recipe: None,
            fix: None,
            dependency: None,
            cwe: vec!["CWE-94".into()],
            frameworks: vec![],
            source: None,
            patterns: vec![],
            pattern_not: None,
            pattern_inside: None,
            cia: None,
        };
        let source = "import org.springframework.web.bind.annotation.RequestParam;\nclass Controller { String go(@RequestParam String expr) { engine.eval(expr); return expr; } }\n";
        let semantics = semantics::extract(Lang::Java, source);
        let findings = special_case_findings(&rule, Lang::Java, Path::new("Controller.java"), source, &semantics);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence.get("source_kind").and_then(|v| v.as_str()), Some("spring.request_param"));
        assert_eq!(findings[0].evidence.get("sink_kind").and_then(|v| v.as_str()), Some("java.script_engine.eval"));
    }

    #[test]
    fn spring_sql_prepare_statement_special_case_uses_tainted_query() {
        let rule = Rule {
            id: "CBR-JAVA-FIND_SQL_STRING_CONCATENATION".into(),
            title: "SQL string concatenation".into(),
            severity: crate::finding::Severity::Critical,
            languages: vec![Lang::Java],
            query: None,
            regex: None,
            pattern: Some("PreparedStatement $PS = $SESSION.connection().prepareStatement($QUERY);".into()),
            message: "msg".into(),
            fix_recipe: None,
            fix: None,
            dependency: None,
            cwe: vec!["CWE-89".into()],
            frameworks: vec![],
            source: None,
            patterns: vec![],
            pattern_not: None,
            pattern_inside: None,
            cia: None,
        };
        let source = "import org.springframework.web.bind.annotation.RequestParam;\nclass Controller {\n  void run(@RequestParam String user, Connection conn) throws Exception {\n    String query = \"select * from t where user='\" + user + \"'\";\n    PreparedStatement ps = conn.prepareStatement(query);\n  }\n}\n";
        let semantics = semantics::extract(Lang::Java, source);
        let findings = special_case_findings(&rule, Lang::Java, Path::new("Controller.java"), source, &semantics);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence.get("source_kind").and_then(|v| v.as_str()), Some("spring.request_param"));
        assert_eq!(findings[0].evidence.get("sink_kind").and_then(|v| v.as_str()), Some("java.sql.prepare_statement"));
    }

    #[test]
    fn spring_redirect_sanitizer_is_recognized() {
        assert_eq!(
            regex_sanitizer_kind("CBR-JAVA-SPRING_UNVALIDATED_REDIRECT", r#"return "redirect:" + URLEncoder.encode(next)"#),
            Some("spring.url_encode")
        );
    }

    #[test]
    fn django_format_html_sanitizer_is_recognized() {
        assert_eq!(
            regex_sanitizer_kind("CBR-PYTH-MAKE_RESPONSE_WITH_UNKNOWN_CON", r#"flask.make_response(format_html("{}", value))"#),
            Some("django.format_html")
        );
    }

    #[test]
    fn patterns_all_of_and_pattern_not_filter_matches() {
        let rule = Rule {
            id: "CBR-TEST-REGEX-PATTERNS".into(),
            title: "Regex DSL".into(),
            severity: crate::finding::Severity::Medium,
            languages: vec![Lang::Python],
            query: None,
            regex: None,
            pattern: None,
            patterns: vec!["eval(".into(), "user".into()],
            pattern_not: Some("ast.literal_eval(".into()),
            pattern_inside: None,
            message: "msg".into(),
            fix_recipe: None,
            fix: None,
            dependency: None,
            cwe: vec![],
            frameworks: vec![],
            source: None,
            cia: None,
        };
        let semantics = semantics::extract(Lang::Python, "user = input()\n");
        let findings = match_rule(&rule, Lang::Python, Path::new("x.py"), "eval(user)\nast.literal_eval(user)\n", &semantics);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].snippet, "eval(user)");
    }

    #[test]
    fn pattern_inside_requires_enclosing_context() {
        let rule = Rule {
            id: "CBR-TEST-REGEX-INSIDE".into(),
            title: "Regex inside".into(),
            severity: crate::finding::Severity::Medium,
            languages: vec![Lang::Python],
            query: None,
            regex: Some(r"eval\(user\)".into()),
            pattern: None,
            patterns: vec![],
            pattern_not: None,
            pattern_inside: Some("def dangerous".into()),
            message: "msg".into(),
            fix_recipe: None,
            fix: None,
            dependency: None,
            cwe: vec![],
            frameworks: vec![],
            source: None,
            cia: None,
        };
        let semantics = semantics::extract(Lang::Python, "");
        let source = "def dangerous():\n    eval(user)\n\ndef safe():\n    eval(user)\n";
        let findings = match_rule(&rule, Lang::Python, Path::new("x.py"), source, &semantics);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
    }
}
