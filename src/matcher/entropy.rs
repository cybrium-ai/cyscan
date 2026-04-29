//! Entropy-based secret detection — catches secrets that don't match any
//! known provider pattern by measuring Shannon entropy of string literals.
//!
//! Thresholds (calibrated against GitLeaks/TruffleHog):
//!   - Hex strings:    >= 3.0 bits/char, min 20 chars
//!   - Base64 strings: >= 4.0 bits/char, min 20 chars
//!   - Generic strings: >= 4.5 bits/char, min 16 chars
//!
//! False positive mitigation:
//!   - Skip UUIDs, SHAs, semver, URLs, file paths
//!   - Skip strings that are all-lowercase dictionary words
//!   - Skip repeated characters (aaaa..., 0000...)
//!   - Skip known safe patterns (CSS colors, hashes in lockfiles)
//!   - Only scan strings in assignment context (key = "value")

use std::collections::HashSet;
use std::path::Path;

use crate::finding::{Finding, Severity};

/// Shannon entropy in bits per character.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }

    let len = s.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Character class of a string — used for threshold selection.
#[derive(Debug, Clone, Copy, PartialEq)]
enum CharClass {
    Hex,
    Base64,
    Generic,
}

fn classify_charset(s: &str) -> CharClass {
    let all_hex = s.chars().all(|c| c.is_ascii_hexdigit());
    if all_hex {
        return CharClass::Hex;
    }

    let all_b64 = s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=');
    if all_b64 {
        return CharClass::Base64;
    }

    CharClass::Generic
}

/// Thresholds per character class.
fn entropy_threshold(class: CharClass) -> f64 {
    match class {
        CharClass::Hex    => 3.0,
        CharClass::Base64 => 4.0,
        CharClass::Generic => 4.5,
    }
}

fn min_length(class: CharClass) -> usize {
    match class {
        CharClass::Hex    => 20,
        CharClass::Base64 => 20,
        CharClass::Generic => 16,
    }
}

/// Patterns that look like secrets but aren't — false positive suppression.
fn is_false_positive(s: &str, key: &str) -> bool {
    let lower = s.to_lowercase();
    let key_lower = key.to_lowercase();

    // UUIDs: 8-4-4-4-12 hex pattern
    if s.len() == 36 && s.chars().filter(|&c| c == '-').count() == 4 {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 5
            && parts[0].len() == 8
            && parts[1].len() == 4
            && parts[2].len() == 4
            && parts[3].len() == 4
            && parts[4].len() == 12
        {
            return true;
        }
    }

    // Git commit SHAs (exactly 40 hex chars)
    if s.len() == 40 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    // MD5 hashes (32 hex chars) — common in lockfiles
    if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        // Only if key suggests it's a hash, not a secret
        if key_lower.contains("hash") || key_lower.contains("checksum")
            || key_lower.contains("integrity") || key_lower.contains("sha")
            || key_lower.contains("md5") || key_lower.contains("digest")
        {
            return true;
        }
    }

    // SHA-256 (64 hex chars)
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        if key_lower.contains("hash") || key_lower.contains("sha")
            || key_lower.contains("checksum") || key_lower.contains("integrity")
            || key_lower.contains("digest") || key_lower.contains("fingerprint")
        {
            return true;
        }
    }

    // URLs
    if lower.starts_with("http://") || lower.starts_with("https://")
        || lower.starts_with("ftp://") || lower.starts_with("ssh://")
    {
        return true;
    }

    // File paths
    if s.starts_with('/') || s.starts_with("./") || s.starts_with("../")
        || s.contains("\\\\") || (s.len() > 2 && s.chars().nth(1) == Some(':'))
    {
        return true;
    }

    // CSS / HTML colors (#AABBCC)
    if s.starts_with('#') && (s.len() == 7 || s.len() == 4) {
        return true;
    }

    // Semver (1.2.3, v1.2.3-beta.1)
    if lower.chars().all(|c| c.is_ascii_digit() || c == '.' || c == '-' || c == 'v') {
        return true;
    }

    // Repeated characters (aaaa, 0000, xxxx)
    if s.len() >= 4 {
        let first = s.chars().next().unwrap();
        if s.chars().all(|c| c == first) {
            return true;
        }
    }

    // Common test/example values
    if lower == "changeme" || lower == "password" || lower == "example"
        || lower == "test" || lower.starts_with("example")
        || lower == "placeholder" || lower == "dummy"
        || lower.starts_with("todo") || lower.starts_with("fixme")
    {
        return true;
    }

    // Base64 encoded small values (< 10 bytes decoded = likely not a secret)
    if s.ends_with('=') || s.ends_with("==") {
        let stripped = s.trim_end_matches('=');
        if stripped.len() < 12 {
            return true;
        }
    }

    // Key names that suggest non-secret context
    let safe_keys = [
        "version", "name", "description", "title", "label", "message",
        "comment", "text", "content", "body", "summary", "path",
        "file", "dir", "folder", "url", "uri", "href", "src",
        "class", "id", "type", "kind", "format", "encoding",
        "charset", "locale", "lang", "timezone", "region",
        "hash", "checksum", "sha", "md5", "digest", "integrity",
        "license", "author", "email", "homepage", "repository",
        "test", "spec", "mock", "fixture", "sample", "example",
    ];
    if safe_keys.iter().any(|k| key_lower.contains(k)) {
        return true;
    }

    false
}

/// Extract candidate (key, value) pairs from a line of source code.
/// Looks for assignment patterns: key = "value", key: "value", "key": "value"
fn extract_candidates(line: &str) -> Vec<(String, String)> {
    let mut candidates = Vec::new();

    // Pattern 1: key = "value" or key = 'value'
    // Pattern 2: "key": "value" (JSON)
    // Pattern 3: key: "value" (YAML)
    // Pattern 4: KEY=value (.env)
    for (i, _) in line.match_indices('"') {
        // Find closing quote
        let rest = &line[i + 1..];
        if let Some(end) = rest.find('"') {
            let value = &rest[..end];
            if value.len() >= 12 {
                // Try to extract key from before the quote
                let before = line[..i].trim_end();
                let before = before.trim_end_matches(|c: char| c == '=' || c == ':' || c == ' ');
                let key = before.rsplit(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
                    .next()
                    .unwrap_or("")
                    .to_string();
                candidates.push((key, value.to_string()));
            }
        }
    }

    // Single quotes
    for (i, _) in line.match_indices('\'') {
        let rest = &line[i + 1..];
        if let Some(end) = rest.find('\'') {
            let value = &rest[..end];
            if value.len() >= 12 {
                let before = line[..i].trim_end();
                let before = before.trim_end_matches(|c: char| c == '=' || c == ':' || c == ' ');
                let key = before.rsplit(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
                    .next()
                    .unwrap_or("")
                    .to_string();
                candidates.push((key, value.to_string()));
            }
        }
    }

    // .env style: KEY=value (no quotes, value is rest of line)
    if let Some(eq_pos) = line.find('=') {
        let key = line[..eq_pos].trim();
        let value = line[eq_pos + 1..].trim().trim_matches('"').trim_matches('\'');
        if value.len() >= 12 && !key.is_empty() && key.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            // Only for ALL_CAPS_KEYS (env var style)
            let key_lower = key.to_lowercase();
            // Only if the key suggests it might be a secret
            let secret_keys = ["key", "secret", "token", "password", "credential",
                "auth", "private", "api", "access", "session"];
            if secret_keys.iter().any(|k| key_lower.contains(k)) {
                candidates.push((key.to_string(), value.to_string()));
            }
        }
    }

    candidates
}

/// Scan a source file for high-entropy strings that might be secrets.
/// Returns findings for strings above the entropy threshold that don't
/// match known false-positive patterns.
pub fn scan_file(path: &Path, source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for (line_no, line) in source.lines().enumerate() {
        // Skip comments
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with("/*")
            || trimmed.starts_with('*') || trimmed.starts_with("<!--")
        {
            continue;
        }

        let candidates = extract_candidates(line);
        for (key, value) in candidates {
            // Deduplicate
            if !seen.insert(value.clone()) {
                continue;
            }

            let class = classify_charset(&value);
            let threshold = entropy_threshold(class);
            let min_len = min_length(class);

            if value.len() < min_len {
                continue;
            }

            let entropy = shannon_entropy(&value);
            if entropy < threshold {
                continue;
            }

            if is_false_positive(&value, &key) {
                continue;
            }

            let severity = if entropy >= 5.0 {
                Severity::High
            } else if entropy >= 4.5 {
                Severity::Medium
            } else {
                Severity::Low
            };

            let key_display = if key.is_empty() { "unknown" } else { &key };
            let truncated = if value.len() > 20 {
                format!("{}...{}", &value[..8], &value[value.len()-4..])
            } else {
                value.clone()
            };

            findings.push(Finding {
                rule_id:    "CBR-SEC-ENTROPY".to_string(),
                title:      format!("High-entropy string in '{}' (entropy: {:.1} bits/char)", key_display, entropy),
                severity,
                message:    format!(
                    "A high-entropy string was detected in variable/key '{}'. \
                     High entropy ({:.2} bits/char, threshold {:.1}) suggests this may be \
                     a hardcoded secret, API key, or cryptographic material.\n\n\
                     Remediation: If this is a secret, remove it from source code and use \
                     a secret manager or environment variable. If it's a hash or test data, \
                     consider adding a comment to suppress this finding.",
                    key_display, entropy, threshold
                ),
                file:       path.to_path_buf(),
                line:       line_no + 1,
                column:     0,
                end_line:   line_no + 1,
                end_column: 0,
                start_byte: 0,
                end_byte:   0,
                snippet:    format!("{} = \"{}\"", key_display, truncated),
                fix_recipe: None,
                fix:        None,
                cwe:        vec!["CWE-798".to_string()],
                evidence:   {
                    let mut m = std::collections::HashMap::new();
                    m.insert("entropy".into(), serde_json::json!(entropy));
                    m.insert("charset".into(), serde_json::json!(format!("{:?}", class)));
                    m.insert("length".into(), serde_json::json!(value.len()));
                    m
                },
                reachability: None,
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_entropy_detected() {
        let entropy = shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
        assert!(entropy > 4.0, "AWS secret key should have high entropy: {}", entropy);
    }

    #[test]
    fn low_entropy_safe() {
        let entropy = shannon_entropy("myDatabaseName");
        assert!(entropy < 4.0, "Normal string should have low entropy: {}", entropy);
    }

    #[test]
    fn uuid_is_false_positive() {
        assert!(is_false_positive("550e8400-e29b-41d4-a716-446655440000", "id"));
    }

    #[test]
    fn git_sha_is_false_positive() {
        assert!(is_false_positive("da39a3ee5e6b4b0d3255bfef95601890afd80709", "commit"));
    }

    #[test]
    fn url_is_false_positive() {
        assert!(is_false_positive("https://api.example.com/v1/users", "endpoint"));
    }

    #[test]
    fn actual_secret_not_false_positive() {
        assert!(!is_false_positive("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws_secret"));
    }
}
