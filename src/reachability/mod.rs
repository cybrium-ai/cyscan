//! Reachability analysis — traces import chains from application code
//! to vulnerable functions in dependencies.
//!
//! Given a CVE finding with `vulnerable_symbols` (e.g., `yaml.load`,
//! `requests.get`), this module answers: "Does any code in this repo
//! actually call the vulnerable function?"
//!
//! Result per finding: `Reachable` / `Unreachable` / `Unknown`.
//!
//! Language support:
//!   - Python: import + from...import + function call tracing
//!   - JavaScript/TypeScript: require/import + call site analysis
//!   - Go: package import + function call
//!   - Java: import + method invocation
//!   - Other: regex-based heuristic (lower confidence)

mod import_resolver;

use std::path::Path;

use crate::finding::Finding;

/// Reachability verdict for a single finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The vulnerable symbol is imported and called in application code.
    Reachable,
    /// The package is imported but the vulnerable symbol is never called.
    Unreachable,
    /// Could not determine — analysis was inconclusive.
    Unknown,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Reachable => write!(f, "reachable"),
            Verdict::Unreachable => write!(f, "unreachable"),
            Verdict::Unknown => write!(f, "unknown"),
        }
    }
}

/// Result of reachability analysis for one vulnerability.
#[derive(Debug)]
pub struct ReachabilityResult {
    pub finding_rule_id: String,
    pub package: String,
    pub vulnerable_symbols: Vec<String>,
    pub verdict: Verdict,
    /// Confidence 0.0–1.0. Higher = more certain.
    pub confidence: f64,
    /// Call chain: [("src/main.py:12", "import yaml"), ("src/main.py:45", "yaml.load(...)")]
    pub call_chain: Vec<(String, String)>,
}

/// Analyze reachability for a set of SCA findings against a codebase.
///
/// Looks at each finding's vulnerable symbols and traces whether
/// the application code imports the package and calls those symbols.
pub fn analyze(
    target: &Path,
    findings: &[Finding],
) -> Vec<ReachabilityResult> {
    let mut results = Vec::new();

    // Build import index for the entire codebase once
    let import_index = import_resolver::build_import_index(target);
    log::info!(
        "reachability: indexed {} imports across {} files",
        import_index.total_imports(),
        import_index.file_count(),
    );

    for finding in findings {
        // Only analyze SCA/advisory findings (they have package + vulnerable symbols)
        let package = extract_package_name(finding);
        if package.is_empty() {
            continue;
        }

        let vulnerable_symbols = extract_vulnerable_symbols(finding);

        let (verdict, confidence, call_chain) = if vulnerable_symbols.is_empty() {
            // No specific symbols — check if package is imported at all
            if import_index.is_package_imported(&package) {
                (Verdict::Reachable, 0.5, import_index.get_import_sites(&package))
            } else {
                (Verdict::Unreachable, 0.9, Vec::new())
            }
        } else {
            // Check if any vulnerable symbol is called
            let mut found_chain = Vec::new();
            let mut any_reachable = false;

            for symbol in &vulnerable_symbols {
                if let Some(chain) = import_index.find_call_chain(&package, symbol) {
                    found_chain = chain;
                    any_reachable = true;
                    break;
                }
            }

            if any_reachable {
                (Verdict::Reachable, 0.9, found_chain)
            } else if import_index.is_package_imported(&package) {
                // Package is imported but vulnerable function not called
                (Verdict::Unreachable, 0.8, import_index.get_import_sites(&package))
            } else {
                // Package not even imported
                (Verdict::Unreachable, 0.95, Vec::new())
            }
        };

        results.push(ReachabilityResult {
            finding_rule_id: finding.rule_id.clone(),
            package: package.clone(),
            vulnerable_symbols: vulnerable_symbols.clone(),
            verdict,
            confidence,
            call_chain,
        });
    }

    let reachable = results.iter().filter(|r| r.verdict == Verdict::Reachable).count();
    let unreachable = results.iter().filter(|r| r.verdict == Verdict::Unreachable).count();
    let unknown = results.iter().filter(|r| r.verdict == Verdict::Unknown).count();

    log::info!(
        "reachability: {} reachable, {} unreachable, {} unknown out of {} findings",
        reachable, unreachable, unknown, results.len(),
    );

    results
}

pub fn enrich_findings(target: &Path, findings: &mut [Finding]) {
    let results = analyze(target, findings);
    let result_map: std::collections::HashMap<(String, String), ReachabilityResult> = results
        .into_iter()
        .map(|result| {
            (
                (result.finding_rule_id.clone(), result.package.clone()),
                result,
            )
        })
        .collect();

    for finding in findings {
        let package = extract_package_name(finding);
        if package.is_empty() {
            continue;
        }
        let key = (finding.rule_id.clone(), package.clone());
        let Some(result) = result_map.get(&key) else { continue };
        finding.evidence.insert("reachable_package".into(), serde_json::json!(result.package));
        finding.evidence.insert(
            "reachable_callsite_count".into(),
            serde_json::json!(result.call_chain.len()),
        );
        if let Some(symbol) = result.vulnerable_symbols.iter().find(|sym| {
            result.call_chain.iter().any(|(_, snippet)| snippet.contains(last_symbol_segment(sym)))
        }) {
            finding.evidence.insert("reachable_symbol".into(), serde_json::json!(symbol));
        } else if let Some(symbol) = result.vulnerable_symbols.first() {
            finding.evidence.insert("reachable_symbol".into(), serde_json::json!(symbol));
        }
        finding.evidence.insert(
            "reachability_confidence".into(),
            serde_json::json!(result.confidence),
        );
        finding.reachability = Some(result.verdict.to_string());
    }
}

/// Extract package name from a finding's evidence or title.
fn extract_package_name(finding: &Finding) -> String {
    // Check evidence dict for package info
    if let Some(pkg) = finding.evidence.get("package") {
        if let Some(s) = pkg.as_str() {
            return s.to_string();
        }
    }
    if let Some(pkg) = finding.evidence.get("dependency") {
        if let Some(s) = pkg.as_str() {
            return s.to_string();
        }
    }
    // Try to extract from title: "CVE-XXXX in package-name@1.2.3"
    let title = &finding.title;
    if let Some(idx) = title.find(" in ") {
        let rest = &title[idx + 4..];
        if let Some(at_idx) = rest.find('@') {
            return rest[..at_idx].trim().to_string();
        }
        return rest.split_whitespace().next().unwrap_or("").to_string();
    }
    String::new()
}

/// Extract vulnerable symbols from finding evidence.
fn extract_vulnerable_symbols(finding: &Finding) -> Vec<String> {
    if let Some(syms) = finding.evidence.get("vulnerable_symbols") {
        if let Some(arr) = syms.as_array() {
            return arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
        }
    }
    Vec::new()
}

fn last_symbol_segment(symbol: &str) -> &str {
    symbol
        .rsplit(['.', ':', '/'])
        .next()
        .unwrap_or(symbol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Finding, Severity};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn sca_finding(package: &str, symbols: &[&str]) -> Finding {
        let mut evidence = HashMap::new();
        evidence.insert("package".into(), serde_json::json!(package));
        evidence.insert("vulnerable_symbols".into(), serde_json::json!(symbols));
        Finding {
            rule_id: "CBR-SUPPLY-GHSA-TEST".into(),
            title: "Test advisory".into(),
            severity: Severity::High,
            message: "test".into(),
            file: PathBuf::from("package-lock.json"),
            line: 0,
            column: 0,
            end_line: 0,
            end_column: 0,
            fingerprint: String::new(),
            start_byte: 0,
            end_byte: 0,
            snippet: format!("{package}@1.0.0"),
            fix_recipe: None,
            fix: None,
            cwe: Vec::new(),
            evidence,
            reachability: None,
        }
    }

    #[test]
    fn python_direct_import_symbol_is_marked_reachable() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("app.py"), "from yaml import load\nload(data)\n").unwrap();
        let findings = vec![sca_finding("yaml", &["yaml.load"])];
        let results = analyze(tmp.path(), &findings);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].verdict, Verdict::Reachable);
        assert!(!results[0].call_chain.is_empty());
    }

    #[test]
    fn reachability_enrichment_adds_symbol_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("app.py"), "from yaml import load\nload(data)\n").unwrap();
        let mut findings = vec![sca_finding("yaml", &["yaml.load"])];
        enrich_findings(tmp.path(), &mut findings);
        assert_eq!(findings[0].reachability.as_deref(), Some("reachable"));
        assert_eq!(findings[0].evidence.get("reachable_package").and_then(|v| v.as_str()), Some("yaml"));
        assert_eq!(findings[0].evidence.get("reachable_symbol").and_then(|v| v.as_str()), Some("yaml.load"));
        assert_eq!(findings[0].evidence.get("reachable_callsite_count").and_then(|v| v.as_u64()), Some(1));
    }
}
