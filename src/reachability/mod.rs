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
