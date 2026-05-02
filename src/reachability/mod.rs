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
///
/// Carries enough evidence that an enterprise reviewer can see *why*
/// a finding is reachable: the exact dependency-path that brought the
/// vulnerable package in, the import name(s) that matched in the
/// scanned code, and the symbol that triggered the verdict.
#[derive(Debug)]
pub struct ReachabilityResult {
    pub finding_rule_id: String,
    pub package: String,
    /// Candidate import names a vulnerable package can register under
    /// (e.g. PyYAML → ["pyyaml", "yaml"]). Populated from
    /// `extract_import_candidates`.
    pub import_candidates: Vec<String>,
    pub vulnerable_symbols: Vec<String>,
    /// Top-down dep chain: ["app", "express", "qs"]. Populated from
    /// the lockfile when available; defaults to [package].
    pub dependency_path: Vec<String>,
    /// The vulnerable symbol that actually appeared in the code, if any.
    pub matched_symbol: Option<String>,
    /// The candidate import name that matched in the scanned source.
    pub matched_import: Option<String>,
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
        let import_candidates  = extract_import_candidates(finding, &package, &vulnerable_symbols);
        let dependency_path    = extract_dependency_path(finding, &package);

        let mut matched_symbol: Option<String> = None;
        let mut matched_import: Option<String> = None;

        let (verdict, confidence, call_chain) = if vulnerable_symbols.is_empty() {
            // No specific symbols — check if any import-candidate is imported
            if import_index.is_any_package_imported(&import_candidates) {
                matched_import = import_index.matched_import_name(&import_candidates);
                (Verdict::Reachable, 0.5, import_index.get_import_sites_any(&import_candidates))
            } else {
                (Verdict::Unreachable, 0.9, Vec::new())
            }
        } else {
            // Check if any vulnerable symbol is called via any import alias
            let mut found_chain = Vec::new();
            let mut any_reachable = false;

            'outer: for symbol in &vulnerable_symbols {
                for cand in &import_candidates {
                    if let Some(chain) = import_index.find_call_chain(cand, symbol) {
                        found_chain  = chain;
                        any_reachable = true;
                        matched_symbol = Some(symbol.clone());
                        matched_import = Some(cand.clone());
                        break 'outer;
                    }
                }
            }

            if any_reachable {
                (Verdict::Reachable, 0.9, found_chain)
            } else if import_index.is_any_package_imported(&import_candidates) {
                // Package is imported but vulnerable function not called
                matched_import = import_index.matched_import_name(&import_candidates);
                (Verdict::Unreachable, 0.8, import_index.get_import_sites_any(&import_candidates))
            } else {
                // Package not even imported
                (Verdict::Unreachable, 0.95, Vec::new())
            }
        };

        results.push(ReachabilityResult {
            finding_rule_id: finding.rule_id.clone(),
            package: package.clone(),
            import_candidates,
            vulnerable_symbols: vulnerable_symbols.clone(),
            dependency_path,
            matched_symbol,
            matched_import,
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

/// Run reachability analysis and write the result onto each finding's
/// `evidence` map. This is the function the supply-chain pipeline calls
/// after persisting findings — every reachable finding carries the
/// dependency-path, matched import + symbol, and the call-site list so
/// reviewers can answer the "is this exploitable in our code" question
/// without leaving the report.
pub fn enrich_findings(target: &Path, findings: &mut [Finding]) {
    let results = analyze(target, findings);
    let result_map: std::collections::HashMap<(String, String), ReachabilityResult> = results
        .into_iter()
        .map(|r| ((r.finding_rule_id.clone(), r.package.clone()), r))
        .collect();

    for finding in findings {
        let package = extract_package_name(finding);
        if package.is_empty() { continue }
        let key = (finding.rule_id.clone(), package.clone());
        let Some(result) = result_map.get(&key) else { continue };

        finding.evidence.insert("reachable_package".into(), serde_json::json!(result.package));
        finding.evidence.insert(
            "reachable_dependency_path".into(),
            serde_json::json!(result.dependency_path),
        );
        finding.evidence.insert(
            "reachable_dependency_path_length".into(),
            serde_json::json!(result.dependency_path.len()),
        );
        finding.evidence.insert(
            "reachable_dependency_path_string".into(),
            serde_json::json!(result.dependency_path.join(" > ")),
        );
        if let Some(import_name) = &result.matched_import {
            finding.evidence.insert("reachable_import_name".into(), serde_json::json!(import_name));
        }
        finding.evidence.insert(
            "reachable_callsite_count".into(),
            serde_json::json!(result.call_chain.len()),
        );
        finding.evidence.insert(
            "reachable_callsites".into(),
            serde_json::json!(result.call_chain.iter()
                .map(|(loc, snippet)| serde_json::json!({"location": loc, "snippet": snippet}))
                .collect::<Vec<_>>()),
        );
        if let Some(symbol) = result.matched_symbol.as_ref() {
            finding.evidence.insert("reachable_symbol".into(), serde_json::json!(symbol));
        } else if let Some(symbol) = result.vulnerable_symbols.iter().find(|sym| {
            result.call_chain.iter()
                .any(|(_, snippet)| snippet.contains(last_symbol_segment(sym)))
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

/// Reconstruct the dependency path stored on a finding's evidence by
/// the supply-chain lockfile walker. Falls back to [package] when no
/// path was attached (e.g. the lockfile parser couldn't resolve the
/// transitive chain).
fn extract_dependency_path(finding: &Finding, package: &str) -> Vec<String> {
    if let Some(path) = finding.evidence.get("dependency_path").and_then(|v| v.as_array()) {
        let parsed: Vec<String> = path.iter().filter_map(|v| v.as_str().map(String::from)).collect();
        if !parsed.is_empty() { return parsed; }
    }
    vec![package.to_string()]
}

/// Build the candidate-name list for a package — the alias variants a
/// vulnerable package can register under (PyYAML → pyyaml + yaml,
/// lodash-es → lodash, etc.) so the import-index probe doesn't false-
/// negative on naming convention mismatches.
fn extract_import_candidates(
    finding: &Finding,
    package: &str,
    vulnerable_symbols: &[String],
) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();

    if let Some(imports) = finding.evidence.get("normalized_import_names").and_then(|v| v.as_array()) {
        for v in imports {
            if let Some(name) = v.as_str() { candidates.push(name.to_string()); }
        }
    }

    if candidates.is_empty() {
        candidates.push(package.to_string());
        candidates.push(package.to_ascii_lowercase());
        candidates.push(package.replace('-', "_").to_ascii_lowercase());
        candidates.push(package.replace('_', "-").to_ascii_lowercase());
    }

    // Also derive candidates from the vulnerable-symbol module prefix —
    // a CVE on `requests.utils.unquote_unreserved` implies the package
    // surfaces as `requests`, regardless of how it's normalised.
    for symbol in vulnerable_symbols {
        let normalised = symbol.replace("::", ".");
        if let Some((module, _)) = normalised.rsplit_once('.') {
            candidates.push(module.to_string());
            if let Some(tail) = module.rsplit(['.', '/']).next() {
                candidates.push(tail.to_string());
            }
        }
    }

    candidates.retain(|c| !c.is_empty());
    candidates.sort();
    candidates.dedup();
    candidates
}

fn last_symbol_segment(symbol: &str) -> &str {
    symbol.rsplit(['.', ':', '/']).next().unwrap_or(symbol)
}
