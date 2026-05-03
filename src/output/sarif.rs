//! SARIF 2.1.0 output. Hand-rolled via serde_json so we avoid the heavy
//! `sarif` crate; the subset we emit is stable and GitHub / VSCode-code-
//! scanning-compatible.

use std::{collections::BTreeMap, io};

use serde_json::json;

use crate::finding::{Finding, Severity};

pub fn emit(findings: &[Finding]) -> io::Result<()> {
    // Collect unique rules so we can emit rules[] alongside results[].
    let mut rules: BTreeMap<&str, &Finding> = BTreeMap::new();
    for f in findings {
        rules.entry(f.rule_id.as_str()).or_insert(f);
    }

    let rules_json: Vec<_> = rules.values().map(|f| {
        json!({
            "id":   f.rule_id,
            "name": f.rule_id,
            "shortDescription": { "text": f.title },
            "fullDescription":  { "text": f.message },
            "defaultConfiguration": { "level": sarif_level(f.severity) },
            "properties": {
                "security-severity": security_score(f.severity),
                "cwe": f.cwe,
            },
        })
    }).collect();

    let results_json: Vec<_> = findings.iter().map(|f| {
        // SARIF forbids startLine=0. Supply-chain findings attach to
        // whole lockfiles and have no line info; emit a file-only
        // physicalLocation (spec-legal) in that case.
        let physical = if f.line == 0 {
            json!({ "artifactLocation": { "uri": f.file.to_string_lossy() } })
        } else {
            json!({
                "artifactLocation": { "uri": f.file.to_string_lossy() },
                "region": {
                    "startLine":   f.line,
                    "startColumn": f.column,
                    "endLine":     f.end_line,
                    "endColumn":   f.end_column,
                    "snippet":     { "text": f.snippet },
                }
            })
        };
        // Cross-service chain → SARIF relatedLocations (one per
        // upstream caller / linked finding). Lets the SARIF viewer
        // render the chain as clickable side-by-side navigation.
        let related_locations = build_related_locations(f);

        let mut result = json!({
            "ruleId": f.rule_id,
            "level":  sarif_level(f.severity),
            "message": { "text": f.message },
            "locations": [{ "physicalLocation": physical }],
            "properties": {
                "fix_recipe":        f.fix_recipe,
                "packageCoordinate": package_coordinate(f),
            }
        });
        if !related_locations.is_empty() {
            result["relatedLocations"] = json!(related_locations);
        }
        result
    }).collect();

    let sarif = json!({
        "$schema":  "https://json.schemastore.org/sarif-2.1.0.json",
        "version":  "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name":           "cyscan",
                    "informationUri": "https://github.com/cybrium-ai/cyscan",
                    "rules":          rules_json,
                }
            },
            "results": results_json,
        }]
    });

    serde_json::to_writer_pretty(io::stdout().lock(), &sarif)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    println!();
    Ok(())
}

fn sarif_level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium                    => "warning",
        Severity::Low | Severity::Info      => "note",
    }
}

/// Canonical coordinate string the platform reachability engine uses
/// to join cyscan findings with its advisory-symbol index. Returns
/// None for source-code findings.
fn package_coordinate(f: &Finding) -> Option<String> {
    // Cheap heuristic: supply-chain findings have our CBR-SUPPLY- or
    // CBR-DEP- prefix, a line=0 location, and a `name@version` snippet.
    if f.line != 0 { return None; }
    if !(f.rule_id.starts_with("CBR-SUPPLY-") || f.rule_id.starts_with("CBR-DEP-")) {
        return None;
    }
    Some(f.snippet.clone())
}

/// Build SARIF relatedLocations entries from a finding's
/// `cross_service_chain` and `cross_service_callers` evidence (when
/// present). Returns an empty Vec when there's nothing to add.
fn build_related_locations(f: &Finding) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    if let Some(chain) = f.evidence.get("cross_service_chain").and_then(|v| v.as_array()) {
        for entry in chain {
            let file = entry.get("file").and_then(|v| v.as_str()).unwrap_or("");
            let line = entry.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let snippet = entry.get("snippet").and_then(|v| v.as_str()).unwrap_or("");
            let rule_id = entry.get("rule_id").and_then(|v| v.as_str()).unwrap_or("");
            out.push(json!({
                "physicalLocation": {
                    "artifactLocation": { "uri": file },
                    "region": {
                        "startLine": line.max(1),
                        "snippet": { "text": snippet },
                    }
                },
                "message": { "text": format!("Linked finding [{rule_id}]: {snippet}") },
            }));
        }
    }
    if let Some(callers) = f.evidence.get("cross_service_callers").and_then(|v| v.as_array()) {
        for entry in callers {
            let file = entry.get("file").and_then(|v| v.as_str()).unwrap_or("");
            let line = entry.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let language = entry.get("language").and_then(|v| v.as_str()).unwrap_or("");
            let method = entry.get("method").and_then(|v| v.as_str()).unwrap_or("");
            let path = entry.get("path").and_then(|v| v.as_str()).unwrap_or("");
            out.push(json!({
                "physicalLocation": {
                    "artifactLocation": { "uri": file },
                    "region": {
                        "startLine": line.max(1),
                        "snippet": { "text": format!("{method} {path}") },
                    }
                },
                "message": { "text": format!("Upstream {language} caller: {method} {path}") },
            }));
        }
    }
    out
}

fn security_score(s: Severity) -> f64 {
    match s {
        Severity::Critical => 9.5,
        Severity::High     => 7.5,
        Severity::Medium   => 5.0,
        Severity::Low      => 3.0,
        Severity::Info     => 1.0,
    }
}
