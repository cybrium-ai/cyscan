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
        json!({
            "ruleId": f.rule_id,
            "level":  sarif_level(f.severity),
            "message": { "text": f.message },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": { "uri": f.file.to_string_lossy() },
                    "region": {
                        "startLine":   f.line,
                        "startColumn": f.column,
                        "endLine":     f.end_line,
                        "endColumn":   f.end_column,
                        "snippet":     { "text": f.snippet },
                    }
                }
            }],
            "properties": {
                "fix_recipe": f.fix_recipe,
            }
        })
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

fn security_score(s: Severity) -> f64 {
    match s {
        Severity::Critical => 9.5,
        Severity::High     => 7.5,
        Severity::Medium   => 5.0,
        Severity::Low      => 3.0,
        Severity::Info     => 1.0,
    }
}
