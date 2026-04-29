//! Container image vulnerability scanning — shells out to grype or trivy
//! to scan images for known CVEs.
//!
//! Tries grype first (lighter), falls back to trivy.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Result};

use crate::finding::{Finding, Severity};

/// Scan a container image for vulnerabilities using grype or trivy.
pub fn scan_image(image: &str) -> Result<Vec<Finding>> {
    // Try grype first
    if let Ok(findings) = scan_with_grype(image) {
        return Ok(findings);
    }

    // Fall back to trivy
    if let Ok(findings) = scan_with_trivy(image) {
        return Ok(findings);
    }

    bail!("neither grype nor trivy found — install one: brew install grype OR brew install trivy")
}

fn scan_with_grype(image: &str) -> Result<Vec<Finding>> {
    let out = Command::new("grype")
        .args([image, "-o", "json", "--only-fixed"])
        .output()?;

    if !out.status.success() {
        bail!("grype failed: {}", String::from_utf8_lossy(&out.stderr));
    }

    let json: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let matches = json.get("matches").and_then(|m| m.as_array());

    let mut findings = Vec::new();
    if let Some(matches) = matches {
        for m in matches {
            let vuln = m.get("vulnerability").unwrap_or(m);
            let id = vuln.get("id").and_then(|i| i.as_str()).unwrap_or("UNKNOWN");
            let sev_str = vuln.get("severity").and_then(|s| s.as_str()).unwrap_or("Unknown");
            let desc = vuln.get("description").and_then(|d| d.as_str()).unwrap_or("");

            let severity = match sev_str.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high"     => Severity::High,
                "medium"   => Severity::Medium,
                "low"      => Severity::Low,
                _          => Severity::Info,
            };

            // Extract package info
            let artifact = m.get("artifact");
            let pkg_name = artifact.and_then(|a| a.get("name")).and_then(|n| n.as_str()).unwrap_or("");
            let pkg_ver = artifact.and_then(|a| a.get("version")).and_then(|v| v.as_str()).unwrap_or("");

            let fixed_ver = vuln.get("fix")
                .and_then(|f| f.get("versions"))
                .and_then(|v| v.as_array())
                .and_then(|v| v.first())
                .and_then(|v| v.as_str())
                .unwrap_or("N/A");

            let mut evidence = HashMap::new();
            evidence.insert("image".into(), serde_json::Value::String(image.to_string()));
            evidence.insert("package".into(), serde_json::Value::String(pkg_name.to_string()));
            evidence.insert("installed_version".into(), serde_json::Value::String(pkg_ver.to_string()));
            evidence.insert("fixed_version".into(), serde_json::Value::String(fixed_ver.to_string()));

            findings.push(Finding {
                rule_id:    format!("CBR-IMG-{}", id),
                title:      format!("{} in {} ({})", id, pkg_name, image),
                severity,
                message:    if desc.is_empty() {
                    format!("{} {} has {} (fix: {})", pkg_name, pkg_ver, id, fixed_ver)
                } else {
                    format!("{}\n\nPackage: {}@{} → fix: {}", desc, pkg_name, pkg_ver, fixed_ver)
                },
                file:       PathBuf::from(image),
                line: 0, column: 0, end_line: 0, end_column: 0,
                start_byte: 0, end_byte: 0,
                snippet:    format!("{}@{}", pkg_name, pkg_ver),
                fix_recipe: None,
                fix:        None,
                cwe:        vec![],
                evidence,
                reachability: None,
            });
        }
    }

    Ok(findings)
}

fn scan_with_trivy(image: &str) -> Result<Vec<Finding>> {
    let out = Command::new("trivy")
        .args(["image", "--format", "json", "--severity", "CRITICAL,HIGH,MEDIUM,LOW", image])
        .output()?;

    if !out.status.success() {
        bail!("trivy failed: {}", String::from_utf8_lossy(&out.stderr));
    }

    let json: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let results = json.get("Results").and_then(|r| r.as_array());

    let mut findings = Vec::new();
    if let Some(results) = results {
        for result in results {
            let vulns = result.get("Vulnerabilities").and_then(|v| v.as_array());
            if let Some(vulns) = vulns {
                for vuln in vulns {
                    let id = vuln.get("VulnerabilityID").and_then(|i| i.as_str()).unwrap_or("UNKNOWN");
                    let sev_str = vuln.get("Severity").and_then(|s| s.as_str()).unwrap_or("UNKNOWN");
                    let title = vuln.get("Title").and_then(|t| t.as_str()).unwrap_or("");
                    let desc = vuln.get("Description").and_then(|d| d.as_str()).unwrap_or("");
                    let pkg = vuln.get("PkgName").and_then(|p| p.as_str()).unwrap_or("");
                    let ver = vuln.get("InstalledVersion").and_then(|v| v.as_str()).unwrap_or("");
                    let fixed = vuln.get("FixedVersion").and_then(|f| f.as_str()).unwrap_or("N/A");

                    let severity = match sev_str.to_uppercase().as_str() {
                        "CRITICAL" => Severity::Critical,
                        "HIGH"     => Severity::High,
                        "MEDIUM"   => Severity::Medium,
                        "LOW"      => Severity::Low,
                        _          => Severity::Info,
                    };

                    let mut evidence = HashMap::new();
                    evidence.insert("image".into(), serde_json::Value::String(image.to_string()));
                    evidence.insert("package".into(), serde_json::Value::String(pkg.to_string()));
                    evidence.insert("installed_version".into(), serde_json::Value::String(ver.to_string()));
                    evidence.insert("fixed_version".into(), serde_json::Value::String(fixed.to_string()));

                    let msg = if !title.is_empty() {
                        format!("{}\n\n{}\n\nPackage: {}@{} → fix: {}", title, desc, pkg, ver, fixed)
                    } else {
                        format!("{}\n\nPackage: {}@{} → fix: {}", desc, pkg, ver, fixed)
                    };

                    findings.push(Finding {
                        rule_id:    format!("CBR-IMG-{}", id),
                        title:      format!("{} in {} ({})", id, pkg, image),
                        severity,
                        message:    msg,
                        file:       PathBuf::from(image),
                        line: 0, column: 0, end_line: 0, end_column: 0,
                        start_byte: 0, end_byte: 0,
                        snippet:    format!("{}@{}", pkg, ver),
                        fix_recipe: None,
                        fix:        None,
                        cwe:        vec![],
                        evidence,
                        reachability: None,
                    });
                }
            }
        }
    }

    Ok(findings)
}
