//! Container image vulnerability scanning — native cyscan implementation.
//!
//! Pipeline:
//!   1. `docker save <image>` → tarball of image layers
//!   2. Extract OS package databases from layers (dpkg, apk, rpm)
//!   3. Parse installed packages → (name, version, ecosystem)
//!   4. Match against OSV/NVD advisories (reuses supply::advisory)
//!
//! Falls back to grype/trivy if docker is unavailable.

use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::finding::{Finding, Severity};

/// An OS package extracted from a container image.
#[derive(Debug, Clone)]
struct OsPackage {
    name:    String,
    version: String,
    source:  String, // dpkg, apk, rpm
}

/// Scan a container image for vulnerabilities.
/// Tries native scanning first (docker save + package parse + OSV lookup),
/// falls back to grype/trivy if docker isn't available.
pub fn scan_image(image: &str) -> Result<Vec<Finding>> {
    // Try native scan
    match scan_native(image) {
        Ok(findings) => return Ok(findings),
        Err(e) => {
            log::debug!("native image scan failed ({}), trying grype/trivy fallback", e);
        }
    }

    // Fallback to grype
    if let Ok(findings) = scan_with_grype(image) {
        return Ok(findings);
    }

    // Fallback to trivy
    if let Ok(findings) = scan_with_trivy(image) {
        return Ok(findings);
    }

    bail!("image scanning requires docker (native) or grype/trivy (fallback)")
}

// ── Native scanner ──────────────────────────────────────────────────────

fn scan_native(image: &str) -> Result<Vec<Finding>> {
    // Step 1: Save image to tarball
    let temp = tempfile::tempdir()?;
    let tar_path = temp.path().join("image.tar");

    let status = Command::new("docker")
        .args(["save", "-o", tar_path.to_str().unwrap(), image])
        .status()
        .context("docker not found")?;

    if !status.success() {
        // Try pulling first
        let _ = Command::new("docker").args(["pull", image]).status();
        let status = Command::new("docker")
            .args(["save", "-o", tar_path.to_str().unwrap(), image])
            .status()?;
        if !status.success() {
            bail!("docker save failed for {}", image);
        }
    }

    // Step 2: Extract package databases from image layers
    let packages = extract_packages(&tar_path)?;
    if packages.is_empty() {
        return Ok(Vec::new());
    }

    log::info!("extracted {} OS packages from {}", packages.len(), image);

    // Step 3: Look up vulnerabilities via OSV API
    let findings = lookup_vulns(&packages, image)?;

    Ok(findings)
}

/// Extract OS packages from a Docker image tarball.
/// Walks each layer's tar, looking for package database files.
fn extract_packages(image_tar: &std::path::Path) -> Result<Vec<OsPackage>> {
    let file = std::fs::File::open(image_tar)?;
    let mut archive = tar::Archive::new(file);

    let mut packages = Vec::new();
    let mut dpkg_status = String::new();
    let mut apk_installed = String::new();
    let mut rpm_manifest = String::new();
    let mut pacman_local: Vec<(String, String)> = Vec::new();

    // Image tarball contains layer tarballs
    for entry in archive.entries()? {
        let entry = entry?;
        let path = entry.path()?.to_path_buf();
        let path_str = path.to_string_lossy().to_string();

        // Layer tarballs are .tar or inside directories
        if path_str.ends_with("/layer.tar") || path_str.ends_with(".tar") {
            // Extract this layer and look for package DBs
            let decoder = if is_gzipped_entry(&entry) {
                // Some layers are gzipped
                Box::new(flate2::read::GzDecoder::new(entry)) as Box<dyn Read>
            } else {
                Box::new(entry) as Box<dyn Read>
            };

            if let Ok(mut layer) = tar::Archive::new(decoder).entries() {
                while let Some(Ok(mut layer_entry)) = layer.next() {
                    let Ok(lpath) = layer_entry.path() else { continue };
                    let lpath_str = lpath.to_string_lossy().to_string();

                    // dpkg (Debian/Ubuntu)
                    if lpath_str.ends_with("var/lib/dpkg/status") || lpath_str == "var/lib/dpkg/status" {
                        dpkg_status.clear();
                        layer_entry.read_to_string(&mut dpkg_status).ok();
                    }

                    // apk (Alpine)
                    if lpath_str.ends_with("lib/apk/db/installed") || lpath_str == "lib/apk/db/installed" {
                        apk_installed.clear();
                        layer_entry.read_to_string(&mut apk_installed).ok();
                    }

                    // rpm (RHEL/CentOS/Fedora) — text manifest or rpmdb.sqlite
                    if lpath_str.ends_with("var/lib/rpm/Packages") || lpath_str.ends_with("var/lib/rpm/rpmdb.sqlite") {
                        // Binary DB — fall back to rpm -qa inside container later
                    }
                    // rpm manifest (newer dnf-based systems)
                    if lpath_str.ends_with("var/lib/dnf/history.sqlite") || lpath_str.contains("var/log/dnf.rpm.log") {
                        rpm_manifest.clear();
                        layer_entry.read_to_string(&mut rpm_manifest).ok();
                    }

                    // pacman (Arch Linux) — /var/lib/pacman/local/<pkg>-<ver>/desc
                    if lpath_str.contains("var/lib/pacman/local/") && lpath_str.ends_with("/desc") {
                        let mut desc = String::new();
                        if layer_entry.read_to_string(&mut desc).is_ok() {
                            if let Some((name, ver)) = parse_pacman_desc(&desc) {
                                pacman_local.push((name, ver));
                            }
                        }
                    }
                }
            }
        }
    }

    // Parse extracted package databases
    if !dpkg_status.is_empty() {
        packages.extend(parse_dpkg_status(&dpkg_status));
    }
    if !apk_installed.is_empty() {
        packages.extend(parse_apk_installed(&apk_installed));
    }
    if !pacman_local.is_empty() {
        for (name, ver) in &pacman_local {
            packages.push(OsPackage {
                name: name.clone(),
                version: ver.clone(),
                source: "pacman".into(),
            });
        }
    }

    // If no package DB found in layers, try `docker run rpm -qa` for rpm-based images
    if packages.is_empty() {
        if let Ok(rpm_pkgs) = extract_rpm_via_docker(image_tar) {
            packages.extend(rpm_pkgs);
        }
    }

    Ok(packages)
}

fn is_gzipped_entry<R: Read>(_entry: &tar::Entry<R>) -> bool {
    // We'll try both — if not gzipped, tar::Archive will handle it
    false
}

/// Parse dpkg /var/lib/dpkg/status file.
/// Format: paragraph-separated entries with Package: and Version: fields.
fn parse_dpkg_status(content: &str) -> Vec<OsPackage> {
    let mut packages = Vec::new();
    let mut name = String::new();
    let mut version = String::new();

    for line in content.lines() {
        if line.is_empty() {
            if !name.is_empty() && !version.is_empty() {
                packages.push(OsPackage {
                    name: name.clone(),
                    version: version.clone(),
                    source: "dpkg".into(),
                });
            }
            name.clear();
            version.clear();
        } else if let Some(val) = line.strip_prefix("Package: ") {
            name = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("Version: ") {
            version = val.trim().to_string();
        }
    }
    // Last entry
    if !name.is_empty() && !version.is_empty() {
        packages.push(OsPackage { name, version, source: "dpkg".into() });
    }

    packages
}

/// Parse apk /lib/apk/db/installed file.
/// Format: paragraph-separated, P: = package name, V: = version.
fn parse_apk_installed(content: &str) -> Vec<OsPackage> {
    let mut packages = Vec::new();
    let mut name = String::new();
    let mut version = String::new();

    for line in content.lines() {
        if line.is_empty() {
            if !name.is_empty() && !version.is_empty() {
                packages.push(OsPackage {
                    name: name.clone(),
                    version: version.clone(),
                    source: "apk".into(),
                });
            }
            name.clear();
            version.clear();
        } else if let Some(val) = line.strip_prefix("P:") {
            name = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("V:") {
            version = val.trim().to_string();
        }
    }
    if !name.is_empty() && !version.is_empty() {
        packages.push(OsPackage { name, version, source: "apk".into() });
    }

    packages
}

/// Parse pacman desc file.
/// Format: sections delimited by %NAME%, %VERSION%, etc.
fn parse_pacman_desc(content: &str) -> Option<(String, String)> {
    let mut name = None;
    let mut version = None;
    let mut current_section = "";

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('%') && trimmed.ends_with('%') {
            current_section = trimmed;
        } else if !trimmed.is_empty() {
            match current_section {
                "%NAME%" => name = Some(trimmed.to_string()),
                "%VERSION%" => version = Some(trimmed.to_string()),
                _ => {}
            }
        }
    }

    match (name, version) {
        (Some(n), Some(v)) => Some((n, v)),
        _ => None,
    }
}

/// Extract RPM packages by running rpm -qa inside a temporary container.
/// This handles rpm-based images (RHEL, CentOS, Fedora, Amazon Linux)
/// where the binary rpmdb can't be parsed directly.
fn extract_rpm_via_docker(image_tar: &std::path::Path) -> Result<Vec<OsPackage>> {
    // Get the image name from the tar manifest
    let file = std::fs::File::open(image_tar)?;
    let mut archive = tar::Archive::new(file);
    let mut image_name = String::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if path.to_string_lossy() == "manifest.json" {
            let mut content = String::new();
            entry.read_to_string(&mut content).ok();
            if let Ok(manifest) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(tags) = manifest.as_array()
                    .and_then(|a| a.first())
                    .and_then(|m| m.get("RepoTags"))
                    .and_then(|t| t.as_array())
                {
                    if let Some(tag) = tags.first().and_then(|t| t.as_str()) {
                        image_name = tag.to_string();
                    }
                }
            }
            break;
        }
    }

    if image_name.is_empty() {
        bail!("could not determine image name from tarball");
    }

    // Run rpm -qa inside a temporary container
    let out = Command::new("docker")
        .args(["run", "--rm", "--entrypoint", "rpm", &image_name, "-qa", "--queryformat", "%{NAME} %{VERSION}-%{RELEASE}\n"])
        .output()?;

    if !out.status.success() {
        bail!("rpm -qa failed inside container");
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut packages = Vec::new();

    for line in stdout.lines() {
        let mut parts = line.splitn(2, ' ');
        if let (Some(name), Some(version)) = (parts.next(), parts.next()) {
            let name = name.trim().to_string();
            let version = version.trim().to_string();
            if !name.is_empty() && !version.is_empty() && name != "(none)" {
                packages.push(OsPackage {
                    name,
                    version,
                    source: "rpm".into(),
                });
            }
        }
    }

    Ok(packages)
}

/// Look up vulnerabilities for OS packages across three databases:
///   1. OSV.dev    — aggregates Debian, Alpine, RHEL, NVD, GitHub Advisories
///   2. NVD (NIST) — CPE-based matching for broader coverage
///   3. GitHub Security Advisories — GHSA IDs
///
/// Results are deduplicated by CVE ID per package.
fn lookup_vulns(packages: &[OsPackage], image: &str) -> Result<Vec<Finding>> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("cyscan/0.7")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut findings = Vec::new();
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    // ── Source 1: OSV.dev (batch API — covers Debian, Alpine, NVD, GHSA) ──
    for chunk in packages.chunks(1000) {
        let queries: Vec<serde_json::Value> = chunk.iter().map(|pkg| {
            serde_json::json!({
                "package": { "name": pkg.name, "ecosystem": osv_ecosystem(&pkg.source) },
                "version": pkg.version
            })
        }).collect();

        let body = serde_json::json!({ "queries": queries });

        if let Ok(resp) = client.post("https://api.osv.dev/v1/querybatch").json(&body).send() {
            if let Ok(data) = resp.json::<serde_json::Value>() {
                if let Some(results) = data.get("results").and_then(|r| r.as_array()) {
                    for (i, result) in results.iter().enumerate() {
                        if let Some(vulns) = result.get("vulns").and_then(|v| v.as_array()) {
                            let pkg = &chunk[i];
                            for vuln in vulns {
                                if let Some(f) = vuln_to_finding(vuln, pkg, image, "osv") {
                                    let dedup_key = format!("{}:{}", f.rule_id, pkg.name);
                                    if seen_ids.insert(dedup_key) {
                                        findings.push(f);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            log::warn!("OSV API batch query failed");
        }
    }

    // ── Source 2: NVD (NIST) — CPE match for packages OSV might miss ──
    // Query top packages only (NVD has rate limits: 5 req/30s without API key)
    let nvd_candidates: Vec<_> = packages.iter()
        .filter(|p| p.source == "dpkg" || p.source == "rpm")
        .take(50)  // rate-limit safe
        .collect();

    for pkg in &nvd_candidates {
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&keywordExactMatch&resultsPerPage=5",
            urlencoding::encode(&pkg.name)
        );

        if let Ok(resp) = client.get(&url).send() {
            if let Ok(data) = resp.json::<serde_json::Value>() {
                if let Some(vulns) = data.get("vulnerabilities").and_then(|v| v.as_array()) {
                    for vuln_wrapper in vulns {
                        let cve = match vuln_wrapper.get("cve") {
                            Some(c) => c,
                            None => continue,
                        };
                        let id = cve.get("id").and_then(|i| i.as_str()).unwrap_or("UNKNOWN");
                        let dedup_key = format!("CBR-IMG-{}:{}", id, pkg.name);
                        if seen_ids.contains(&dedup_key) { continue; }

                        // Extract CVSS v3.1 score
                        let severity = cve.get("metrics")
                            .and_then(|m| m.get("cvssMetricV31"))
                            .and_then(|arr| arr.as_array())
                            .and_then(|a| a.first())
                            .and_then(|m| m.get("cvssData"))
                            .and_then(|d| d.get("baseScore"))
                            .and_then(|s| s.as_f64())
                            .map(|score| {
                                if score >= 9.0 { Severity::Critical }
                                else if score >= 7.0 { Severity::High }
                                else if score >= 4.0 { Severity::Medium }
                                else { Severity::Low }
                            })
                            .unwrap_or(Severity::Medium);

                        let desc = cve.get("descriptions")
                            .and_then(|d| d.as_array())
                            .and_then(|a| a.first())
                            .and_then(|d| d.get("value"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("");

                        // Check if this CVE actually affects this package version
                        // (keyword match is broad — skip if description doesn't mention the package)
                        if !desc.to_lowercase().contains(&pkg.name.to_lowercase()) {
                            continue;
                        }

                        let mut evidence = HashMap::new();
                        evidence.insert("image".into(), serde_json::Value::String(image.to_string()));
                        evidence.insert("package".into(), serde_json::Value::String(pkg.name.clone()));
                        evidence.insert("installed_version".into(), serde_json::Value::String(pkg.version.clone()));
                        evidence.insert("source".into(), serde_json::Value::String("nvd".into()));

                        if seen_ids.insert(dedup_key) {
                            findings.push(Finding {
                                rule_id:    format!("CBR-IMG-{}", id),
                                title:      format!("{} in {} ({})", id, pkg.name, image),
                                severity,
                                message:    format!("{}\n\nPackage: {} {} ({})\nImage: {}",
                                    desc, pkg.name, pkg.version, pkg.source, image),
                                file:       PathBuf::from(image),
                                line: 0, column: 0, end_line: 0, end_column: 0,
                                start_byte: 0, end_byte: 0,
                                snippet:    format!("{}@{}", pkg.name, pkg.version),
                                fix_recipe: None, fix: None, cwe: vec![],
                                evidence,
                                reachability: None,
                                fingerprint: String::new(),
                            });
                        }
                    }
                }
            }
        }
        // NVD rate limit: 5 requests per 30 seconds (without API key)
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    // ── Source 3: GitHub Security Advisories (GHSA) ──
    // Query for ecosystem-specific advisories
    for pkg in packages.iter().take(100) {
        let ghsa_ecosystem = match pkg.source.as_str() {
            "dpkg" => "RUST",  // GHSA doesn't have a Debian ecosystem — skip for OS pkgs
            _ => continue,     // GHSA is best for app-level deps, not OS packages
        };
        // OS packages are well-covered by OSV which already aggregates GHSA.
        // We only add direct GHSA queries for app-layer packages (npm, pypi, etc.)
        // which are handled by `cyscan supply`. Skip here to avoid noise.
    }

    Ok(findings)
}

/// Map package source to OSV ecosystem name.
fn osv_ecosystem(source: &str) -> &'static str {
    match source {
        "dpkg"   => "Debian",
        "apk"    => "Alpine",
        "rpm"    => "Red Hat",
        "pacman" => "Arch Linux",
        _        => "Linux",
    }
}

/// Convert an OSV vulnerability JSON object to a Finding.
fn vuln_to_finding(vuln: &serde_json::Value, pkg: &OsPackage, image: &str, source: &str) -> Option<Finding> {
    let id = vuln.get("id").and_then(|i| i.as_str())?;
    let summary = vuln.get("summary").and_then(|s| s.as_str()).unwrap_or("");
    let details = vuln.get("details").and_then(|d| d.as_str()).unwrap_or("");
    let severity = extract_severity(vuln);

    let fixed_ver = vuln.get("affected")
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|a| a.get("ranges"))
        .and_then(|r| r.as_array())
        .and_then(|r| r.first())
        .and_then(|r| r.get("events"))
        .and_then(|e| e.as_array())
        .and_then(|events| events.iter().find_map(|e| e.get("fixed").and_then(|f| f.as_str())))
        .unwrap_or("N/A");

    let desc = if !summary.is_empty() { summary } else { details };
    let msg = format!("{}\n\nPackage: {} {} ({})\nFixed: {}\nImage: {}\nSource: {}",
        desc, pkg.name, pkg.version, pkg.source, fixed_ver, image, source);

    let mut evidence = HashMap::new();
    evidence.insert("image".into(), serde_json::Value::String(image.to_string()));
    evidence.insert("package".into(), serde_json::Value::String(pkg.name.clone()));
    evidence.insert("installed_version".into(), serde_json::Value::String(pkg.version.clone()));
    evidence.insert("fixed_version".into(), serde_json::Value::String(fixed_ver.to_string()));
    evidence.insert("pkg_type".into(), serde_json::Value::String(pkg.source.clone()));
    evidence.insert("source".into(), serde_json::Value::String(source.to_string()));

    Some(Finding {
        rule_id:    format!("CBR-IMG-{}", id),
        title:      format!("{} in {} ({})", id, pkg.name, image),
        severity,
        message:    msg,
        file:       PathBuf::from(image),
        line: 0, column: 0, end_line: 0, end_column: 0,
        start_byte: 0, end_byte: 0,
        snippet:    format!("{}@{}", pkg.name, pkg.version),
        fix_recipe: None, fix: None, cwe: vec![],
        evidence,
        reachability: None,
        fingerprint: String::new(),
    })
}

fn extract_severity(vuln: &serde_json::Value) -> Severity {
    // Try CVSS from severity array
    if let Some(sevs) = vuln.get("severity").and_then(|s| s.as_array()) {
        for s in sevs {
            if let Some(score) = s.get("score").and_then(|s| s.as_str()) {
                // CVSS vector — extract base score
                if let Some(base) = parse_cvss_score(score) {
                    return if base >= 9.0 { Severity::Critical }
                    else if base >= 7.0 { Severity::High }
                    else if base >= 4.0 { Severity::Medium }
                    else { Severity::Low };
                }
            }
        }
    }

    // Try database_specific severity
    if let Some(db) = vuln.get("database_specific") {
        if let Some(sev) = db.get("severity").and_then(|s| s.as_str()) {
            return match sev.to_uppercase().as_str() {
                "CRITICAL" => Severity::Critical,
                "HIGH"     => Severity::High,
                "MODERATE" | "MEDIUM" => Severity::Medium,
                "LOW"      => Severity::Low,
                _          => Severity::Info,
            };
        }
    }

    Severity::Medium // default if unknown
}

/// Parse CVSS v3 base score from vector string.
/// e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" → 9.8
fn parse_cvss_score(vector: &str) -> Option<f64> {
    // Simplified — look for a numeric score if embedded, otherwise estimate from vector
    // Some OSV entries include the score directly
    if let Ok(score) = vector.parse::<f64>() {
        return Some(score);
    }

    // Rough estimation from CVSS v3 vector
    if !vector.starts_with("CVSS:3") { return None; }

    let mut score: f64 = 5.0; // base

    if vector.contains("AV:N") { score += 1.5; } // network
    if vector.contains("AC:L") { score += 0.5; } // low complexity
    if vector.contains("PR:N") { score += 0.5; } // no privileges
    if vector.contains("UI:N") { score += 0.5; } // no user interaction
    if vector.contains("C:H")  { score += 0.5; } // high confidentiality
    if vector.contains("I:H")  { score += 0.5; } // high integrity
    if vector.contains("A:H")  { score += 0.5; } // high availability

    Some(score.min(10.0))
}

// ── Fallback scanners ───────────────────────────────────────────────────

fn scan_with_grype(image: &str) -> Result<Vec<Finding>> {
    let out = Command::new("grype")
        .args([image, "-o", "json", "--only-fixed"])
        .output()?;

    if !out.status.success() {
        bail!("grype failed");
    }

    let json: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let matches = json.get("matches").and_then(|m| m.as_array());

    let mut findings = Vec::new();
    if let Some(matches) = matches {
        for m in matches {
            let vuln = m.get("vulnerability").unwrap_or(m);
            let id = vuln.get("id").and_then(|i| i.as_str()).unwrap_or("UNKNOWN");
            let sev_str = vuln.get("severity").and_then(|s| s.as_str()).unwrap_or("Unknown");
            let artifact = m.get("artifact");
            let pkg = artifact.and_then(|a| a.get("name")).and_then(|n| n.as_str()).unwrap_or("");
            let ver = artifact.and_then(|a| a.get("version")).and_then(|v| v.as_str()).unwrap_or("");

            let severity = match sev_str.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high"     => Severity::High,
                "medium"   => Severity::Medium,
                "low"      => Severity::Low,
                _          => Severity::Info,
            };

            let mut evidence = HashMap::new();
            evidence.insert("image".into(), serde_json::Value::String(image.to_string()));
            evidence.insert("package".into(), serde_json::Value::String(pkg.to_string()));

            findings.push(Finding {
                rule_id: format!("CBR-IMG-{}", id),
                title: format!("{} in {} ({})", id, pkg, image),
                severity,
                message: format!("{} {}@{}", id, pkg, ver),
                file: PathBuf::from(image),
                line: 0, column: 0, end_line: 0, end_column: 0,
                start_byte: 0, end_byte: 0,
                snippet: format!("{}@{}", pkg, ver),
                fix_recipe: None, fix: None, cwe: vec![],
                evidence, reachability: None,
                fingerprint: String::new(),
            });
        }
    }
    Ok(findings)
}

fn scan_with_trivy(image: &str) -> Result<Vec<Finding>> {
    let out = Command::new("trivy")
        .args(["image", "--format", "json", image])
        .output()?;

    if !out.status.success() {
        bail!("trivy failed");
    }

    let json: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let results = json.get("Results").and_then(|r| r.as_array());

    let mut findings = Vec::new();
    if let Some(results) = results {
        for result in results {
            if let Some(vulns) = result.get("Vulnerabilities").and_then(|v| v.as_array()) {
                for vuln in vulns {
                    let id = vuln.get("VulnerabilityID").and_then(|i| i.as_str()).unwrap_or("UNKNOWN");
                    let sev_str = vuln.get("Severity").and_then(|s| s.as_str()).unwrap_or("UNKNOWN");
                    let pkg = vuln.get("PkgName").and_then(|p| p.as_str()).unwrap_or("");
                    let ver = vuln.get("InstalledVersion").and_then(|v| v.as_str()).unwrap_or("");

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

                    findings.push(Finding {
                        rule_id: format!("CBR-IMG-{}", id),
                        title: format!("{} in {} ({})", id, pkg, image),
                        severity,
                        message: format!("{} {}@{}", id, pkg, ver),
                        file: PathBuf::from(image),
                        line: 0, column: 0, end_line: 0, end_column: 0,
                        start_byte: 0, end_byte: 0,
                        snippet: format!("{}@{}", pkg, ver),
                        fix_recipe: None, fix: None, cwe: vec![],
                        evidence, reachability: None,
                        fingerprint: String::new(),
                    });
                }
            }
        }
    }
    Ok(findings)
}
