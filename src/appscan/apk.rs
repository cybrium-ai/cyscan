//! Android .apk scanner — decodes the binary AndroidManifest.xml and audits
//! the app's security posture: debuggable/backup flags, cleartext traffic,
//! exported components, dangerous permissions, signing scheme, and hardcoded
//! secrets in bundled resources/assets.
//!
//! .apk structure (a ZIP):
//!   AndroidManifest.xml   (binary AXML)
//!   classes*.dex          (Dalvik bytecode)
//!   resources.arsc
//!   res/ , assets/ , lib/
//!   META-INF/             (v1 JAR signature: *.RSA / *.DSA / *.EC)

use std::path::Path;
use std::process::Command;

use axmldecoder::{parse, Node, Element};

use super::{AppFinding, AppReport, compute_score};

/// Permissions worth calling out when present.
const DANGEROUS_PERMS: &[&str] = &[
    "SEND_SMS", "READ_SMS", "RECEIVE_SMS", "READ_CONTACTS", "WRITE_CONTACTS",
    "ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "RECORD_AUDIO", "CAMERA",
    "READ_PHONE_STATE", "READ_CALL_LOG", "WRITE_CALL_LOG", "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE", "REQUEST_INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW",
    "QUERY_ALL_PACKAGES", "MANAGE_EXTERNAL_STORAGE", "BIND_ACCESSIBILITY_SERVICE",
];

pub fn scan(apk_path: &Path) -> anyhow::Result<AppReport> {
    let temp = tempfile::tempdir()?;

    // Extract the .apk (it's a ZIP), same pattern as the .ipa scanner.
    let status = Command::new("unzip")
        .args(["-q", "-o", &apk_path.to_string_lossy(), "-d", &temp.path().to_string_lossy()])
        .status()?;
    if !status.success() {
        anyhow::bail!("Failed to extract .apk file (is `unzip` installed?)");
    }

    let manifest_path = temp.path().join("AndroidManifest.xml");
    if !manifest_path.exists() {
        anyhow::bail!("No AndroidManifest.xml found — not a valid APK");
    }
    let manifest_bytes = std::fs::read(&manifest_path)?;
    let doc = parse(&manifest_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to decode AndroidManifest.xml: {e}"))?;

    // Flatten every element for easy querying (borrowed from the document).
    let mut elements: Vec<&Element> = Vec::new();
    if let Some(root) = doc.get_root() {
        collect(root, &mut elements);
    }

    let manifest_el = elements.iter().find(|e| e.get_tag() == "manifest");
    let app_el = elements.iter().find(|e| e.get_tag() == "application");

    let package = manifest_el.and_then(|e| attr(e, "package")).unwrap_or_default();
    let version = manifest_el
        .and_then(|e| attr(e, "versionName"))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "unknown".into());
    let app_name = manifest_el
        .and_then(|e| attr(e, "label"))
        .filter(|v| !v.is_empty() && !v.starts_with("@"))
        .or_else(|| if package.is_empty() { None } else { Some(package.clone()) })
        .unwrap_or_else(|| "unknown".into());

    let mut findings: Vec<AppFinding> = Vec::new();

    // 1. Debuggable ---------------------------------------------------------
    let debuggable = app_el.and_then(|e| attr(e, "debuggable")).as_deref() == Some("true");
    findings.push(AppFinding {
        check: "Debuggable flag".into(),
        category: "hardening".into(),
        severity: "critical".into(),
        passed: !debuggable,
        detail: if debuggable {
            "android:debuggable=\"true\" — the app is debuggable in production".into()
        } else {
            "App is not debuggable".into()
        },
        remediation: "Remove android:debuggable or set it to false for release builds".into(),
    });

    // 2. allowBackup (defaults to true when absent, pre-Android 12) ---------
    let backup_attr = app_el.and_then(|e| attr(e, "allowBackup"));
    let backup_enabled = backup_attr.as_deref() != Some("false");
    findings.push(AppFinding {
        check: "Application backup".into(),
        category: "data".into(),
        severity: "medium".into(),
        passed: !backup_enabled,
        detail: if backup_enabled {
            "android:allowBackup is enabled (or unset — defaults to true) — app data can be extracted via adb backup".into()
        } else {
            "Backups are disabled".into()
        },
        remediation: "Set android:allowBackup=\"false\" unless backups are required".into(),
    });

    // 3. Cleartext traffic --------------------------------------------------
    let cleartext = app_el.and_then(|e| attr(e, "usesCleartextTraffic")).as_deref() == Some("true");
    let nsc = app_el.and_then(|e| attr(e, "networkSecurityConfig"));
    findings.push(AppFinding {
        check: "Cleartext traffic".into(),
        category: "network".into(),
        severity: "high".into(),
        passed: !cleartext,
        detail: if cleartext {
            "android:usesCleartextTraffic=\"true\" — the app permits unencrypted HTTP".into()
        } else if nsc.is_some() {
            "Cleartext not explicitly enabled; a network security config is present".into()
        } else {
            "Cleartext traffic not explicitly enabled".into()
        },
        remediation: "Disable cleartext traffic and enforce HTTPS via a network security config".into(),
    });

    // 4. minSdkVersion ------------------------------------------------------
    let uses_sdk = elements.iter().find(|e| e.get_tag() == "uses-sdk");
    let min_sdk = uses_sdk
        .and_then(|e| attr(e, "minSdkVersion"))
        .and_then(|v| v.parse::<i64>().ok());
    if let Some(min) = min_sdk {
        findings.push(AppFinding {
            check: "Minimum SDK version".into(),
            category: "hardening".into(),
            severity: "medium".into(),
            passed: min >= 26,
            detail: format!("minSdkVersion = {min}{}", if min < 26 {
                " — supports Android versions that miss modern security mitigations" } else { "" }),
            remediation: "Raise minSdkVersion to 26+ (Android 8.0) where feasible".into(),
        });
    }

    // 5. Exported components without a permission ---------------------------
    let mut exported_open = Vec::new();
    for e in &elements {
        let tag = e.get_tag();
        if matches!(tag, "activity" | "service" | "receiver" | "provider") {
            let exported = attr(e, "exported").as_deref() == Some("true");
            let has_perm = attr(e, "permission").map_or(false, |p| !p.is_empty());
            if exported && !has_perm {
                let name = attr(e, "name").unwrap_or_else(|| "(unnamed)".into());
                exported_open.push(format!("{tag} {name}"));
            }
        }
    }
    findings.push(AppFinding {
        check: "Exported components".into(),
        category: "access-control".into(),
        severity: "high".into(),
        passed: exported_open.is_empty(),
        detail: if exported_open.is_empty() {
            "No components are exported without a permission".into()
        } else {
            format!("{} exported without a permission: {}",
                exported_open.len(),
                truncate_list(&exported_open, 6))
        },
        remediation: "Set android:exported=\"false\" or guard with a signature-level permission".into(),
    });

    // 6. Dangerous permissions (informational inventory) --------------------
    let mut perms = Vec::new();
    for e in &elements {
        if e.get_tag() == "uses-permission" {
            if let Some(name) = attr(e, "name") {
                let short = name.rsplit('.').next().unwrap_or(&name).to_string();
                if DANGEROUS_PERMS.contains(&short.as_str()) {
                    perms.push(short);
                }
            }
        }
    }
    perms.sort();
    perms.dedup();
    if !perms.is_empty() {
        findings.push(AppFinding {
            check: "Dangerous permissions".into(),
            category: "privacy".into(),
            severity: "low".into(),
            passed: false,
            detail: format!("Requests {} sensitive permission(s): {}", perms.len(), truncate_list(&perms, 12)),
            remediation: "Request only the permissions the app genuinely needs; justify each in the store listing".into(),
        });
    }

    // 7. Signing scheme -----------------------------------------------------
    let has_v1 = has_v1_signature(temp.path());
    let has_v2plus = apk_has_signing_block(apk_path);
    let signed = has_v1 || has_v2plus;
    let mut scheme = Vec::new();
    if has_v1 { scheme.push("v1 (JAR)"); }
    if has_v2plus { scheme.push("v2/v3 (APK Signing Block)"); }
    findings.push(AppFinding {
        check: "Code signing".into(),
        category: "integrity".into(),
        severity: "high".into(),
        passed: has_v2plus,
        detail: if !signed {
            "No signature detected — the APK is unsigned".into()
        } else if !has_v2plus {
            "Only a v1 (JAR) signature is present — vulnerable to Janus (CVE-2017-13156); no APK Signing Block".into()
        } else {
            format!("Signed with {}", scheme.join(" + "))
        },
        remediation: "Sign with APK Signature Scheme v2+ (and v3 for key rotation)".into(),
    });

    // 8. Hardcoded secrets in bundled resources/assets ----------------------
    scan_secrets(temp.path(), &mut findings);

    let score = compute_score(&findings);
    let passed = findings.iter().filter(|f| f.passed).count();
    let failed = findings.iter().filter(|f| !f.passed).count();

    Ok(AppReport {
        app_name,
        app_type: "apk".into(),
        bundle_id: if package.is_empty() { "unknown".into() } else { package },
        version,
        score,
        findings,
        frameworks: Vec::new(),
        entitlements: Vec::new(),
        passed,
        failed,
    })
}

/// Recursively flatten the AXML tree into a flat list of element references.
fn collect<'a>(node: &'a Node, out: &mut Vec<&'a Element>) {
    if let Node::Element(el) = node {
        out.push(el);
        for child in el.get_children() {
            collect(child, out);
        }
    }
}

/// Read an attribute by local name, tolerating an `android:`/namespace prefix
/// (axmldecoder may key attributes with or without the resolved prefix).
fn attr(el: &Element, local: &str) -> Option<String> {
    let attrs = el.get_attributes();
    if let Some(v) = attrs.get(local) {
        return Some(v.clone());
    }
    for (k, v) in attrs {
        let name = k.rsplit(':').next().unwrap_or(k);
        if name == local {
            return Some(v.clone());
        }
    }
    None
}

fn truncate_list(items: &[String], max: usize) -> String {
    if items.len() <= max {
        items.join(", ")
    } else {
        format!("{}, +{} more", items[..max].join(", "), items.len() - max)
    }
}

/// v1 JAR signature: a signing cert block in META-INF/.
fn has_v1_signature(root: &Path) -> bool {
    let meta = root.join("META-INF");
    let Ok(entries) = std::fs::read_dir(&meta) else { return false };
    for e in entries.flatten() {
        if let Some(ext) = e.path().extension().and_then(|x| x.to_str()) {
            if matches!(ext.to_uppercase().as_str(), "RSA" | "DSA" | "EC") {
                return true;
            }
        }
    }
    false
}

/// v2/v3 signature lives in the APK Signing Block, tagged with a fixed magic
/// string just before the ZIP central directory.
fn apk_has_signing_block(apk_path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(apk_path) else { return false };
    bytes.windows(16).any(|w| w == b"APK Sig Block 42")
}

/// Light secrets pass over bundled text resources/assets (dex bytecode is not
/// decompiled here — this catches secrets shipped in plaintext resources).
fn scan_secrets(root: &Path, findings: &mut Vec<AppFinding>) {
    use std::io::Read;
    let patterns: [(&str, &str, &str); 6] = [
        ("AIza", "Google API key", "high"),
        ("AKIA", "AWS access key", "critical"),
        ("sk_live_", "Stripe live key", "critical"),
        ("-----BEGIN", "Private key", "critical"),
        ("firebaseio.com", "Firebase database URL", "medium"),
        ("AAAA", "FCM legacy server key", "medium"),
    ];
    let mut hits: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
        if !matches!(ext.as_str(), "xml" | "json" | "properties" | "txt" | "js" | "html" | "yml" | "yaml" | "" ) {
            continue;
        }
        // Skip large binaries.
        if std::fs::metadata(p).map(|m| m.len() > 2_000_000).unwrap_or(true) {
            continue;
        }
        let mut buf = String::new();
        if std::fs::File::open(p).and_then(|mut f| f.read_to_string(&mut buf)).is_err() {
            continue;
        }
        for (needle, name, sev) in &patterns {
            // FCM key heuristic: "AAAA" alone is noisy — require it to look like a key.
            let matched = if *needle == "AAAA" {
                buf.contains("AAAA") && buf.contains("google") && buf.len() < 1_000_000 && buf.contains(":APA91")
            } else {
                buf.contains(needle)
            };
            if matched && seen.insert((*name, sev.to_string())) {
                hits.push(format!("{name} ({sev})"));
            }
        }
    }
    let passed = hits.is_empty();
    findings.push(AppFinding {
        check: "Hardcoded secrets in resources".into(),
        category: "secrets".into(),
        severity: "critical".into(),
        passed,
        detail: if passed {
            "No plaintext secrets detected in bundled resources".into()
        } else {
            format!("Potential secret(s) in resources/assets: {}", hits.join(", "))
        },
        remediation: "Move secrets out of the APK; fetch at runtime or use the Android Keystore".into(),
    });
}
