//! macOS .pkg installer scanner + Android APK + Windows EXE/MSI + Linux deb/rpm.
//!
//! Supported formats:
//!   .pkg   — macOS installer (xar archive)
//!   .apk   — Android application package (ZIP with classes.dex + AndroidManifest.xml)
//!   .aab   — Android App Bundle
//!   .exe   — Windows PE executable
//!   .msi   — Windows installer
//!   .deb   — Debian package
//!   .rpm   — Red Hat package

use std::path::Path;
use std::process::Command;

use super::{AppFinding, AppReport, compute_score};

pub fn scan(pkg_path: &Path) -> anyhow::Result<AppReport> {
    let ext = pkg_path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "pkg" => scan_macos_pkg(pkg_path),
        "apk" => scan_android_apk(pkg_path),
        "aab" => scan_android_aab(pkg_path),
        "exe" | "msi" => scan_windows(pkg_path),
        "deb" => scan_linux_deb(pkg_path),
        "rpm" => scan_linux_rpm(pkg_path),
        _ => anyhow::bail!("Unsupported: .{}. Supported: .app, .ipa, .pkg, .apk, .aab, .exe, .msi, .deb, .rpm", ext),
    }
}

// ── macOS .pkg ──────────────────────────────────────────────────────────

fn scan_macos_pkg(pkg_path: &Path) -> anyhow::Result<AppReport> {
    let temp = tempfile::tempdir()?;
    let mut findings = Vec::new();

    // Expand pkg
    let _ = Command::new("pkgutil")
        .args(["--expand", &pkg_path.to_string_lossy(), &temp.path().join("expanded").to_string_lossy()])
        .status();

    // Check installer scripts
    let scripts_dir = temp.path().join("expanded");
    if scripts_dir.exists() {
        findings.extend(check_pkg_scripts(&scripts_dir));
    }

    // Check signing
    let signed = Command::new("pkgutil")
        .args(["--check-signature", &pkg_path.to_string_lossy()])
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("signed"))
        .unwrap_or(false);

    findings.push(AppFinding {
        check: "Package Signing".into(),
        category: "integrity".into(),
        severity: "critical".into(),
        passed: signed,
        detail: if signed { "Package is signed".into() } else { "Package is NOT signed".into() },
        remediation: "Sign with: productsign --sign \"Developer ID Installer\" pkg".into(),
    });

    // Check notarization
    let notarized = Command::new("spctl")
        .args(["--assess", "--type", "install", &pkg_path.to_string_lossy()])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    findings.push(AppFinding {
        check: "Notarization".into(),
        category: "integrity".into(),
        severity: "high".into(),
        passed: notarized,
        detail: if notarized { "Package is notarized".into() } else { "Package is NOT notarized".into() },
        remediation: "Submit to Apple notarization service".into(),
    });

    let score = compute_score(&findings);
    let passed = findings.iter().filter(|f| f.passed).count();
    let failed = findings.iter().filter(|f| !f.passed).count();

    Ok(AppReport {
        app_name: pkg_path.file_stem().unwrap_or_default().to_string_lossy().to_string(),
        app_type: "pkg".into(),
        bundle_id: "unknown".into(),
        version: "unknown".into(),
        score, findings,
        frameworks: vec![], entitlements: vec![],
        passed, failed,
    })
}

fn check_pkg_scripts(expanded_dir: &Path) -> Vec<AppFinding> {
    let mut findings = Vec::new();

    // Walk for scripts
    for entry in walkdir::WalkDir::new(expanded_dir).into_iter().filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if name == "preinstall" || name == "postinstall"
            || name == "preflight" || name == "postflight"
        {
            let content = std::fs::read_to_string(entry.path()).unwrap_or_default();
            let lower = content.to_lowercase();

            // curl | bash
            if lower.contains("curl") && (lower.contains("bash") || lower.contains("sh")) {
                findings.push(AppFinding {
                    check: format!("Script {}: curl-pipe-bash", name),
                    category: "scripts".into(),
                    severity: "critical".into(),
                    passed: false,
                    detail: format!("Installer script '{}' downloads and executes code", name),
                    remediation: "Bundle scripts instead of downloading at install time".into(),
                });
            }

            // chmod 777
            if lower.contains("chmod 777") || lower.contains("chmod -R 777") {
                findings.push(AppFinding {
                    check: format!("Script {}: chmod 777", name),
                    category: "scripts".into(),
                    severity: "high".into(),
                    passed: false,
                    detail: format!("Script '{}' sets world-writable permissions", name),
                    remediation: "Use restrictive permissions (755 for dirs, 644 for files)".into(),
                });
            }

            // Hardcoded passwords
            if lower.contains("password") && lower.contains("=") {
                findings.push(AppFinding {
                    check: format!("Script {}: hardcoded password", name),
                    category: "secrets".into(),
                    severity: "critical".into(),
                    passed: false,
                    detail: format!("Script '{}' may contain hardcoded credentials", name),
                    remediation: "Use macOS Keychain or prompt user for credentials".into(),
                });
            }

            // Runs as root
            if lower.contains("sudo") || lower.contains("dscl") {
                findings.push(AppFinding {
                    check: format!("Script {}: elevated privileges", name),
                    category: "scripts".into(),
                    severity: "medium".into(),
                    passed: false,
                    detail: format!("Script '{}' uses sudo or system directory commands", name),
                    remediation: "Minimize root operations in installer scripts".into(),
                });
            }
        }
    }
    findings
}

// ── Android APK ─────────────────────────────────────────────────────────

fn scan_android_apk(apk_path: &Path) -> anyhow::Result<AppReport> {
    let temp = tempfile::tempdir()?;
    let mut findings = Vec::new();

    // Extract APK (ZIP)
    let _ = Command::new("unzip")
        .args(["-q", "-o", &apk_path.to_string_lossy(), "-d", &temp.path().to_string_lossy()])
        .status();

    // Parse AndroidManifest.xml (binary XML — use aapt if available)
    let manifest = Command::new("aapt")
        .args(["dump", "badging", &apk_path.to_string_lossy()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let (app_name, bundle_id, version) = parse_apk_manifest(&manifest);

    // 1. Debuggable
    let debuggable = manifest.contains("application-debuggable");
    findings.push(AppFinding {
        check: "Debuggable Flag".into(),
        category: "security".into(),
        severity: "critical".into(),
        passed: !debuggable,
        detail: if debuggable { "APK is debuggable — attackers can attach debugger".into() } else { "Not debuggable".into() },
        remediation: "Set android:debuggable=false in AndroidManifest.xml".into(),
    });

    // 2. Backup allowed
    let backup = manifest.contains("allowBackup='true'") || !manifest.contains("allowBackup");
    findings.push(AppFinding {
        check: "Backup Allowed".into(),
        category: "data".into(),
        severity: "high".into(),
        passed: !backup,
        detail: if backup { "App data can be backed up via ADB".into() } else { "Backup disabled".into() },
        remediation: "Set android:allowBackup=false in AndroidManifest.xml".into(),
    });

    // 3. Cleartext traffic
    let cleartext = manifest.contains("usesCleartextTraffic='true'");
    findings.push(AppFinding {
        check: "Cleartext Traffic".into(),
        category: "network".into(),
        severity: "high".into(),
        passed: !cleartext,
        detail: if cleartext { "App allows HTTP cleartext traffic".into() } else { "HTTPS enforced".into() },
        remediation: "Set android:usesCleartextTraffic=false or use network_security_config.xml".into(),
    });

    // 4. Min SDK version
    if let Some(sdk) = extract_field(&manifest, "sdkVersion:'") {
        let min_sdk: u32 = sdk.parse().unwrap_or(0);
        findings.push(AppFinding {
            check: "Minimum SDK Version".into(),
            category: "compatibility".into(),
            severity: "medium".into(),
            passed: min_sdk >= 28,
            detail: format!("minSdkVersion={} {}", min_sdk, if min_sdk < 28 { "— below API 28 lacks security features" } else { "— current" }),
            remediation: "Set minSdkVersion to at least 28 (Android 9)".into(),
        });
    }

    // 5. Dangerous permissions
    let dangerous_perms = [
        ("CAMERA", "medium"), ("RECORD_AUDIO", "medium"),
        ("READ_CONTACTS", "medium"), ("READ_SMS", "high"),
        ("SEND_SMS", "high"), ("CALL_PHONE", "high"),
        ("READ_CALL_LOG", "high"), ("ACCESS_FINE_LOCATION", "medium"),
        ("READ_EXTERNAL_STORAGE", "medium"), ("WRITE_EXTERNAL_STORAGE", "medium"),
        ("INSTALL_PACKAGES", "critical"), ("REQUEST_INSTALL_PACKAGES", "high"),
        ("SYSTEM_ALERT_WINDOW", "high"),
    ];
    for (perm, sev) in &dangerous_perms {
        if manifest.contains(perm) {
            findings.push(AppFinding {
                check: format!("Permission: {}", perm),
                category: "permissions".into(),
                severity: sev.to_string(),
                passed: false,
                detail: format!("App requests dangerous permission: {}", perm),
                remediation: format!("Review if {} is necessary. Remove if unused.", perm),
            });
        }
    }

    // 6. Signing
    let signed = Command::new("jarsigner")
        .args(["-verify", &apk_path.to_string_lossy()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("jar verified"))
        .unwrap_or(false);

    findings.push(AppFinding {
        check: "APK Signing".into(),
        category: "integrity".into(),
        severity: "critical".into(),
        passed: signed,
        detail: if signed { "APK is signed".into() } else { "APK signature could not be verified".into() },
        remediation: "Sign APK with apksigner or jarsigner".into(),
    });

    // 7. Secrets in DEX
    let strings_out = Command::new("strings")
        .args(["-a", &temp.path().join("classes.dex").to_string_lossy()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    for (pattern, name) in &[("AKIA", "AWS Key"), ("sk_live_", "Stripe Key"), ("AIza", "Firebase/GCP Key")] {
        if strings_out.contains(pattern) {
            findings.push(AppFinding {
                check: format!("Secret in DEX: {}", name),
                category: "secrets".into(),
                severity: "critical".into(),
                passed: false,
                detail: format!("{} found in compiled DEX bytecode", name),
                remediation: "Use Android Keystore or server-side secret management".into(),
            });
        }
    }

    let score = compute_score(&findings);
    let passed = findings.iter().filter(|f| f.passed).count();
    let failed = findings.iter().filter(|f| !f.passed).count();

    Ok(AppReport {
        app_name, app_type: "apk".into(), bundle_id, version,
        score, findings, frameworks: vec![], entitlements: vec![],
        passed, failed,
    })
}

fn scan_android_aab(aab_path: &Path) -> anyhow::Result<AppReport> {
    // AAB is similar to APK but uses bundletool — scan as ZIP for now
    scan_android_apk(aab_path)
}

fn parse_apk_manifest(manifest: &str) -> (String, String, String) {
    let name = extract_field(manifest, "application-label:'").unwrap_or("unknown".into());
    let pkg = extract_field(manifest, "package: name='").unwrap_or("unknown".into());
    let ver = extract_field(manifest, "versionName='").unwrap_or("unknown".into());
    (name, pkg, ver)
}

fn extract_field(text: &str, prefix: &str) -> Option<String> {
    text.find(prefix).map(|start| {
        let rest = &text[start + prefix.len()..];
        rest.split('\'').next().unwrap_or("").to_string()
    })
}

// ── Windows EXE/MSI ─────────────────────────────────────────────────────

fn scan_windows(exe_path: &Path) -> anyhow::Result<AppReport> {
    let mut findings = Vec::new();
    let ext = exe_path.extension().and_then(|e| e.to_str()).unwrap_or("exe");

    // Extract strings
    let strings_out = Command::new("strings")
        .args(["-a", &exe_path.to_string_lossy()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    // Check for secrets
    for (pattern, name) in &[("AKIA", "AWS Key"), ("sk_live_", "Stripe Key"),
        ("-----BEGIN", "Private Key"), ("password", "Hardcoded password")] {
        if strings_out.contains(pattern) {
            findings.push(AppFinding {
                check: format!("Secret: {}", name),
                category: "secrets".into(),
                severity: "critical".into(),
                passed: false,
                detail: format!("{} found in binary strings", name),
                remediation: "Use Windows Credential Manager or DPAPI for secrets".into(),
            });
        }
    }

    // Check for http URLs
    let http_count = strings_out.matches("http://").count();
    if http_count > 3 {
        findings.push(AppFinding {
            check: "HTTP URLs".into(), category: "network".into(),
            severity: "medium".into(), passed: false,
            detail: format!("{} HTTP URLs found", http_count),
            remediation: "Use HTTPS for all network connections".into(),
        });
    }

    let score = compute_score(&findings);
    let passed = findings.iter().filter(|f| f.passed).count();
    let failed = findings.iter().filter(|f| !f.passed).count();

    Ok(AppReport {
        app_name: exe_path.file_stem().unwrap_or_default().to_string_lossy().to_string(),
        app_type: ext.to_string(), bundle_id: "N/A".into(), version: "unknown".into(),
        score, findings, frameworks: vec![], entitlements: vec![],
        passed, failed,
    })
}

// ── Linux deb/rpm ───────────────────────────────────────────────────────

fn scan_linux_deb(deb_path: &Path) -> anyhow::Result<AppReport> {
    let temp = tempfile::tempdir()?;
    let mut findings = Vec::new();

    // Extract deb
    let _ = Command::new("dpkg-deb")
        .args(["-x", &deb_path.to_string_lossy(), &temp.path().to_string_lossy()])
        .status();

    // Extract control info
    let _ = Command::new("dpkg-deb")
        .args(["-e", &deb_path.to_string_lossy(), &temp.path().join("DEBIAN").to_string_lossy()])
        .status();

    // Check maintainer scripts
    for script in &["preinst", "postinst", "prerm", "postrm"] {
        let script_path = temp.path().join("DEBIAN").join(script);
        if script_path.exists() {
            let content = std::fs::read_to_string(&script_path).unwrap_or_default();
            let lower = content.to_lowercase();

            if lower.contains("curl") && lower.contains("bash") {
                findings.push(AppFinding {
                    check: format!("{}: curl-pipe-bash", script),
                    category: "scripts".into(), severity: "critical".into(), passed: false,
                    detail: format!("Maintainer script '{}' downloads and executes code", script),
                    remediation: "Bundle dependencies instead of downloading at install time".into(),
                });
            }

            if lower.contains("chmod 777") {
                findings.push(AppFinding {
                    check: format!("{}: world-writable", script),
                    category: "scripts".into(), severity: "high".into(), passed: false,
                    detail: format!("Script '{}' sets 777 permissions", script),
                    remediation: "Use restrictive permissions".into(),
                });
            }
        }
    }

    // Check for SUID binaries in package
    if let Ok(output) = Command::new("find")
        .args([&temp.path().to_string_lossy().to_string(), "-perm", "-4000", "-type", "f"])
        .output()
    {
        let suid = String::from_utf8_lossy(&output.stdout);
        let count = suid.lines().filter(|l| !l.is_empty()).count();
        if count > 0 {
            findings.push(AppFinding {
                check: "SUID binaries in package".into(),
                category: "system".into(), severity: "high".into(), passed: false,
                detail: format!("{} SUID binary(ies) in package", count),
                remediation: "Review if SUID is necessary. Use capabilities instead.".into(),
            });
        }
    }

    let score = compute_score(&findings);
    let passed = findings.iter().filter(|f| f.passed).count();
    let failed = findings.iter().filter(|f| !f.passed).count();

    Ok(AppReport {
        app_name: deb_path.file_stem().unwrap_or_default().to_string_lossy().to_string(),
        app_type: "deb".into(), bundle_id: "N/A".into(), version: "unknown".into(),
        score, findings, frameworks: vec![], entitlements: vec![],
        passed, failed,
    })
}

fn scan_linux_rpm(rpm_path: &Path) -> anyhow::Result<AppReport> {
    let mut findings = Vec::new();

    // Extract RPM scripts
    let scripts = Command::new("rpm")
        .args(["-qp", "--scripts", &rpm_path.to_string_lossy()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let lower = scripts.to_lowercase();
    if lower.contains("curl") && lower.contains("bash") {
        findings.push(AppFinding {
            check: "RPM script: curl-pipe-bash".into(),
            category: "scripts".into(), severity: "critical".into(), passed: false,
            detail: "RPM scriptlet downloads and executes code".into(),
            remediation: "Bundle dependencies in the RPM".into(),
        });
    }

    let score = compute_score(&findings);
    let passed = findings.iter().filter(|f| f.passed).count();
    let failed = findings.iter().filter(|f| !f.passed).count();

    Ok(AppReport {
        app_name: rpm_path.file_stem().unwrap_or_default().to_string_lossy().to_string(),
        app_type: "rpm".into(), bundle_id: "N/A".into(), version: "unknown".into(),
        score, findings, frameworks: vec![], entitlements: vec![],
        passed, failed,
    })
}
