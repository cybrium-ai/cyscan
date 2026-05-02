//! macOS .app bundle scanner.
//!
//! An .app is a directory:
//!   MyApp.app/
//!     Contents/
//!       Info.plist          — bundle metadata
//!       MacOS/MyApp         — Mach-O binary
//!       Frameworks/         — embedded frameworks
//!       _CodeSignature/     — code signing
//!       embedded.provisionprofile (optional)
//!       Resources/
//!         PrivacyInfo.xcprivacy (optional)

use std::path::Path;
use std::process::Command;

use super::{AppFinding, AppReport, compute_score};

pub fn scan(app_path: &Path) -> anyhow::Result<AppReport> {
    let contents = app_path.join("Contents");
    let info_plist = contents.join("Info.plist");

    // Read Info.plist
    let (bundle_id, version, app_name) = read_info_plist(&info_plist);

    let mut findings = Vec::new();
    let mut frameworks = Vec::new();
    let entitlements: Vec<String>;

    // 1. Code signing
    findings.push(check_code_signing(app_path));

    // 2. Entitlements
    let (ent_findings, ent_list) = check_entitlements(app_path);
    findings.extend(ent_findings);
    entitlements = ent_list;

    // 3. App Transport Security
    findings.push(check_ats(&info_plist));

    // 4. URL schemes
    findings.extend(check_url_schemes(&info_plist));

    // 5. Hardened Runtime
    findings.push(check_hardened_runtime(app_path));

    // 6. Library Validation
    findings.push(check_library_validation(app_path));

    // 7. Embedded frameworks
    let fw_dir = contents.join("Frameworks");
    if fw_dir.exists() {
        let (fw_findings, fw_list) = check_frameworks(&fw_dir);
        findings.extend(fw_findings);
        frameworks = fw_list;
    }

    // 8. Secrets in binary
    let binary_path = find_binary(&contents, &app_name);
    if let Some(bin) = &binary_path {
        findings.extend(check_binary_secrets(bin));
    }

    // 9. Privacy manifest
    findings.push(check_privacy_manifest(&contents));

    // 10. Provisioning profile
    findings.push(check_provisioning_profile(&contents));

    // 11. Notarization
    findings.push(check_notarization(app_path));

    // 12. Minimum OS version
    findings.push(check_min_os_version(&info_plist));

    let score = compute_score(&findings);
    let passed = findings.iter().filter(|f| f.passed).count();
    let failed = findings.iter().filter(|f| !f.passed).count();

    Ok(AppReport {
        app_name,
        app_type: "app".into(),
        bundle_id,
        version,
        score,
        findings,
        frameworks,
        entitlements,
        passed,
        failed,
    })
}

fn read_info_plist(plist_path: &Path) -> (String, String, String) {
    let read = |key: &str| -> String {
        Command::new("defaults")
            .args(["read", &plist_path.to_string_lossy(), key])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };
    let bundle_id = read("CFBundleIdentifier");
    let version = read("CFBundleShortVersionString");
    let name = read("CFBundleName");
    (
        if bundle_id.is_empty() { "unknown".into() } else { bundle_id },
        if version.is_empty() { "unknown".into() } else { version },
        if name.is_empty() { "unknown".into() } else { name },
    )
}

fn check_code_signing(app_path: &Path) -> AppFinding {
    let out = Command::new("codesign")
        .args(["--verify", "--deep", "--strict", &app_path.to_string_lossy()])
        .output();
    let passed = out.map(|o| o.status.success()).unwrap_or(false);
    AppFinding {
        check: "Code Signing".into(),
        category: "integrity".into(),
        severity: "critical".into(),
        passed,
        detail: if passed {
            "App is properly code-signed with valid signature".into()
        } else {
            "App is NOT properly code-signed or signature is invalid".into()
        },
        remediation: "Sign with: codesign --deep --force --sign \"Developer ID Application: ...\" MyApp.app".into(),
    }
}

fn check_entitlements(app_path: &Path) -> (Vec<AppFinding>, Vec<String>) {
    let out = Command::new("codesign")
        .args(["-d", "--entitlements", ":-", &app_path.to_string_lossy()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let mut findings = Vec::new();
    let mut ent_list = Vec::new();

    // Extract entitlement keys
    for line in out.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("<key>") && trimmed.ends_with("</key>") {
            let key = trimmed.trim_start_matches("<key>").trim_end_matches("</key>");
            ent_list.push(key.to_string());
        }
    }

    // Dangerous entitlements
    let dangerous = [
        ("com.apple.security.cs.disable-library-validation", "critical", "Disables library validation — allows loading unsigned dylibs"),
        ("com.apple.security.cs.allow-unsigned-executable-memory", "high", "Allows unsigned executable memory — JIT compilation risk"),
        ("com.apple.security.cs.disable-executable-page-protection", "critical", "Disables executable page protection"),
        ("com.apple.security.cs.allow-dyld-environment-variables", "high", "Allows DYLD environment variables — dylib injection risk"),
        ("com.apple.security.get-task-allow", "high", "Allows debugging — should be removed for release builds"),
        ("com.apple.security.cs.debugger", "high", "Debugger entitlement present in production build"),
        ("com.apple.security.temporary-exception.files.absolute-path.read-write", "medium", "Temporary file access exception"),
    ];

    for (ent, sev, desc) in &dangerous {
        let has_it = ent_list.iter().any(|e| e == *ent);
        if has_it {
            findings.push(AppFinding {
                check: format!("Dangerous entitlement: {}", ent.split('.').last().unwrap_or(ent)),
                category: "entitlements".into(),
                severity: sev.to_string(),
                passed: false,
                detail: desc.to_string(),
                remediation: format!("Remove {} from entitlements unless absolutely required", ent),
            });
        }
    }

    // Check sandbox
    let sandboxed = ent_list.iter().any(|e| e == "com.apple.security.app-sandbox");
    findings.push(AppFinding {
        check: "App Sandbox".into(),
        category: "entitlements".into(),
        severity: "high".into(),
        passed: sandboxed,
        detail: if sandboxed {
            "App is sandboxed".into()
        } else {
            "App is NOT sandboxed — has full filesystem and network access".into()
        },
        remediation: "Enable App Sandbox in Xcode capabilities".into(),
    });

    (findings, ent_list)
}

fn check_ats(plist_path: &Path) -> AppFinding {
    let out = Command::new("defaults")
        .args(["read", &plist_path.to_string_lossy(), "NSAppTransportSecurity"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let allows_arbitrary = out.contains("NSAllowsArbitraryLoads = 1")
        || out.contains("NSAllowsArbitraryLoads = true");

    AppFinding {
        check: "App Transport Security (ATS)".into(),
        category: "network".into(),
        severity: "high".into(),
        passed: !allows_arbitrary,
        detail: if allows_arbitrary {
            "ATS allows arbitrary HTTP loads — all network traffic can be unencrypted".into()
        } else {
            "ATS is enforced — network connections require HTTPS".into()
        },
        remediation: "Remove NSAllowsArbitraryLoads from Info.plist. Use per-domain exceptions if needed.".into(),
    }
}

fn check_url_schemes(plist_path: &Path) -> Vec<AppFinding> {
    let out = Command::new("defaults")
        .args(["read", &plist_path.to_string_lossy(), "CFBundleURLTypes"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let mut findings = Vec::new();
    if out.contains("CFBundleURLSchemes") {
        // Check for common vulnerable schemes
        let risky_schemes = ["http", "https", "file", "javascript"];
        for scheme in &risky_schemes {
            if out.to_lowercase().contains(scheme) {
                findings.push(AppFinding {
                    check: format!("URL scheme: {}", scheme),
                    category: "network".into(),
                    severity: "medium".into(),
                    passed: false,
                    detail: format!("App registers '{}' URL scheme — potential for URL hijacking", scheme),
                    remediation: "Use unique custom URL schemes. Validate all URL inputs.".into(),
                });
            }
        }
    }
    findings
}

fn check_hardened_runtime(app_path: &Path) -> AppFinding {
    let out = Command::new("codesign")
        .args(["-d", "-vvv", &app_path.to_string_lossy()])
        .output()
        .map(|o| {
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            format!("{}{}", stdout, stderr)
        })
        .unwrap_or_default();

    let hardened = out.contains("flags=0x10000(runtime)") || out.contains("runtime");
    AppFinding {
        check: "Hardened Runtime".into(),
        category: "integrity".into(),
        severity: "high".into(),
        passed: hardened,
        detail: if hardened {
            "Hardened Runtime is enabled".into()
        } else {
            "Hardened Runtime is NOT enabled — app is vulnerable to code injection".into()
        },
        remediation: "Enable Hardened Runtime in Xcode: Signing & Capabilities > Hardened Runtime".into(),
    }
}

fn check_library_validation(app_path: &Path) -> AppFinding {
    let out = Command::new("codesign")
        .args(["-d", "--entitlements", ":-", &app_path.to_string_lossy()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let disabled = out.contains("disable-library-validation");
    AppFinding {
        check: "Library Validation".into(),
        category: "integrity".into(),
        severity: "high".into(),
        passed: !disabled,
        detail: if disabled {
            "Library validation is DISABLED — unsigned dylibs can be loaded".into()
        } else {
            "Library validation is enabled — only signed libraries can load".into()
        },
        remediation: "Remove com.apple.security.cs.disable-library-validation entitlement".into(),
    }
}

fn check_frameworks(fw_dir: &Path) -> (Vec<AppFinding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut fw_list = Vec::new();

    if let Ok(entries) = std::fs::read_dir(fw_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".framework") || name.ends_with(".dylib") {
                fw_list.push(name.clone());

                // Check if framework is signed
                let signed = Command::new("codesign")
                    .args(["--verify", &entry.path().to_string_lossy()])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);

                if !signed {
                    findings.push(AppFinding {
                        check: format!("Unsigned framework: {}", name),
                        category: "integrity".into(),
                        severity: "high".into(),
                        passed: false,
                        detail: format!("Embedded framework '{}' is not properly signed", name),
                        remediation: "Sign all embedded frameworks with your Developer ID".into(),
                    });
                }
            }
        }
    }

    (findings, fw_list)
}

fn find_binary(contents: &Path, _app_name: &str) -> Option<std::path::PathBuf> {
    let macos_dir = contents.join("MacOS");
    if macos_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&macos_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    return Some(path);
                }
            }
        }
    }
    None
}

fn check_binary_secrets(binary_path: &Path) -> Vec<AppFinding> {
    let out = Command::new("strings")
        .args(["-a", &binary_path.to_string_lossy()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let mut findings = Vec::new();

    let secret_patterns = [
        ("AKIA[0-9A-Z]{16}", "AWS Access Key", "critical"),
        ("sk_live_[A-Za-z0-9]{24,}", "Stripe Secret Key", "critical"),
        ("ghp_[A-Za-z0-9]{36}", "GitHub PAT", "critical"),
        ("-----BEGIN RSA PRIVATE KEY-----", "RSA Private Key", "critical"),
        ("-----BEGIN PRIVATE KEY-----", "Private Key", "critical"),
        ("sk-[A-Za-z0-9]{20}T3BlbkFJ", "OpenAI API Key", "critical"),
        ("xoxb-[0-9]{10,13}-", "Slack Bot Token", "critical"),
        ("SG.[A-Za-z0-9_-]{22}\\.", "SendGrid API Key", "critical"),
    ];

    for (pattern, name, severity) in &secret_patterns {
        let re = regex::Regex::new(pattern).ok();
        if let Some(re) = re {
            if re.is_match(&out) {
                findings.push(AppFinding {
                    check: format!("Hardcoded secret: {}", name),
                    category: "secrets".into(),
                    severity: severity.to_string(),
                    passed: false,
                    detail: format!("{} found embedded in binary", name),
                    remediation: "Remove secrets from source code. Use Keychain or secure storage at runtime.".into(),
                });
            }
        }
    }

    // Check for http:// URLs (non-HTTPS)
    let http_count = out.matches("http://").count();
    if http_count > 5 {
        findings.push(AppFinding {
            check: "HTTP URLs in binary".into(),
            category: "network".into(),
            severity: "medium".into(),
            passed: false,
            detail: format!("{} HTTP (non-HTTPS) URLs found in binary strings", http_count),
            remediation: "Replace http:// URLs with https://".into(),
        });
    }

    findings
}

fn check_privacy_manifest(contents: &Path) -> AppFinding {
    // Apple requires PrivacyInfo.xcprivacy since Spring 2024
    let privacy_paths = [
        contents.join("Resources").join("PrivacyInfo.xcprivacy"),
        contents.join("PrivacyInfo.xcprivacy"),
    ];
    let exists = privacy_paths.iter().any(|p| p.exists());

    AppFinding {
        check: "Privacy Manifest (PrivacyInfo.xcprivacy)".into(),
        category: "privacy".into(),
        severity: "high".into(),
        passed: exists,
        detail: if exists {
            "Privacy manifest exists — required by Apple since Spring 2024".into()
        } else {
            "Privacy manifest MISSING — Apple requires PrivacyInfo.xcprivacy for App Store submission".into()
        },
        remediation: "Add PrivacyInfo.xcprivacy declaring privacy-impacting APIs and tracking domains".into(),
    }
}

fn check_provisioning_profile(contents: &Path) -> AppFinding {
    let profile = contents.join("embedded.provisionprofile");
    if !profile.exists() {
        return AppFinding {
            check: "Provisioning Profile".into(),
            category: "distribution".into(),
            severity: "low".into(),
            passed: true,
            detail: "No embedded provisioning profile (Developer ID distribution)".into(),
            remediation: "".into(),
        };
    }

    // Check if it's a development profile (has get-task-allow)
    let out = Command::new("security")
        .args(["cms", "-D", "-i", &profile.to_string_lossy()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let is_dev = out.contains("<key>get-task-allow</key>");
    AppFinding {
        check: "Provisioning Profile".into(),
        category: "distribution".into(),
        severity: if is_dev { "high" } else { "low" }.into(),
        passed: !is_dev,
        detail: if is_dev {
            "DEVELOPMENT provisioning profile embedded — not suitable for release".into()
        } else {
            "Production provisioning profile".into()
        },
        remediation: "Use a Distribution provisioning profile for release builds".into(),
    }
}

fn check_notarization(app_path: &Path) -> AppFinding {
    let out = Command::new("spctl")
        .args(["--assess", "--verbose=2", &app_path.to_string_lossy()])
        .output()
        .map(|o| {
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            format!("{}{}", String::from_utf8_lossy(&o.stdout), stderr)
        })
        .unwrap_or_default();

    let notarized = out.contains("accepted") || out.contains("Notarized Developer ID");
    AppFinding {
        check: "Apple Notarization".into(),
        category: "integrity".into(),
        severity: "high".into(),
        passed: notarized,
        detail: if notarized {
            "App is notarized by Apple".into()
        } else {
            "App is NOT notarized — macOS Gatekeeper will block it".into()
        },
        remediation: "Submit to Apple notarization: xcrun notarytool submit MyApp.zip --apple-id ... --team-id ...".into(),
    }
}

fn check_min_os_version(plist_path: &Path) -> AppFinding {
    let ver = Command::new("defaults")
        .args(["read", &plist_path.to_string_lossy(), "LSMinimumSystemVersion"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    let major: u32 = ver.split('.').next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let outdated = major > 0 && major < 13;

    AppFinding {
        check: "Minimum OS Version".into(),
        category: "compatibility".into(),
        severity: "medium".into(),
        passed: !outdated,
        detail: if ver.is_empty() {
            "No minimum OS version specified".into()
        } else if outdated {
            format!("Minimum macOS {} — versions below 13 (Ventura) lack critical security features", ver)
        } else {
            format!("Minimum macOS {} — current", ver)
        },
        remediation: "Set LSMinimumSystemVersion to at least 13.0 (Ventura)".into(),
    }
}
