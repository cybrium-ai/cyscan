//! iOS .ipa scanner — extracts the .app from the ZIP archive and scans it.
//!
//! .ipa structure:
//!   Payload/
//!     MyApp.app/
//!       Info.plist
//!       MyApp (Mach-O binary)
//!       embedded.mobileprovision
//!       Frameworks/
//!       PlugIns/

use std::path::Path;
use std::process::Command;

use super::{AppFinding, AppReport, compute_score};

pub fn scan(ipa_path: &Path) -> anyhow::Result<AppReport> {
    let temp = tempfile::tempdir()?;

    // Extract .ipa (it's a ZIP)
    let status = Command::new("unzip")
        .args(["-q", "-o", &ipa_path.to_string_lossy(), "-d", &temp.path().to_string_lossy()])
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to extract .ipa file");
    }

    // Find the .app inside Payload/
    let payload = temp.path().join("Payload");
    let app_dir = std::fs::read_dir(&payload)?
        .filter_map(|e| e.ok())
        .find(|e| {
            e.path().extension()
                .and_then(|ext| ext.to_str())
                .map_or(false, |ext| ext.eq_ignore_ascii_case("app"))
        })
        .map(|e| e.path());

    let app_dir = match app_dir {
        Some(d) => d,
        None => anyhow::bail!("No .app found inside Payload/ directory"),
    };

    // Read Info.plist (iOS uses binary plist — convert first)
    let info_plist = app_dir.join("Info.plist");
    let read_plist = |key: &str| -> String {
        Command::new("/usr/libexec/PlistBuddy")
            .args(["-c", &format!("Print :{}", key), &info_plist.to_string_lossy()])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };

    let bundle_id = read_plist("CFBundleIdentifier");
    let version = read_plist("CFBundleShortVersionString");
    let app_name = read_plist("CFBundleName");

    let mut findings = Vec::new();
    let mut frameworks = Vec::new();
    let mut entitlements = Vec::new();

    // 1. ATS
    let ats_raw = read_plist("NSAppTransportSecurity:NSAllowsArbitraryLoads");
    let ats_disabled = ats_raw.to_lowercase() == "true";
    findings.push(AppFinding {
        check: "App Transport Security".into(),
        category: "network".into(),
        severity: "high".into(),
        passed: !ats_disabled,
        detail: if ats_disabled {
            "ATS allows arbitrary HTTP loads".into()
        } else {
            "ATS enforced — HTTPS required".into()
        },
        remediation: "Remove NSAllowsArbitraryLoads from Info.plist".into(),
    });

    // 2. Provisioning profile
    let profile = app_dir.join("embedded.mobileprovision");
    if profile.exists() {
        let out = Command::new("security")
            .args(["cms", "-D", "-i", &profile.to_string_lossy()])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        let is_dev = out.contains("<key>get-task-allow</key>")
            && out.contains("<true/>");
        findings.push(AppFinding {
            check: "Provisioning Profile".into(),
            category: "distribution".into(),
            severity: if is_dev { "high" } else { "low" }.into(),
            passed: !is_dev,
            detail: if is_dev {
                "DEVELOPMENT profile — get-task-allow enabled (debuggable)".into()
            } else {
                "Distribution profile".into()
            },
            remediation: "Use App Store or Ad Hoc distribution profile for release".into(),
        });

        // Check expiration
        if out.contains("ExpirationDate") {
            // Parse date — basic check
            let expired = out.contains("2024") || out.contains("2023");
            if expired {
                findings.push(AppFinding {
                    check: "Profile Expiration".into(),
                    category: "distribution".into(),
                    severity: "high".into(),
                    passed: false,
                    detail: "Provisioning profile may be expired".into(),
                    remediation: "Regenerate provisioning profile in Apple Developer portal".into(),
                });
            }
        }
    }

    // 3. Privacy manifest
    let privacy_exists = app_dir.join("PrivacyInfo.xcprivacy").exists();
    findings.push(AppFinding {
        check: "Privacy Manifest".into(),
        category: "privacy".into(),
        severity: "high".into(),
        passed: privacy_exists,
        detail: if privacy_exists {
            "PrivacyInfo.xcprivacy present".into()
        } else {
            "MISSING — required for App Store since Spring 2024".into()
        },
        remediation: "Add PrivacyInfo.xcprivacy with required API declarations".into(),
    });

    // 4. Minimum iOS version
    let min_ios = read_plist("MinimumOSVersion");
    let major: u32 = min_ios.split('.').next().and_then(|v| v.parse().ok()).unwrap_or(0);
    findings.push(AppFinding {
        check: "Minimum iOS Version".into(),
        category: "compatibility".into(),
        severity: "medium".into(),
        passed: major >= 16,
        detail: if major >= 16 {
            format!("Minimum iOS {} — current", min_ios)
        } else {
            format!("Minimum iOS {} — versions below 16 lack security features", min_ios)
        },
        remediation: "Set MinimumOSVersion to 16.0 or later".into(),
    });

    // 5. Frameworks
    let fw_dir = app_dir.join("Frameworks");
    if fw_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&fw_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".framework") || name.ends_with(".dylib") {
                    frameworks.push(name);
                }
            }
        }
    }

    // 6. Binary secrets
    let binary = app_dir.join(app_name.as_str());
    let alt_binary = std::fs::read_dir(&app_dir).ok()
        .and_then(|mut d| d.find(|e| {
            e.as_ref().ok().map_or(false, |e| {
                let p = e.path();
                p.is_file() && !p.to_string_lossy().contains(".")
                    && e.file_name().to_string_lossy().len() > 3
            })
        }))
        .and_then(|e| e.ok())
        .map(|e| e.path());

    let bin_path = if binary.exists() { Some(binary) } else { alt_binary };
    if let Some(bin) = bin_path {
        let strings_out = Command::new("strings")
            .args(["-a", &bin.to_string_lossy()])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();

        // Check for secrets
        let checks = [
            ("AKIA", "AWS Key", "critical"),
            ("sk_live_", "Stripe Key", "critical"),
            ("-----BEGIN", "Private Key", "critical"),
            ("firebase", "Firebase config", "medium"),
        ];
        for (pattern, name, sev) in &checks {
            if strings_out.contains(pattern) {
                findings.push(AppFinding {
                    check: format!("Secret in binary: {}", name),
                    category: "secrets".into(),
                    severity: sev.to_string(),
                    passed: false,
                    detail: format!("{} found in binary strings", name),
                    remediation: "Use iOS Keychain or secure enclave for secrets".into(),
                });
            }
        }
    }

    let score = compute_score(&findings);
    let passed = findings.iter().filter(|f| f.passed).count();
    let failed = findings.iter().filter(|f| !f.passed).count();

    Ok(AppReport {
        app_name: if app_name.is_empty() { "unknown".into() } else { app_name },
        app_type: "ipa".into(),
        bundle_id: if bundle_id.is_empty() { "unknown".into() } else { bundle_id },
        version: if version.is_empty() { "unknown".into() } else { version },
        score,
        findings,
        frameworks,
        entitlements,
        passed,
        failed,
    })
}
