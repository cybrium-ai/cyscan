//! Application package scanner — analyzes .app, .ipa, .pkg bundles for
//! security issues: entitlements, hardcoded secrets, ATS misconfig,
//! framework CVEs, provisioning profiles, privacy manifest compliance.
//!
//! Usage:
//!   cyscan app MyApp.app              # scan macOS app bundle
//!   cyscan app MyApp.ipa              # scan iOS TestFlight/App Store build
//!   cyscan app Installer.pkg          # scan macOS installer package
//!   cyscan app --format json MyApp.app

pub mod macos_app;
pub mod ipa;
pub mod pkg;

use std::path::Path;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AppFinding {
    pub check:       String,
    pub category:    String,
    pub severity:    String,
    pub passed:      bool,
    pub detail:      String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppReport {
    pub app_name:    String,
    pub app_type:    String, // app, ipa, pkg
    pub bundle_id:   String,
    pub version:     String,
    pub score:       u32,
    pub findings:    Vec<AppFinding>,
    pub frameworks:  Vec<String>,
    pub entitlements: Vec<String>,
    pub passed:      usize,
    pub failed:      usize,
}

/// Scan an application package.
pub fn scan(path: &Path) -> anyhow::Result<AppReport> {
    let ext = path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let is_app_dir = path.is_dir() && path.extension()
        .and_then(|e| e.to_str())
        .map_or(false, |e| e.eq_ignore_ascii_case("app"));

    if is_app_dir || ext == "app" {
        macos_app::scan(path)
    } else if ext == "ipa" {
        ipa::scan(path)
    } else if ext == "pkg" {
        pkg::scan(path)
    } else {
        anyhow::bail!("Unsupported file type: .{}. Supported: .app, .ipa, .pkg", ext)
    }
}

/// Compute score from findings.
pub fn compute_score(findings: &[AppFinding]) -> u32 {
    if findings.is_empty() { return 100; }
    let mut total: u32 = 0;
    let mut earned: u32 = 0;
    for f in findings {
        let w = match f.severity.as_str() {
            "critical" => 15, "high" => 10, "medium" => 5, "low" => 2, _ => 3,
        };
        total += w;
        if f.passed { earned += w; }
    }
    if total == 0 { return 100; }
    ((earned as f64 / total as f64) * 100.0).round() as u32
}
