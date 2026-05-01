//! License compliance scanner — flags dependencies with risky licenses
//! (copyleft, network-copyleft, or unknown) that could affect commercial use.
//!
//! Risk categories:
//!   - **copyleft**: GPL, LGPL, MPL — derivative works must use the same license
//!   - **network-copyleft**: AGPL, SSPL — triggers on network use (SaaS)
//!   - **restricted**: BUSL, Commons Clause, Elastic License — commercial restrictions
//!   - **unknown**: no license detected — legal risk

use std::collections::HashMap;

use crate::finding::{Finding, Severity};
use super::lockfile::Dependency;

/// License risk category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseRisk {
    /// Permissive — MIT, Apache-2.0, BSD, ISC, etc.
    Permissive,
    /// Weak copyleft — LGPL, MPL (linking/file-level boundary)
    WeakCopyleft,
    /// Strong copyleft — GPL (derivative works must be GPL)
    Copyleft,
    /// Network copyleft — AGPL, SSPL (SaaS triggers copyleft)
    NetworkCopyleft,
    /// Source-available with commercial restrictions — BUSL, Elastic, etc.
    Restricted,
    /// No license or unrecognised — default deny for legal review
    Unknown,
}

impl LicenseRisk {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Permissive     => "permissive",
            Self::WeakCopyleft   => "weak-copyleft",
            Self::Copyleft       => "copyleft",
            Self::NetworkCopyleft => "network-copyleft",
            Self::Restricted     => "restricted",
            Self::Unknown        => "unknown",
        }
    }

    fn severity(self) -> Severity {
        match self {
            Self::Permissive     => Severity::Info,
            Self::WeakCopyleft   => Severity::Low,
            Self::Copyleft       => Severity::Medium,
            Self::NetworkCopyleft => Severity::High,
            Self::Restricted     => Severity::High,
            Self::Unknown        => Severity::Medium,
        }
    }
}

/// Classify an SPDX license identifier into a risk category.
pub fn classify(spdx: &str) -> LicenseRisk {
    let s = spdx.to_uppercase();

    // Exact matches first, then prefix/contains checks.
    // Order matters — check more specific (AGPL) before less specific (GPL).

    // Network copyleft
    if s.contains("AGPL") || s.contains("SSPL") || s.contains("OSL") {
        return LicenseRisk::NetworkCopyleft;
    }

    // Restricted / source-available
    if s.contains("BUSL") || s.contains("BSL-1") || s.contains("COMMONS-CLAUSE")
        || s.contains("ELASTIC") || s.contains("CONFLUENT") || s.contains("MONGODB")
        || s.contains("TIMESCALE") || s.contains("POLYFORM")
    {
        return LicenseRisk::Restricted;
    }

    // Strong copyleft
    if s.contains("GPL") && !s.contains("LGPL") {
        return LicenseRisk::Copyleft;
    }

    // Weak copyleft
    if s.contains("LGPL") || s.contains("MPL") || s.contains("EPL")
        || s.contains("CPL") || s.contains("CDDL") || s.contains("EUPL")
    {
        return LicenseRisk::WeakCopyleft;
    }

    // Permissive
    if s.contains("MIT") || s.contains("APACHE") || s.contains("BSD")
        || s.contains("ISC") || s.contains("UNLICENSE") || s.contains("CC0")
        || s.contains("WTFPL") || s.contains("0BSD") || s.contains("ZLIB")
        || s.contains("ARTISTIC") || s.contains("PYTHON") || s.contains("PSF")
        || s.contains("BOOST") || s.contains("BSL-1.0")  // Boost, not BUSL
        || s.contains("X11") || s == "PUBLIC DOMAIN"
    {
        return LicenseRisk::Permissive;
    }

    LicenseRisk::Unknown
}

/// Scan dependencies for license compliance issues.
/// Only emits findings for non-permissive licenses.
pub fn scan(deps: &[Dependency]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for dep in deps {
        let Some(license) = &dep.license else { continue };

        // SPDX expressions can be compound: "MIT OR Apache-2.0".
        // For compound licenses, classify the LEAST restrictive option
        // (the user can choose the most permissive one).
        let risk = if license.contains(" OR ") {
            license.split(" OR ")
                .map(|part| classify(part.trim()))
                .min_by_key(|r| match r {
                    LicenseRisk::Permissive     => 0,
                    LicenseRisk::WeakCopyleft   => 1,
                    LicenseRisk::Copyleft       => 2,
                    LicenseRisk::NetworkCopyleft => 3,
                    LicenseRisk::Restricted     => 4,
                    LicenseRisk::Unknown        => 5,
                })
                .unwrap_or(LicenseRisk::Unknown)
        } else {
            classify(license)
        };

        // Skip permissive — nothing to report
        if risk == LicenseRisk::Permissive {
            continue;
        }

        // Dedupe: one finding per (package, license)
        let key = format!("{}@{}", dep.name, license);
        if !seen.insert(key) { continue; }

        let (rule_id, title, message) = match risk {
            LicenseRisk::NetworkCopyleft => (
                "CBR-LIC-NETWORK-COPYLEFT",
                "Network copyleft license detected",
                format!(
                    "{}@{} uses license '{}' ({}). Network copyleft licenses like AGPL/SSPL \
                     require that ANY network user of this software can obtain the complete \
                     source code — including YOUR proprietary code that links to it. This is \
                     incompatible with most commercial SaaS products.",
                    dep.name, dep.version, license, risk.as_str()
                ),
            ),
            LicenseRisk::Copyleft => (
                "CBR-LIC-COPYLEFT",
                "Copyleft license detected",
                format!(
                    "{}@{} uses license '{}' ({}). Copyleft licenses require derivative works \
                     to be released under the same license. Linking to GPL code may require \
                     open-sourcing your entire application.",
                    dep.name, dep.version, license, risk.as_str()
                ),
            ),
            LicenseRisk::WeakCopyleft => (
                "CBR-LIC-WEAK-COPYLEFT",
                "Weak copyleft license detected",
                format!(
                    "{}@{} uses license '{}' ({}). Weak copyleft licenses like LGPL/MPL allow \
                     linking from proprietary code but require modifications to the library \
                     itself to be shared. Review your usage to ensure compliance.",
                    dep.name, dep.version, license, risk.as_str()
                ),
            ),
            LicenseRisk::Restricted => (
                "CBR-LIC-RESTRICTED",
                "Restricted / source-available license detected",
                format!(
                    "{}@{} uses license '{}' ({}). This license restricts commercial use. \
                     Review the license terms to determine if your usage is permitted.",
                    dep.name, dep.version, license, risk.as_str()
                ),
            ),
            LicenseRisk::Unknown => (
                "CBR-LIC-UNKNOWN",
                "Unknown or missing license",
                format!(
                    "{}@{} uses license '{}' which could not be classified. Unknown licenses \
                     pose legal risk — consult legal counsel before shipping.",
                    dep.name, dep.version, license
                ),
            ),
            LicenseRisk::Permissive => unreachable!(),
        };

        let mut evidence = HashMap::new();
        evidence.insert("license".into(), serde_json::Value::String(license.clone()));
        evidence.insert("risk".into(), serde_json::Value::String(risk.as_str().into()));
        evidence.insert("ecosystem".into(), serde_json::Value::String(dep.ecosystem.as_str().into()));

        findings.push(Finding {
            rule_id:    rule_id.to_string(),
            title:      title.to_string(),
            severity:   risk.severity(),
            message,
            file:       dep.lockfile.clone(),
            line: 0, column: 0, end_line: 0, end_column: 0,
            fingerprint: String::new(),
            start_byte: 0, end_byte: 0,
            snippet:    format!("{}@{} [{}]", dep.name, dep.version, license),
            fix_recipe: None,
            fix:        None,
            cwe:        vec!["CWE-1357".to_string()], // Reliance on insufficiently trustworthy component
            evidence,
            reachability: None,
        });
    }

    findings
}
