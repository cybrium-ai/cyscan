//! CIA triad posture scoring — aggregates findings into Confidentiality,
//! Integrity, and Availability scores (0-100).

use serde::Serialize;

use crate::finding::{Finding, Severity};
use crate::rule::{CiaImpact, CiaTriad, RulePack};

#[derive(Debug, Clone, Serialize)]
pub struct CiaScore {
    pub confidentiality: u32,
    pub integrity:       u32,
    pub availability:    u32,
    pub c_findings:      usize,
    pub i_findings:      usize,
    pub a_findings:      usize,
}

/// Compute CIA posture scores from findings + the rule pack.
/// Score = 100 minus weighted penalty per finding.
/// Weights: severity * CIA impact level.
pub fn score(findings: &[Finding], pack: &RulePack) -> CiaScore {
    let mut c_penalty: f64 = 0.0;
    let mut i_penalty: f64 = 0.0;
    let mut a_penalty: f64 = 0.0;
    let mut c_count: usize = 0;
    let mut i_count: usize = 0;
    let mut a_count: usize = 0;

    // Build rule lookup
    let rules: std::collections::HashMap<&str, &crate::rule::Rule> = pack.rules()
        .iter()
        .map(|r| (r.id.as_str(), r))
        .collect();

    for finding in findings {
        let cia = if let Some(rule) = rules.get(finding.rule_id.as_str()) {
            rule.cia_impact()
        } else {
            // For findings without a matching rule (entropy, image CVE, etc.),
            // use a default based on severity
            classify_finding(finding)
        };

        let sev_weight = match finding.severity {
            Severity::Critical => 5.0,
            Severity::High     => 3.0,
            Severity::Medium   => 1.5,
            Severity::Low      => 0.5,
            Severity::Info     => 0.1,
        };

        let c_impact = cia.confidentiality.score() as f64 * sev_weight;
        let i_impact = cia.integrity.score() as f64 * sev_weight;
        let a_impact = cia.availability.score() as f64 * sev_weight;

        if c_impact > 0.0 { c_penalty += c_impact; c_count += 1; }
        if i_impact > 0.0 { i_penalty += i_impact; i_count += 1; }
        if a_impact > 0.0 { a_penalty += a_impact; a_count += 1; }
    }

    // Normalize penalties to 0-100 scale
    // Cap at 100 penalty points (score can't go below 0)
    let normalize = |penalty: f64| -> u32 {
        let score = 100.0 - (penalty * 2.0).min(100.0);
        score.max(0.0).round() as u32
    };

    CiaScore {
        confidentiality: normalize(c_penalty),
        integrity:       normalize(i_penalty),
        availability:    normalize(a_penalty),
        c_findings:      c_count,
        i_findings:      i_count,
        a_findings:      a_count,
    }
}

/// Classify a finding without a rule (entropy, image CVE, etc.)
fn classify_finding(finding: &Finding) -> CiaTriad {
    let id = finding.rule_id.to_uppercase();

    if id.contains("ENTROPY") || id.contains("SEC-") {
        return CiaTriad {
            confidentiality: CiaImpact::High,
            integrity: CiaImpact::Medium,
            availability: CiaImpact::Low,
        };
    }
    if id.contains("IMG-") || id.contains("CVE-") {
        return CiaTriad {
            confidentiality: CiaImpact::Medium,
            integrity: CiaImpact::High,
            availability: CiaImpact::Medium,
        };
    }
    if id.contains("LIC-") {
        return CiaTriad {
            confidentiality: CiaImpact::None,
            integrity: CiaImpact::None,
            availability: CiaImpact::None,
        };
    }

    CiaTriad {
        confidentiality: CiaImpact::Medium,
        integrity: CiaImpact::Medium,
        availability: CiaImpact::Low,
    }
}

/// Print CIA posture summary to stdout.
pub fn print_summary(cia: &CiaScore, findings: &[Finding], pack: &RulePack) {
    let c_icon = score_icon(cia.confidentiality);
    let i_icon = score_icon(cia.integrity);
    let a_icon = score_icon(cia.availability);

    println!();
    println!("  \x1b[1mCIA Posture Summary\x1b[0m");
    println!();
    println!("    Confidentiality:  {}/100  [{}]  {} finding(s) with impact",
        cia.confidentiality, c_icon, cia.c_findings);
    println!("    Integrity:        {}/100  [{}]  {} finding(s) with impact",
        cia.integrity, i_icon, cia.i_findings);
    println!("    Availability:     {}/100  [{}]  {} finding(s) with impact",
        cia.availability, a_icon, cia.a_findings);
    println!();

    // Top risks per dimension
    let rules: std::collections::HashMap<&str, &crate::rule::Rule> = pack.rules()
        .iter()
        .map(|r| (r.id.as_str(), r))
        .collect();

    for (dim, label) in [("c", "Confidentiality"), ("i", "Integrity"), ("a", "Availability")] {
        let mut dim_findings: Vec<(&Finding, u32)> = findings.iter()
            .filter_map(|f| {
                let cia = if let Some(r) = rules.get(f.rule_id.as_str()) {
                    r.cia_impact()
                } else {
                    classify_finding(f)
                };
                let impact = match dim {
                    "c" => cia.confidentiality.score(),
                    "i" => cia.integrity.score(),
                    "a" => cia.availability.score(),
                    _ => 0,
                };
                if impact > 0 { Some((f, impact)) } else { None }
            })
            .collect();

        dim_findings.sort_by(|a, b| b.1.cmp(&a.1).then(b.0.severity.cmp(&a.0.severity)));

        if !dim_findings.is_empty() {
            println!("  Top {} Risks:", label);
            for (f, _) in dim_findings.iter().take(5) {
                let sev = match f.severity {
                    Severity::Critical => "\x1b[31mCRIT\x1b[0m",
                    Severity::High     => "\x1b[33mHIGH\x1b[0m",
                    Severity::Medium   => "\x1b[36mMED \x1b[0m",
                    Severity::Low      => "\x1b[34mLOW \x1b[0m",
                    Severity::Info     => "INFO",
                };
                println!("    [{}] {} — {}", sev, f.rule_id, f.title);
            }
            println!();
        }
    }
}

fn score_icon(score: u32) -> &'static str {
    if score >= 80 { "\x1b[32mGOOD\x1b[0m" }
    else if score >= 50 { "\x1b[33mFAIR\x1b[0m" }
    else { "\x1b[31mPOOR\x1b[0m" }
}
