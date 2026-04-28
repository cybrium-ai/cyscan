//! OSV advisory matcher. Loads a bundled snapshot from
//! `rules/advisories/*.jsonl` and matches every dependency against it.
//!
//! The snapshot is refreshed nightly by a GitHub Action that pulls
//! osv.dev's `all.zip`, filters to our ecosystems, and commits back to
//! the repo. Ships with each release; `--offline` is the default mode.
//!
//! We only keep the fields we actually consume — `id`, `summary`,
//! `affected[].package.{ecosystem,name}`, `affected[].ranges[].events`,
//! plus an optional CVSS score. The full OSV schema is big and most of
//! it is reference material we don't need at scan time.

use std::{
    collections::HashMap,
    fs,
    path::Path,
};

use anyhow::{Context, Result};
use semver::Version;
use serde::Deserialize;

use crate::{
    finding::{Finding, Severity},
    supply::lockfile::{Dependency, Ecosystem},
};

#[derive(Debug, Deserialize)]
pub struct Advisory {
    pub id:       String,
    #[serde(default)]
    pub summary:  String,
    #[serde(default)]
    pub details:  String,
    #[serde(default)]
    pub affected: Vec<Affected>,
    #[serde(default)]
    pub severity: Vec<SeverityEntry>,
    /// OSV's `ecosystem_specific.imports` — symbols the vulnerable code
    /// exports. Kept verbatim in the SARIF output so the platform
    /// reachability engine can consume them.
    #[serde(default)]
    pub vulnerable_symbols: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Affected {
    pub package: Pkg,
    #[serde(default)]
    pub ranges:  Vec<Range>,
    /// Explicit version list — used when ranges don't apply (pre-release
    /// ecosystems or single-version yanks).
    #[serde(default)]
    pub versions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Pkg {
    pub ecosystem: String,
    pub name:      String,
}

#[derive(Debug, Deserialize)]
pub struct Range {
    #[serde(rename = "type", default)]
    pub range_type: String,
    #[serde(default)]
    pub events: Vec<Event>,
}

#[derive(Debug, Deserialize)]
pub struct Event {
    #[serde(default)] pub introduced: Option<String>,
    #[serde(default)] pub fixed:      Option<String>,
    #[serde(default)] pub last_affected: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SeverityEntry {
    #[serde(rename = "type", default)]
    pub severity_type: String,
    #[serde(default)]
    pub score: String,
}

/// A bundle of advisories keyed by `(ecosystem, name)` for O(1) lookup
/// during the scan. Loaded once per process.
#[derive(Default)]
pub struct Snapshot {
    by_pkg: HashMap<(Ecosystem, String), Vec<Advisory>>,
}

impl Snapshot {
    pub fn load_dir(dir: &Path) -> Result<Self> {
        if !dir.exists() {
            log::warn!("advisory snapshot dir missing: {} (scan will match nothing)", dir.display());
            return Ok(Self::default());
        }
        let mut by_pkg: HashMap<(Ecosystem, String), Vec<Advisory>> = HashMap::new();
        let mut file_count = 0;
        let mut adv_count = 0;
        for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("jsonl") { continue; }
            file_count += 1;

            let raw = fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            for (ln, line) in raw.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() { continue; }
                let adv: Advisory = match serde_json::from_str(line) {
                    Ok(a)  => a,
                    Err(e) => {
                        log::warn!("{}:{}: bad advisory: {e}", path.display(), ln + 1);
                        continue;
                    }
                };
                for aff in &adv.affected {
                    let Some(eco) = normalise_ecosystem(&aff.package.ecosystem) else { continue };
                    by_pkg.entry((eco, aff.package.name.clone()))
                        .or_default()
                        .push(clone_advisory(&adv));
                }
                adv_count += 1;
            }
        }
        log::info!("loaded {adv_count} advisory/advisories from {file_count} snapshot file(s)");
        Ok(Self { by_pkg })
    }
}

/// Clones an Advisory without deriving Clone — Advisory contains OSV
/// data that's mostly strings, cheap enough to dup per package index.
fn clone_advisory(a: &Advisory) -> Advisory {
    Advisory {
        id:       a.id.clone(),
        summary:  a.summary.clone(),
        details:  a.details.clone(),
        affected: a.affected.iter().map(|aff| Affected {
            package:  Pkg { ecosystem: aff.package.ecosystem.clone(), name: aff.package.name.clone() },
            ranges:   aff.ranges.iter().map(|r| Range {
                range_type: r.range_type.clone(),
                events: r.events.iter().map(|e| Event {
                    introduced:   e.introduced.clone(),
                    fixed:        e.fixed.clone(),
                    last_affected: e.last_affected.clone(),
                }).collect(),
            }).collect(),
            versions: aff.versions.clone(),
        }).collect(),
        severity: a.severity.iter().map(|s| SeverityEntry {
            severity_type: s.severity_type.clone(),
            score:         s.score.clone(),
        }).collect(),
        vulnerable_symbols: a.vulnerable_symbols.clone(),
    }
}

fn normalise_ecosystem(raw: &str) -> Option<Ecosystem> {
    // OSV uses `crates.io`, `npm`, `PyPI`, `Go`. Some entries include
    // a `:` suffix for distro-specific (Debian:12, etc.) — reject those.
    match raw.split(':').next().unwrap_or(raw) {
        "crates.io" => Some(Ecosystem::Crates),
        "npm"       => Some(Ecosystem::Npm),
        "PyPI"      => Some(Ecosystem::Pypi),
        "Go"        => Some(Ecosystem::Go),
        _ => None,
    }
}

/// Returns one Finding per `(dependency, advisory)` pair. The snippet
/// quotes `name@version` and the message starts with the advisory
/// summary so reports read well without extra lookups.
pub fn scan(deps: &[Dependency], snap: &Snapshot) -> Vec<Finding> {
    let mut out = Vec::new();
    for dep in deps {
        let Some(advs) = snap.by_pkg.get(&(dep.ecosystem, dep.name.clone())) else { continue };
        for adv in advs {
            if !advisory_affects(adv, dep) { continue; }
            out.push(make_finding(adv, dep));
        }
    }
    out
}

fn make_finding(adv: &Advisory, dep: &Dependency) -> Finding {
    let severity = cvss_to_severity(adv);
    let title = if adv.summary.is_empty() {
        format!("{} affects {}@{}", adv.id, dep.name, dep.version)
    } else {
        adv.summary.clone()
    };
    let message = format!(
        "{} {} {}@{} — see https://osv.dev/vulnerability/{}",
        adv.id, dep.ecosystem.as_str(), dep.name, dep.version, adv.id,
    );
    Finding {
        rule_id:    format!("CBR-SUPPLY-{}", adv.id),
        title,
        severity,
        message,
        file:       dep.lockfile.clone(),
        line:       0, column: 0, end_line: 0, end_column: 0,
        start_byte: 0, end_byte: 0,
        snippet:    format!("{}@{}", dep.name, dep.version),
        fix_recipe: None,
        fix:        None,
        cwe:        Vec::new(),
        evidence:   HashMap::new(),
        reachability: None,
    }
}

fn advisory_affects(adv: &Advisory, dep: &Dependency) -> bool {
    let dep_v = match Version::parse(strip_v(&dep.version)) {
        Ok(v)  => v,
        Err(_) => return matches_exact_version_only(adv, dep),
    };
    for aff in &adv.affected {
        if !normalise_ecosystem(&aff.package.ecosystem)
            .map_or(false, |e| e == dep.ecosystem) { continue; }
        if aff.package.name != dep.name { continue; }
        if aff.versions.iter().any(|v| strip_v(v) == strip_v(&dep.version)) {
            return true;
        }
        for range in &aff.ranges {
            if range_hits(range, &dep_v) { return true; }
        }
    }
    false
}

fn matches_exact_version_only(adv: &Advisory, dep: &Dependency) -> bool {
    // Fallback when the dep version isn't semver-clean (go +incompatible
    // pseudo-versions, git SHAs). Only exact-list match applies.
    adv.affected.iter().any(|aff| aff.package.name == dep.name
        && aff.versions.iter().any(|v| v == &dep.version))
}

fn range_hits(range: &Range, v: &Version) -> bool {
    // OSV events are an ordered list: `introduced X` means "vulnerable
    // from X onward"; a following `fixed Y` closes the range at Y (open
    // interval). `last_affected Z` means closed at Z.
    let mut vuln_from: Option<Version> = None;
    for event in &range.events {
        if let Some(i) = &event.introduced {
            if i == "0" { vuln_from = Some(Version::new(0, 0, 0)); continue; }
            if let Ok(iv) = Version::parse(strip_v(i)) { vuln_from = Some(iv); }
        }
        if let Some(f) = &event.fixed {
            if let (Some(from), Ok(fv)) = (vuln_from.as_ref(), Version::parse(strip_v(f))) {
                if v >= from && v < &fv { return true; }
            }
            vuln_from = None;
        }
        if let Some(la) = &event.last_affected {
            if let (Some(from), Ok(lv)) = (vuln_from.as_ref(), Version::parse(strip_v(la))) {
                if v >= from && v <= &lv { return true; }
            }
            vuln_from = None;
        }
    }
    // Open-ended "introduced with no fix" — still vulnerable.
    if let Some(from) = vuln_from {
        return v >= &from;
    }
    false
}

fn strip_v(s: &str) -> &str { s.strip_prefix('v').unwrap_or(s) }

fn cvss_to_severity(adv: &Advisory) -> Severity {
    let score = adv.severity.iter()
        .filter_map(|s| parse_cvss(&s.score))
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    match score {
        Some(x) if x >= 9.0 => Severity::Critical,
        Some(x) if x >= 7.0 => Severity::High,
        Some(x) if x >= 4.0 => Severity::Medium,
        Some(x) if x >  0.0 => Severity::Low,
        _                   => Severity::Medium, // No CVSS? Assume medium.
    }
}

fn parse_cvss(score: &str) -> Option<f64> {
    // CVSS vector strings look like `CVSS:3.1/AV:N/.../S:U`. We only
    // care about the `/S:` field isn't what gives a score — the numeric
    // base score isn't in the vector itself. osv.dev typically stores
    // the score as a bare decimal in `score`; some entries put the full
    // vector. Accept either.
    if let Ok(n) = score.parse::<f64>() { return Some(n); }
    None
}
