//! Policy rules — user-authored YAML that matches against `Dependency`
//! rather than source code. A rule with a `dependency:` block is
//! picked up here; anything with `regex:` or `query:` is ignored.
//!
//! Supported predicates (AND-ed within one rule):
//!   ecosystem: npm | pypi | crates.io | go
//!   name:      "<exact>"           — exact match, case-insensitive
//!   name_pattern: "<regex>"         — substring regex, case-insensitive
//!   version:   { min: "1.0.0", max: "2.0.0" }  — semver range (inclusive)

use regex::RegexBuilder;
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::{
    finding::Finding,
    rule::Rule,
    supply::lockfile::{Dependency, Ecosystem},
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DependencyPolicy {
    #[serde(default)] pub ecosystem:    Option<String>,
    #[serde(default)] pub name:         Option<String>,
    #[serde(default)] pub name_pattern: Option<String>,
    #[serde(default)] pub version:      Option<VersionRange>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VersionRange {
    #[serde(default)] pub min: Option<String>,
    #[serde(default)] pub max: Option<String>,
}

pub fn scan(deps: &[Dependency], rules: &[Rule]) -> Vec<Finding> {
    let mut out = Vec::new();
    for rule in rules {
        let Some(pol) = rule.dependency.as_ref() else { continue };
        for dep in deps {
            if !matches(pol, dep) { continue; }
            out.push(Finding {
                rule_id:    rule.id.clone(),
                title:      rule.title.clone(),
                severity:   rule.severity,
                message:    format!("{} — {}@{}", rule.message.trim(), dep.name, dep.version),
                file:       dep.lockfile.clone(),
                line: 0, column: 0, end_line: 0, end_column: 0,
                start_byte: 0, end_byte: 0,
                snippet:    format!("{}@{}", dep.name, dep.version),
                fix_recipe: rule.fix_recipe.clone(),
                fix:        None,
                cwe:        rule.cwe.clone(),
            });
        }
    }
    out
}

fn matches(pol: &DependencyPolicy, dep: &Dependency) -> bool {
    if let Some(eco) = &pol.ecosystem {
        let want = match eco.to_ascii_lowercase().as_str() {
            "npm"       => Ecosystem::Npm,
            "pypi"      => Ecosystem::Pypi,
            "crates.io" | "crates" => Ecosystem::Crates,
            "go"        => Ecosystem::Go,
            _ => return false,
        };
        if dep.ecosystem != want { return false; }
    }
    if let Some(name) = &pol.name {
        if dep.name.eq_ignore_ascii_case(name) == false { return false; }
    }
    if let Some(pat) = &pol.name_pattern {
        let re = match RegexBuilder::new(pat).case_insensitive(true).build() {
            Ok(r) => r,
            Err(_) => return false,
        };
        if !re.is_match(&dep.name) { return false; }
    }
    if let Some(range) = &pol.version {
        let Ok(dep_v) = Version::parse(dep.version.strip_prefix('v').unwrap_or(&dep.version)) else {
            // Non-semver versions can't be range-compared; treat as miss.
            return false;
        };
        if let Some(min) = &range.min {
            if let Ok(mn) = Version::parse(min.strip_prefix('v').unwrap_or(min)) {
                if dep_v < mn { return false; }
            }
        }
        if let Some(max) = &range.max {
            if let Ok(mx) = Version::parse(max.strip_prefix('v').unwrap_or(max)) {
                if dep_v > mx { return false; }
            }
        }
    }
    true
}
