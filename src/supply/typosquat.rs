//! Typosquat heuristic — flag dependencies whose name is ≤ 2 edits away
//! from a popular package in the same ecosystem. Bundled lists live in
//! `rules/typosquat/<ecosystem>.txt`, one name per line.
//!
//! This is a heuristic, not a guarantee. False positives happen when a
//! legitimately-named package shares its ecosystem with a top package
//! (e.g. `requests2` for a fork of `requests`). The finding severity
//! is `low` so it shows up as a hint rather than a gate.

use std::{collections::HashSet, fs};
use std::collections::HashMap;

use crate::{
    finding::{Finding, Severity},
    supply::lockfile::{Dependency, Ecosystem},
};

/// Bundled top-packages list, resolved at startup.
pub fn scan(deps: &[Dependency]) -> Vec<Finding> {
    let Some(dir) = resolve_dir() else { return Vec::new() };
    let mut per_eco: std::collections::HashMap<Ecosystem, HashSet<String>> =
        std::collections::HashMap::new();

    for (eco, filename) in [
        (Ecosystem::Crates, "crates.txt"),
        (Ecosystem::Npm,    "npm.txt"),
        (Ecosystem::Pypi,   "pypi.txt"),
        (Ecosystem::Go,     "go.txt"),
    ] {
        let path = dir.join(filename);
        if let Ok(raw) = fs::read_to_string(&path) {
            per_eco.insert(eco, raw.lines()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty() && !s.starts_with('#'))
                .collect());
        }
    }

    let mut out = Vec::new();
    for dep in deps {
        let Some(popular) = per_eco.get(&dep.ecosystem) else { continue };
        let lower = dep.name.to_ascii_lowercase();
        // Exact matches are legitimate installs — skip.
        if popular.contains(&lower) { continue; }
        // Check within edit distance 2 against every popular name of
        // similar length. Keeps this O(deps × popular-in-length-band)
        // rather than the full O(deps × popular) product.
        for p in popular.iter()
            .filter(|p| p.len().abs_diff(lower.len()) <= 2)
        {
            if levenshtein(&lower, p) <= 2 {
                out.push(Finding {
                    rule_id:    "CBR-SUPPLY-TYPOSQUAT".to_string(),
                    title:      format!("{} resembles popular package {}", dep.name, p),
                    severity:   Severity::Low,
                    message:    format!(
                        "Dependency `{}@{}` is within 2 edits of the popular {} package `{}`. \
                         Double-check this isn't a typosquat.",
                        dep.name, dep.version, dep.ecosystem.as_str(), p,
                    ),
                    file:       dep.lockfile.clone(),
                    line: 0, column: 0, end_line: 0, end_column: 0,
                    start_byte: 0, end_byte: 0,
                    snippet:    format!("{}@{}", dep.name, dep.version),
                    fix_recipe: None,
                    fix:        None,
                    cwe:        vec!["CWE-506".to_string()],
                    evidence:   HashMap::new(),
                    reachability: None,
                });
                break; // Only report the first popular match per dep.
            }
        }
    }
    out
}

/// Resolve the bundled typosquat dir with the same search order as the
/// rules/ dir in cli.rs. Keep this in sync if that changes.
fn resolve_dir() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    if let Ok(p) = std::env::var("CYSCAN_TYPOSQUAT_DIR") {
        return Some(PathBuf::from(p));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for rel in ["rules/typosquat", "../rules/typosquat", "../share/cyscan/rules/typosquat"] {
                let c = dir.join(rel);
                if c.exists() { return Some(c.canonicalize().unwrap_or(c)); }
            }
        }
    }
    let fallback: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules/typosquat");
    fallback.exists().then_some(fallback)
}

/// Classic DP edit distance. Small enough that we don't need
/// bit-parallelism; popular lists are capped at 1000 names.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() { return b.len(); }
    if b.is_empty() { return a.len(); }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut curr = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        curr[0] = i;
        for j in 1..=b.len() {
            let cost = if a[i-1] == b[j-1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j-1] + 1).min(prev[j-1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}
