//! File walker + orchestrator. Walks the target honouring `.gitignore`,
//! classifies each file by language, dispatches to the matcher in
//! parallel, merges findings.

use std::{fs, path::Path};

use anyhow::{Context, Result};
use ignore::WalkBuilder;
use rayon::prelude::*;

use crate::{finding::Finding, lang::Lang, matcher, rule::RulePack};

pub fn run(target: &Path, pack: &RulePack) -> Result<Vec<Finding>> {
    if !target.exists() {
        anyhow::bail!("target does not exist: {}", target.display());
    }

    // Gather the candidate file list eagerly so we can fan out with rayon.
    let files: Vec<_> = WalkBuilder::new(target)
        .standard_filters(true)
        .hidden(false)
        .build()
        .filter_map(|r| r.ok())
        .filter(|e| e.file_type().map_or(false, |ft| ft.is_file()))
        .map(|e| e.into_path())
        .filter(|p| Lang::from_path(p).is_some())
        .collect();

    log::info!("scanning {} candidate file(s)", files.len());

    let mut findings: Vec<Finding> = files
        .par_iter()
        .flat_map_iter(|path| {
            let lang = Lang::from_path(path).expect("filtered above");
            match fs::read_to_string(path) {
                Ok(source) => matcher::run_rules(pack.rules(), lang, path, &source),
                Err(err) => {
                    log::warn!("skipping {}: {err}", path.display());
                    Vec::new()
                }
            }
        })
        .collect();

    // Stable ordering — severity desc, then file, then line.
    findings.sort_by(|a, b| {
        b.severity.cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.line.cmp(&b.line))
    });

    Ok(findings)
}

/// Utility for tests: read + scan a single file without walking.
#[allow(dead_code)]
pub fn scan_file(path: &Path, pack: &RulePack) -> Result<Vec<Finding>> {
    let lang = Lang::from_path(path)
        .with_context(|| format!("unrecognised language for {}", path.display()))?;
    let source = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(matcher::run_rules(pack.rules(), lang, path, &source))
}
