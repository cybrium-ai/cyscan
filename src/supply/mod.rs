//! Supply-chain scanner — parses lockfiles, matches against advisories,
//! flags typosquats and policy violations.
//!
//! Lives next to the SAST matcher rather than inside it because the
//! inputs (lockfiles) and outputs (dependency-scoped findings) don't
//! share code with source-file scanning. They do share the `Finding`
//! shape so one SARIF document covers both.
//!
//! OSS-only — reachability enrichment is a platform concern and runs
//! against the SARIF this module emits. See docs/sprints/sprint-34.md.

pub mod advisory;
pub mod license;
pub mod lockfile;
pub mod policy;
pub mod typosquat;

use std::path::Path;

use anyhow::Result;

use crate::{finding::Finding, reachability, rule::RulePack};

/// Walk `target`, find every supported lockfile, and emit findings from
/// the advisory matcher, the typosquat heuristic, and any policy rules
/// in `pack` that carry a `dependency:` block.
pub fn run(target: &Path, pack: &RulePack, advisories: &advisory::Snapshot) -> Result<Vec<Finding>> {
    let deps = lockfile::discover(target)?;
    log::info!("supply: discovered {} dependencies across the tree", deps.len());

    let mut findings = Vec::new();
    findings.extend(advisory::scan(&deps, advisories));
    findings.extend(typosquat::scan(&deps));
    findings.extend(policy::scan(&deps, pack.rules()));
    findings.extend(license::scan(&deps));
    reachability::enrich_findings(target, &mut findings);

    findings.sort_by(|a, b| {
        b.severity.cmp(&a.severity)
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    Ok(findings)
}
