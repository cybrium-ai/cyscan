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

    // Project pre-pass (Gap A4 / inter-procedural dataflow). Aggregate
    // FileSemantics from every file and run the fixed-point taint
    // propagator BEFORE per-file rule matching. Rules with a
    // `dataflow:` block consult the resulting `ProjectSemantics` to
    // decide reachability across function boundaries.
    let project = if pack.rules().iter().any(|r| r.dataflow.is_some()) {
        log::info!("dataflow: building project semantics for {} files", files.len());
        Some(crate::dataflow::aggregate_project(target))
    } else {
        None
    };

    // Cross-service pre-pass — discover the API surface so finding
    // emission can tag handler-side findings with their upstream
    // callers. Always runs (cheap regex pass over each file). The
    // resulting CrossServiceMap is also surfaced via `cyscan xservice`.
    let xservice = crate::xservice::build(target);
    log::info!(
        "xservice: {} clients, {} handlers, {} links",
        xservice.clients.len(), xservice.handlers.len(), xservice.links.len(),
    );

    let mut findings: Vec<Finding> = files
        .par_iter()
        .flat_map_iter(|path| {
            let lang = Lang::from_path(path).expect("filtered above");
            match fs::read_to_string(path) {
                Ok(source) => {
                    let mut found = matcher::run_rules_with_project(
                        pack.rules(),
                        lang,
                        path,
                        &source,
                        project.as_ref(),
                    );
                    // Tag every finding inside an HTTP handler with the
                    // list of upstream callers — the controllers /
                    // services that route into this handler. Cross-
                    // language by design.
                    for f in found.iter_mut() {
                        let callers = xservice.callers_of_handler(&f.file, f.line);
                        if !callers.is_empty() {
                            f.evidence.insert(
                                "cross_service_callers".into(),
                                serde_json::json!(callers.iter().map(|c| serde_json::json!({
                                    "file":     c.file.display().to_string(),
                                    "line":     c.line,
                                    "language": c.language,
                                    "method":   c.method.as_str(),
                                    "path":     c.path,
                                    "via":      c.via,
                                })).collect::<Vec<_>>()),
                            );
                        }
                    }
                    found
                }
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

    // Cross-service finding aggregation: when the same rule fires in
    // both a handler AND a caller that reaches it, we synthesise a
    // composite finding tagged `evidence.cross_service_aggregate` so
    // SARIF consumers can render the chain as a single reviewable
    // unit. Originals stay in the list — aggregates are additive.
    let aggregates = build_cross_service_aggregates(&findings, &xservice);
    findings.extend(aggregates);

    Ok(findings)
}

/// Detect chains where the same rule_id fires inside an HTTP handler
/// AND in a controller that calls that handler. Emit one composite
/// finding per chain, tagged so SARIF can render it as a chain of
/// related-locations.
fn build_cross_service_aggregates(
    findings: &[Finding],
    xservice: &crate::xservice::CrossServiceMap,
) -> Vec<Finding> {
    use std::collections::HashMap;
    let mut by_rule: HashMap<&str, Vec<&Finding>> = HashMap::new();
    for f in findings {
        by_rule.entry(f.rule_id.as_str()).or_default().push(f);
    }
    let mut out = Vec::new();
    for (rule_id, rule_findings) in &by_rule {
        if rule_findings.len() < 2 { continue; }
        // Find every (caller_finding, handler_finding) pair whose
        // files are linked in xservice.
        for handler_f in rule_findings.iter() {
            let callers = xservice.callers_of_handler(&handler_f.file, handler_f.line);
            if callers.is_empty() { continue; }
            // Collect every finding in `rule_findings` that lives in
            // any of those caller files — and tag them as the chain.
            let chain_findings: Vec<&Finding> = rule_findings.iter()
                .filter(|f| callers.iter().any(|c| c.file == f.file))
                .copied()
                .collect();
            if chain_findings.is_empty() { continue; }
            // Dedup: chain identified by (rule_id, handler_file, handler_line).
            let key = format!("{}@{}:{}", rule_id, handler_f.file.display(), handler_f.line);
            if out.iter().any(|a: &Finding| a.evidence.get("cross_service_chain_key")
                .and_then(|v| v.as_str()) == Some(&key))
            {
                continue;
            }
            // Locations: the handler + every chain finding.
            let related: Vec<serde_json::Value> = std::iter::once(*handler_f)
                .chain(chain_findings.iter().copied())
                .map(|f| serde_json::json!({
                    "file":     f.file.display().to_string(),
                    "line":     f.line,
                    "rule_id":  f.rule_id,
                    "snippet":  f.snippet,
                }))
                .collect();
            let mut composite: Finding = (**handler_f).clone();
            composite.rule_id = format!("{}-XSVC", rule_id);
            composite.title   = format!("[cross-service] {}", handler_f.title);
            composite.evidence.insert(
                "cross_service_chain_key".into(),
                serde_json::json!(key),
            );
            composite.evidence.insert(
                "cross_service_chain".into(),
                serde_json::json!(related),
            );
            composite.evidence.insert(
                "cross_service_chain_length".into(),
                serde_json::json!(chain_findings.len() + 1),
            );
            out.push(composite);
        }
    }
    out
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
