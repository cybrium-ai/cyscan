//! File walker + orchestrator. Walks the target honouring `.gitignore`,
//! classifies each file by language, dispatches to the matcher in
//! parallel, merges findings.

use std::{fs, path::Path};

use anyhow::{Context, Result};
use ignore::WalkBuilder;
use rayon::prelude::*;

use crate::{finding::Finding, lang::Lang, matcher, rule::RulePack};

/// Directory names that are vendored, generated, or tooling caches --
/// never the user's own source. Scanning them produces noise (and false
/// positives) with no security value. `.gitignore` usually covers these,
/// but not every repo ignores them, so we exclude them by default.
const EXCLUDED_DIR_COMPONENTS: &[&str] = &[
    // Dependency / vendor trees
    "node_modules", "bower_components", "jspm_packages", "vendor",
    "site-packages", "dist-packages",
    // VCS metadata
    ".git", ".svn", ".hg",
    // Language / tool caches
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", ".nox", ".venv", "venv", "virtualenv", ".dart_tool",
    ".gradle", ".terraform", ".serverless", ".cache",
    // Build / generated output
    "target", "dist", "build", "out", ".next", ".nuxt", ".svelte-kit",
    "__snapshots__", "Pods", "DerivedData",
    // Editor dirs
    ".idea", ".vscode",
];

/// True when a path should be skipped by default -- it lives under a
/// vendored/generated directory, or is itself a minified bundle, source
/// map, or dependency lockfile. These carry no first-party security
/// signal and are a dominant false-positive source. (The `supply`
/// command reads lockfiles through its own path and is unaffected.)
fn is_default_excluded(path: &Path) -> bool {
    for comp in path.components() {
        if let std::path::Component::Normal(os) = comp {
            if let Some(name) = os.to_str() {
                if EXCLUDED_DIR_COMPONENTS.contains(&name) {
                    return true;
                }
            }
        }
    }

    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();

    // Minified / bundled / generated JS & CSS and source maps.
    for suffix in [
        ".min.js", ".min.mjs", ".min.cjs", ".min.css", ".bundle.js",
        ".bundle.css", ".map", "-min.js", "-min.css",
    ] {
        if lower.ends_with(suffix) {
            return true;
        }
    }

    // Dependency lockfiles -- analysed by `cyscan supply`, not by SAST.
    matches!(
        lower.as_str(),
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "npm-shrinkwrap.json"
            | "composer.lock"
            | "gemfile.lock"
            | "poetry.lock"
            | "pipfile.lock"
            | "cargo.lock"
            | "go.sum"
    )
}

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
        .filter(|p| !is_default_excluded(p))
        .filter(|p| Lang::from_path(p).is_some())
        .collect();

    log::info!("scanning {} candidate file(s)", files.len());

    // Project pre-pass (Gap A4 / inter-procedural dataflow). Aggregate
    // FileSemantics from every file and run the fixed-point taint
    // propagator BEFORE per-file rule matching. Rules with a
    // `dataflow:` block consult the resulting `ProjectSemantics` to
    // decide reachability across function boundaries.
    // Project pre-pass triggers when ANY rule needs it: dataflow
    // reachability OR a `metavariable_receiver_type` filter that may
    // need to walk cross-file class hierarchy (`class A : B` declared
    // in B.cs and used in A.cs).
    let project = if pack.rules().iter().any(|r| {
        r.dataflow.is_some() || !r.metavariable_receiver_type.is_empty()
    }) {
        log::info!("project semantics: aggregating {} files", files.len());
        Some(crate::dataflow::aggregate_project(target))
    } else {
        None
    };

    // Cross-service pre-pass — discover the API surface so finding
    // emission can tag handler-side findings with their upstream
    // callers. Always runs (cheap regex pass over each file). The
    // resulting CrossServiceMap is also surfaced via `cyscan xservice`.
    let mut xservice = crate::xservice::build(target);
    log::info!(
        "xservice: {} clients, {} handlers, {} links, k8s_services={}, specs={}",
        xservice.clients.len(),
        xservice.handlers.len(),
        xservice.links.len(),
        xservice.k8s.services.len(),
        xservice.specs.len(),
    );

    // Cross-service taint summary propagation (v0.18 — the practical
    // half of the IR work). When a project taint graph is available
    // (i.e. some rule has a `dataflow:` block so the propagator ran)
    // we ask `xservice::taint` to walk the link graph and emit
    // CrossServiceTaint entries for chains where a tainted source
    // reaches a downstream handler across the service boundary.
    if let Some(proj) = project.as_ref() {
        xservice.taint_links =
            crate::xservice::taint::build_cross_service_taint(&xservice, proj);
        log::info!("xservice taint links: {}", xservice.taint_links.len());
    }

    let mut findings: Vec<Finding> = files
        .par_iter()
        .flat_map_iter(|path| {
            let initial_lang = Lang::from_path(path).expect("filtered above");
            match fs::read_to_string(path) {
                Ok(source) => {
                    // Refine via content sniff — currently upgrades a
                    // YAML file to Kubernetes when its head contains
                    // `apiVersion:` + `kind:`. Cheap.
                    let lang = initial_lang.refine_with_content(&source);
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

                        // v0.18 — taint flowing across services into
                        // this handler. Tag findings so reviewers see
                        // the chain inline.
                        let related_taint: Vec<&crate::xservice::taint::CrossServiceTaint> =
                            xservice.taint_links.iter()
                                .filter(|t| t.handler_file == f.file)
                                .collect();
                        if !related_taint.is_empty() {
                            f.evidence.insert(
                                "cross_service_taint".into(),
                                serde_json::json!(related_taint),
                            );
                        }

                        // v0.18 — k8s topology resolution for any
                        // upstream caller's URL. Lets reviewers see
                        // "AuthController.cs calls user-svc which
                        // resolves to Deployment user-service".
                        let mut resolutions: Vec<serde_json::Value> = Vec::new();
                        for c in &callers {
                            if let Some(resolved) = crate::xservice::k8s::resolve_url(
                                &c.path, &xservice.k8s,
                            ) {
                                resolutions.push(serde_json::json!({
                                    "caller_file":  c.file.display().to_string(),
                                    "caller_path":  c.path,
                                    "service":      resolved.service.name,
                                    "namespace":    resolved.service.namespace,
                                    "deployments":  resolved.deployments,
                                }));
                            }
                        }
                        if !resolutions.is_empty() {
                            f.evidence.insert(
                                "cross_service_k8s_resolution".into(),
                                serde_json::json!(resolutions),
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

#[cfg(test)]
mod exclusion_tests {
    use super::is_default_excluded;
    use std::path::Path;

    #[test]
    fn excludes_vendored_and_generated_dirs() {
        assert!(is_default_excluded(Path::new("app/node_modules/pkg/index.js")));
        assert!(is_default_excluded(Path::new("project/vendor/lib/a.go")));
        assert!(is_default_excluded(Path::new("repo/.venv/lib/site-packages/x.py")));
        assert!(is_default_excluded(Path::new("x/__pycache__/m.py")));
        assert!(is_default_excluded(Path::new("web/dist/app.js")));
        assert!(is_default_excluded(Path::new("rustproj/target/debug/build.rs")));
    }

    #[test]
    fn excludes_minified_maps_and_lockfiles() {
        assert!(is_default_excluded(Path::new("static/jquery.min.js")));
        assert!(is_default_excluded(Path::new("static/app.bundle.js")));
        assert!(is_default_excluded(Path::new("static/app.js.map")));
        assert!(is_default_excluded(Path::new("frontend/package-lock.json")));
        assert!(is_default_excluded(Path::new("frontend/yarn.lock")));
        assert!(is_default_excluded(Path::new("Cargo.lock")));
    }

    #[test]
    fn keeps_first_party_source() {
        assert!(!is_default_excluded(Path::new("backend/apps/scans/views.py")));
        assert!(!is_default_excluded(Path::new("src/main.rs")));
        assert!(!is_default_excluded(Path::new("web/src/app.js")));
        // "env" is a common legit dir name and is NOT excluded.
        assert!(!is_default_excluded(Path::new("config/env/settings.py")));
    }
}
