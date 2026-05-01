//! File walker + orchestrator. Walks the target honouring `.gitignore`,
//! classifies each file by language, dispatches to the matcher in
//! parallel, merges findings.

use std::{collections::{HashMap, HashSet}, fs, path::Path};

use anyhow::{Context, Result};
use ignore::WalkBuilder;
use rayon::prelude::*;

use crate::{finding::Finding, framework, lang::Lang, matcher, rule::RulePack};

#[derive(Debug, Clone, Default)]
pub struct CloudContext {
    pub exposed_services: HashSet<String>,
    pub privileged_pods: HashSet<String>,
    pub public_ips: HashSet<String>,
    pub host_networks: HashSet<String>,
    /// Map of resource names (e.g. "my-bucket") to the file that defines them as public.
    pub public_resources: HashMap<String, String>,
}

#[derive(Debug, Default, Clone)]
pub struct GlobalTaintMap {
    /// Maps function names to a set of (parameter_name, source_kind) that are tainted.
    pub tainted_params: HashMap<String, Vec<(String, String)>>,
}

impl GlobalTaintMap {
    pub fn build(file_semantics: &HashMap<std::path::PathBuf, crate::matcher::semantics::FileSemantics>) -> Self {
        let mut gtm = Self::default();
        let global_definitions: HashMap<String, Vec<String>> = file_semantics
            .values()
            .flat_map(|semantics| semantics.function_definitions.iter())
            .map(|(func_name, params)| (func_name.clone(), params.clone()))
            .collect();
        
        for semantics in file_semantics.values() {
            for (func_name, arg_idx, source_kind) in &semantics.tainted_calls {
                if let Some(params) = global_definitions.get(func_name) {
                    if let Some(param_name) = params.get(*arg_idx) {
                        gtm.tainted_params.entry(func_name.clone())
                            .or_default()
                            .push((param_name.clone(), source_kind.clone()));
                    }
                }
            }
        }
        gtm
    }
}

pub fn run(target: &Path, pack: &RulePack) -> Result<Vec<Finding>> {
    run_with_context(target, pack, None)
}

pub fn run_with_context(target: &Path, pack: &RulePack, cloud: Option<CloudContext>) -> Result<Vec<Finding>> {
    if !target.exists() {
        anyhow::bail!("target does not exist: {}", target.display());
    }

    let detected_frameworks: HashSet<String> = framework::detect(target)
        .into_iter()
        .map(|fw| matcher::normalise_framework_name(&fw.name))
        .collect();

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

    // Pass 1: Extract Semantics and Build Global Taint Map
    let file_semantics: HashMap<std::path::PathBuf, crate::matcher::semantics::FileSemantics> = files
        .par_iter()
        .map(|path| {
            let lang = Lang::from_path(path).expect("filtered above");
            let source = fs::read_to_string(path).unwrap_or_default();
            (
                path.clone(),
                crate::matcher::semantics::extract_with_context(
                    lang,
                    &source,
                    Some(path.as_path()),
                    Some(target),
                ),
            )
        })
        .collect();

    let gtm = GlobalTaintMap::build(&file_semantics);

    // Pass 2: Run Rules with Global Taint Context
    let mut findings: Vec<Finding> = files
        .par_iter()
        .flat_map_iter(|path| {
            let lang = Lang::from_path(path).expect("filtered above");
            let semantics = file_semantics.get(path).cloned().unwrap_or_default();
            let mut final_semantics = semantics.clone();
            
            // Inject global taint into local semantics
            for (func_name, params) in &semantics.function_definitions {
                if let Some(tainted_params) = gtm.tainted_params.get(func_name) {
                    for (param_name, source_kind) in tainted_params {
                        if params.contains(param_name) {
                            final_semantics.tainted_identifiers.insert(param_name.clone(), source_kind.clone());
                        }
                    }
                }
            }

            match fs::read_to_string(path) {
                Ok(source) => matcher::run_rules_with_semantics(pack.rules(), lang, &detected_frameworks, path, &source, Some(target), &final_semantics),
                Err(err) => {
                    log::warn!("skipping {}: {err}", path.display());
                    Vec::new()
                }
            }
        })
        .collect();

    dedup_findings(&mut findings);
    collapse_semantic_overlaps(&mut findings);
    enrich_finding_context(target, &mut findings, cloud.as_ref());

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
    Ok(matcher::run_rules(pack.rules(), lang, &HashSet::new(), path, &source, None))
}

fn dedup_findings(findings: &mut Vec<Finding>) {
    let mut merged = Vec::with_capacity(findings.len());
    let mut seen: HashMap<String, usize> = HashMap::new();

    for finding in findings.drain(..) {
        let key = finding.fingerprint.clone();

        if let Some(idx) = seen.get(&key).copied() {
            merge_finding(&mut merged[idx], finding);
            continue;
        }

        let idx = merged.len();
        seen.insert(key, idx);
        merged.push(finding);
    }

    *findings = merged;
}

fn merge_finding(existing: &mut Finding, duplicate: Finding) {
    for (key, value) in duplicate.evidence {
        existing.evidence.entry(key).or_insert(value);
    }

    if better_reachability(duplicate.reachability.as_deref(), existing.reachability.as_deref()) {
        existing.reachability = duplicate.reachability;
    }
}

fn better_reachability(candidate: Option<&str>, current: Option<&str>) -> bool {
    fn score(value: Option<&str>) -> u8 {
        match value {
            Some("reachable") => 3,
            Some("unknown") => 2,
            Some("unreachable") => 1,
            _ => 0,
        }
    }

    score(candidate) > score(current)
}

fn collapse_semantic_overlaps(findings: &mut Vec<Finding>) {
    let mut merged = Vec::with_capacity(findings.len());
    let mut seen: HashMap<(String, String), usize> = HashMap::new();

    for finding in findings.drain(..) {
        let Some(sink_group) = overlap_group(&finding) else {
            merged.push(finding);
            continue;
        };

        let key = (
            finding.file.to_string_lossy().to_string() + ":" + &finding.start_byte.to_string(),
            sink_group,
        );

        if let Some(idx) = seen.get(&key).copied() {
            merge_overlapping_finding(&mut merged[idx], finding);
            continue;
        }

        let idx = merged.len();
        seen.insert(key, idx);
        merged.push(finding);
    }

    *findings = merged;
}

fn overlap_group(finding: &Finding) -> Option<String> {
    let sink_kind = finding.evidence.get("sink_kind").and_then(|v| v.as_str())?;
    Some(match sink_kind {
        "dom.inner_html" | "dom.document_write" | "react.dangerously_set_inner_html" => "xss.html_injection".into(),
        "rails.raw" | "rails.html_safe" | "rails.render_text" | "rails.render_inline" | "rails.content_tag" => "rails.html_unsafe_render".into(),
        "flask.make_response" | "flask.render_template_string" => "python.web_unsafe_render".into(),
        "python.eval" | "python.exec" | "java.script_engine.eval" | "spring.spel.parse_expression" => "dynamic.code_execution".into(),
        other => other.to_string(),
    })
}

fn merge_overlapping_finding(existing: &mut Finding, mut candidate: Finding) {
    let existing_score = specificity_score(existing);
    let candidate_score = specificity_score(&candidate);
    let existing_rule = existing.rule_id.clone();
    let candidate_rule = candidate.rule_id.clone();

    if candidate_score > existing_score {
        merge_finding(&mut candidate, existing.clone());
        record_overlap(&mut candidate, &existing_rule);
        *existing = candidate;
    } else {
        merge_finding(existing, candidate);
        record_overlap(existing, &candidate_rule);
    }
}

fn record_overlap(finding: &mut Finding, rule_id: &str) {
    let entry = finding.evidence
        .entry("overlap_rule_ids".into())
        .or_insert_with(|| serde_json::json!([]));
    if let Some(arr) = entry.as_array_mut() {
        if !arr.iter().any(|v| v.as_str() == Some(rule_id)) {
            arr.push(serde_json::json!(rule_id));
        }
    }
}

fn specificity_score(finding: &Finding) -> i64 {
    let mut score = 0i64;
    score += (finding.evidence.get("confidence_score")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0) * 100.0) as i64;
    if finding.evidence.contains_key("source_kind") { score += 20; }
    if finding.evidence.contains_key("framework") { score += 10; }
    if finding.evidence.get("matcher_kind").and_then(|v| v.as_str()) == Some("tree_sitter") { score += 8; }
    score += match finding.reachability.as_deref() {
        Some("reachable") => 6,
        Some("unknown") => 3,
        _ => 0,
    };
    score
}

fn enrich_finding_context(target: &Path, findings: &mut [Finding], cloud: Option<&CloudContext>) {
    for finding in findings {
        if let Some(relative) = relative_display_path(target, &finding.file) {
            let fingerprint = compute_fingerprint(finding, &relative);
            finding.evidence.entry("finding_fingerprint".into())
                .or_insert_with(|| serde_json::json!(fingerprint));

            if let Some((kind, reason)) = context_suppression(&finding.file, &relative) {
                finding.evidence.entry("context_suppression".into())
                    .or_insert_with(|| serde_json::json!(kind));
                finding.evidence.entry("context_suppression_reason".into())
                    .or_insert_with(|| serde_json::json!(reason));
                lower_confidence_for_suppressed_context(finding);
            }
        }

        // --- Code to Cloud Synergy: Severity Boosting ---
        if let Some(ctx) = cloud {
            // 1. General Context Boosting (High-Risk Infrastructure)
            if finding.severity >= crate::finding::Severity::High {
                if !ctx.privileged_pods.is_empty() || !ctx.host_networks.is_empty() {
                    let old_severity = finding.severity;
                    finding.severity = crate::finding::Severity::Critical;
                    finding.evidence.insert("cloud_context_boost".into(), serde_json::json!(true));
                    finding.evidence.insert("cloud_context_reason".into(), 
                        serde_json::json!(format!("Boosted from {} due to high-risk cloud configuration (privileged pods or host network detected in manifests)", old_severity)));
                }
            }

            // 2. Resource Linkage (Mapping Code to specific Public Infrastructure)
            for (res_name, infra_file) in &ctx.public_resources {
                // If the code is interacting with a resource named in a public IaC manifest
                if finding.snippet.contains(res_name) {
                    finding.severity = crate::finding::Severity::Critical;
                    finding.evidence.insert("iac_linkage_detected".into(), serde_json::json!(true));
                    finding.evidence.insert("iac_resource_name".into(), serde_json::json!(res_name));
                    finding.evidence.insert("iac_resource_file".into(), serde_json::json!(infra_file));
                    finding.evidence.insert("cloud_context_reason".into(), 
                        serde_json::json!(format!("CRITICAL: Code interacts with resource '{}' which is marked PUBLIC in {}", res_name, infra_file)));
                }
            }
        }
    }
}

fn relative_display_path(target: &Path, file: &Path) -> Option<String> {
    file.strip_prefix(target).ok()
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .or_else(|| Some(file.to_string_lossy().replace('\\', "/")))
}

fn context_suppression(path: &Path, relative: &str) -> Option<(&'static str, &'static str)> {
    let rel = relative.to_ascii_lowercase();
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_ascii_lowercase();

    // 1. Tests and Fixtures
    if rel.contains("/fixtures/") || rel.starts_with("fixtures/") || rel.contains("/testdata/") {
        return Some(("test_fixture_path", "fixture_or_sample_content"));
    }
    if rel.contains("/tests/") || rel.starts_with("tests/") ||
       rel.contains("/test/") || rel.starts_with("test/") ||
       rel.contains("/spec/") || rel.starts_with("spec/") ||
       rel.contains("/__tests__/") || rel.contains("/__mocks__/") {
        return Some(("test_code_path", "test_or_mock_directory"));
    }

    // 2. Third-party / Vendored
    if rel.contains("/vendor/") || rel.starts_with("vendor/") ||
       rel.contains("/node_modules/") || rel.contains("/bower_components/") ||
       rel.contains("/third_party/") || rel.contains("/.terraform/") {
        return Some(("third_party_path", "vendored_or_external_code"));
    }

    // 3. Generated / Build Artifacts
    if rel.contains("/dist/") || rel.starts_with("dist/") ||
       rel.contains("/build/") || rel.starts_with("build/") ||
       rel.contains("/out/") || rel.starts_with("out/") ||
       rel.contains("/target/") || rel.starts_with("target/") ||
       rel.contains("/bin/") || rel.starts_with("bin/") ||
       rel.contains("/obj/") || rel.starts_with("obj/") {
        return Some(("generated_path", "build_output_or_generated_artifact"));
    }
    if rel.contains("/generated/") || rel.starts_with("generated/") ||
       file_name.contains(".generated.") || file_name.contains(".gen.") ||
       file_name.ends_with(".pb.go") || file_name.ends_with(".pb.rs") {
        return Some(("generated_path", "automatically_generated_code"));
    }
    if file_name.ends_with(".g.cs") || file_name.ends_with(".designer.cs") || file_name == "assemblyinfo.cs" {
        return Some(("generated_path", "generated_dotnet_source"));
    }
    if file_name.ends_with(".min.js") || file_name.ends_with(".min.css") {
        return Some(("generated_path", "minified_asset"));
    }

    // 4. Lockfiles and Metadata
    if file_name.ends_with(".lock") || file_name == "package-lock.json" ||
       file_name == "yarn.lock" || file_name == "pnpm-lock.yaml" ||
       file_name == "cargo.lock" || file_name == "go.sum" ||
       file_name == "pom.xml" || file_name == "composer.lock" {
        return Some(("metadata_path", "lockfile_or_manifest"));
    }

    None
}

fn lower_confidence_for_suppressed_context(finding: &mut Finding) {
    let old_label = finding.evidence.get("confidence")
        .and_then(|v| v.as_str())
        .unwrap_or("low")
        .to_string();
    let old_score = finding.evidence.get("confidence_score").and_then(|v| v.as_f64()).unwrap_or(0.50);
    let new_score = old_score.min(0.35);
    let new_label = if new_score >= 0.80 {
        "high"
    } else if new_score >= 0.55 {
        "medium"
    } else {
        "low"
    };
    finding.evidence.insert("confidence".into(), serde_json::json!(new_label));
    finding.evidence.insert("confidence_score".into(), serde_json::json!(new_score));
    finding.evidence.insert(
        "confidence_reason".into(),
        serde_json::json!(format!("context_suppressed:{old_label}")),
    );
}

fn compute_fingerprint(finding: &Finding, relative: &str) -> String {
    let sink_group = overlap_group(finding).unwrap_or_else(|| finding.rule_id.clone());
    let source_kind = finding.evidence.get("source_kind").and_then(|v| v.as_str()).unwrap_or("");
    let framework = finding.evidence.get("framework").and_then(|v| v.as_str()).unwrap_or("");
    let normalized = normalize_snippet(&finding.snippet);
    let raw = format!("{relative}|{sink_group}|{source_kind}|{framework}|{normalized}");
    format!("{:016x}", fnv1a_64(raw.as_bytes()))
}

fn normalize_snippet(snippet: &str) -> String {
    let mut out = String::with_capacity(snippet.len());
    let mut in_space = false;
    for ch in snippet.chars() {
        if ch.is_whitespace() {
            if !in_space {
                out.push(' ');
                in_space = true;
            }
        } else if ch.is_ascii_digit() {
            out.push('#');
            in_space = false;
        } else if ch == '"' || ch == '\'' {
            out.push('"');
            in_space = false;
        } else {
            out.push(ch.to_ascii_lowercase());
            in_space = false;
        }
    }
    out.trim().to_string()
}

fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use std::collections::HashMap;
    use std::path::PathBuf;

    #[test]
    fn duplicate_findings_are_collapsed_and_evidence_is_merged() {
        let mut findings = vec![
            Finding {
                rule_id: "CBR-TEST".into(),
                title: "test".into(),
                severity: Severity::High,
                message: "msg".into(),
                file: PathBuf::from("app.py"),
                line: 10,
                column: 3,
                end_line: 10,
                end_column: 12,
                fingerprint: String::new(),
                start_byte: 0,
                end_byte: 0,
                snippet: "eval(user_input)".into(),
                fix_recipe: None,
                fix: None,
                cwe: vec![],
                evidence: HashMap::from([("matcher_kind".into(), serde_json::json!("regex"))]),
                reachability: Some("unknown".into()),
            },
            Finding {
                rule_id: "CBR-TEST".into(),
                title: "test".into(),
                severity: Severity::High,
                message: "msg".into(),
                file: PathBuf::from("app.py"),
                line: 10,
                column: 3,
                end_line: 10,
                end_column: 12,
                fingerprint: String::new(),
                start_byte: 0,
                end_byte: 0,
                snippet: "eval(user_input)".into(),
                fix_recipe: None,
                fix: None,
                cwe: vec![],
                evidence: HashMap::from([("source_kind".into(), serde_json::json!("flask.request.args"))]),
                reachability: Some("reachable".into()),
            },
        ];

        dedup_findings(&mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].reachability.as_deref(), Some("reachable"));
        assert_eq!(findings[0].evidence.get("matcher_kind").and_then(|v| v.as_str()), Some("regex"));
        assert_eq!(findings[0].evidence.get("source_kind").and_then(|v| v.as_str()), Some("flask.request.args"));
    }

    #[test]
    fn semantic_overlaps_keep_more_specific_finding() {
        let mut findings = vec![
            Finding {
                rule_id: "CBR-GENERIC".into(),
                title: "generic".into(),
                severity: Severity::High,
                message: "msg".into(),
                file: PathBuf::from("app.py"),
                line: 10,
                column: 3,
                end_line: 10,
                end_column: 18,
                fingerprint: String::new(),
                start_byte: 0,
                end_byte: 0,
                snippet: "eval(user_input)".into(),
                fix_recipe: None,
                fix: None,
                cwe: vec![],
                evidence: HashMap::from([
                    ("sink_kind".into(), serde_json::json!("python.eval")),
                    ("matcher_kind".into(), serde_json::json!("regex")),
                    ("confidence_score".into(), serde_json::json!(0.62)),
                ]),
                reachability: Some("unknown".into()),
            },
            Finding {
                rule_id: "CBR-SPECIFIC".into(),
                title: "specific".into(),
                severity: Severity::High,
                message: "msg".into(),
                file: PathBuf::from("app.py"),
                line: 10,
                column: 3,
                end_line: 10,
                end_column: 18,
                fingerprint: String::new(),
                start_byte: 0,
                end_byte: 0,
                snippet: "eval(user_input)".into(),
                fix_recipe: None,
                fix: None,
                cwe: vec![],
                evidence: HashMap::from([
                    ("sink_kind".into(), serde_json::json!("python.eval")),
                    ("source_kind".into(), serde_json::json!("flask.request.args")),
                    ("framework".into(), serde_json::json!("flask")),
                    ("matcher_kind".into(), serde_json::json!("tree_sitter")),
                    ("confidence_score".into(), serde_json::json!(0.95)),
                ]),
                reachability: Some("reachable".into()),
            },
        ];

        collapse_semantic_overlaps(&mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "CBR-SPECIFIC");
        assert_eq!(findings[0].reachability.as_deref(), Some("reachable"));
        assert_eq!(findings[0].evidence.get("overlap_rule_ids").and_then(|v| v.as_array()).map(|a| a.len()), Some(1));
    }

    #[test]
    fn fingerprints_are_stable_for_line_movement() {
        let mut a = vec![Finding {
            rule_id: "CBR-TEST".into(),
            title: "test".into(),
            severity: Severity::High,
            message: "msg".into(),
            file: PathBuf::from("/repo/src/app.py"),
            line: 10,
            column: 3,
            end_line: 10,
            end_column: 18,
            fingerprint: String::new(),
            start_byte: 0,
            end_byte: 0,
            snippet: "eval(user_input)".into(),
            fix_recipe: None,
            fix: None,
            cwe: vec![],
            evidence: HashMap::from([
                ("sink_kind".into(), serde_json::json!("python.eval")),
                ("source_kind".into(), serde_json::json!("flask.request.args")),
                ("framework".into(), serde_json::json!("flask")),
            ]),
            reachability: Some("reachable".into()),
        }];
        let mut b = a.clone();
        b[0].line = 42;
        b[0].end_line = 42;
        enrich_finding_context(Path::new("/repo"), &mut a, None);
        enrich_finding_context(Path::new("/repo"), &mut b, None);
        assert_eq!(a[0].evidence.get("finding_fingerprint"), b[0].evidence.get("finding_fingerprint"));
    }

    #[test]
    fn context_suppression_lowers_confidence() {
        let mut findings = vec![Finding {
            rule_id: "CBR-TEST".into(),
            title: "test".into(),
            severity: Severity::High,
            message: "msg".into(),
            file: PathBuf::from("/repo/tests/fixtures/app.py"),
            line: 10,
            column: 3,
            end_line: 10,
            end_column: 18,
            fingerprint: String::new(),
            start_byte: 0,
            end_byte: 0,
            snippet: "eval(user_input)".into(),
            fix_recipe: None,
            fix: None,
            cwe: vec![],
            evidence: HashMap::from([
                ("sink_kind".into(), serde_json::json!("python.eval")),
                ("source_kind".into(), serde_json::json!("flask.request.args")),
                ("framework".into(), serde_json::json!("flask")),
                ("confidence".into(), serde_json::json!("high")),
                ("confidence_score".into(), serde_json::json!(0.95)),
            ]),
            reachability: Some("reachable".into()),
        }];
        enrich_finding_context(Path::new("/repo"), &mut findings, None);
        assert_eq!(findings[0].evidence.get("context_suppression").and_then(|v| v.as_str()), Some("test_fixture_path"));
        assert_eq!(findings[0].evidence.get("confidence").and_then(|v| v.as_str()), Some("low"));
    }

    #[test]
    fn generated_dotnet_files_are_context_suppressed() {
        let mut findings = vec![Finding {
            rule_id: "CBR-TEST".into(),
            title: "test".into(),
            severity: Severity::High,
            message: "msg".into(),
            file: PathBuf::from("/repo/Views/Generated.g.cs"),
            line: 10,
            column: 3,
            end_line: 10,
            end_column: 18,
            fingerprint: String::new(),
            start_byte: 0,
            end_byte: 0,
            snippet: "return Html.Encode(userInput);".into(),
            fix_recipe: None,
            fix: None,
            cwe: vec![],
            evidence: HashMap::from([
                ("sink_kind".into(), serde_json::json!("generic.output")),
                ("confidence".into(), serde_json::json!("medium")),
                ("confidence_score".into(), serde_json::json!(0.62)),
            ]),
            reachability: Some("unknown".into()),
        }];
        enrich_finding_context(Path::new("/repo"), &mut findings, None);
        assert_eq!(findings[0].evidence.get("context_suppression_reason").and_then(|v| v.as_str()), Some("generated_dotnet_source"));
        assert_eq!(findings[0].evidence.get("confidence").and_then(|v| v.as_str()), Some("low"));
    }
}
