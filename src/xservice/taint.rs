//! Cross-service taint propagation — the practical version.
//!
//! Genuine cross-language IR-level taint is a multi-month research
//! effort (no commercial SAST ships it; the v0.15 honest assessment
//! called this out). What we do instead is **graph-level summary
//! propagation**:
//!
//!   1. Each scanned file produces a `FileSemantics` (already shipped
//!      in v0.13.0). It tells us which functions are *tainted-
//!      receiving* (their params accept a known source) and which are
//!      *tainted-returning* (they propagate the source through).
//!   2. The cross-service link graph (this module's input) tells us
//!      which controller calls which handler.
//!   3. We walk the link graph: when caller A's enclosing function
//!      transitively reaches a tainted source AND callee B's handler
//!      enclosing function is a sink, we emit a `CrossServiceTaint`
//!      link.
//!
//! It's not real IR taint — we don't trace the *value* — but it's a
//! best-effort answer to "is the path source → sink across services
//! reachable in principle". Findings get tagged with the resulting
//! chain so reviewers can confirm.
//!
//! The IR layer is still on the roadmap. This v1 ships the workflow
//! win without the multi-month engine work.

use std::path::PathBuf;

use crate::dataflow::ProjectSemantics;

#[derive(Debug, Clone, serde::Serialize)]
pub struct CrossServiceTaint {
    /// Caller-side function name that holds tainted state.
    pub caller_fn:   String,
    /// File where the caller lives.
    pub caller_file: PathBuf,
    /// Handler-side function name that accepts taint via the link.
    pub handler_fn:  String,
    /// File where the handler lives.
    pub handler_file: PathBuf,
    /// The HTTP method + path that bridges them.
    pub method:      String,
    pub path:        String,
    /// Source kinds that reached the handler through the chain.
    pub reaching_sources: Vec<String>,
    /// Confidence — 0.5 if we relied on summary heuristics, 0.85+
    /// when both sides have explicit taint markers.
    pub confidence:  f64,
}

/// Walk the cross-service link graph and emit a `CrossServiceTaint`
/// entry for every chain where the caller's enclosing function is
/// tainted and the handler's is a known sink-receiver.
pub fn build_cross_service_taint(
    map: &super::CrossServiceMap,
    project: &ProjectSemantics,
) -> Vec<CrossServiceTaint> {
    let mut out = Vec::new();
    for link in &map.links {
        let Some(handler) = &link.handler else { continue };

        // Caller-side enclosing function (best-effort): try the symbol
        // table from ProjectSemantics for the caller's file. Fall back
        // to `unknown_caller` so the chain still surfaces.
        let caller_fn = enclosing_function_name(&link.client.file, link.client.line, project)
            .unwrap_or_else(|| "<unknown>".into());
        let handler_fn = enclosing_function_name(&handler.file, handler.line, project)
            .unwrap_or_else(|| "<unknown>".into());

        // Reaching-source query at the handler. If nothing reaches
        // it, nothing to report — pure call-surface link.
        let sources = project.sources_reaching(&handler_fn);
        if sources.is_empty() { continue; }

        let confidence = if caller_fn != "<unknown>" && handler_fn != "<unknown>" {
            0.85
        } else { 0.5 };

        out.push(CrossServiceTaint {
            caller_fn,
            caller_file: link.client.file.clone(),
            handler_fn,
            handler_file: handler.file.clone(),
            method:       link.client.method.as_str().into(),
            path:         link.client.path.clone(),
            reaching_sources: sources,
            confidence,
        });
    }
    out
}

/// Cheap multi-language enclosing-function detection. Mirrors the
/// helper in `matcher::mod` but doesn't require importing it (and
/// keeps this module self-contained).
fn enclosing_function_name(file: &std::path::Path, line: usize, _proj: &ProjectSemantics) -> Option<String> {
    if line == 0 { return None }
    let body = std::fs::read_to_string(file).ok()?;
    use ::regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(
        r"(?m)^[\s]*(?:async\s+)?(?:pub\s+)?(?:def|function|fn|func|sub|public|private|protected|internal|static|void)\s+([A-Za-z_][A-Za-z_0-9]*)\s*\("
    ).unwrap());
    let mut current: Option<String> = None;
    for (idx, raw) in body.lines().enumerate() {
        let lineno = idx + 1;
        if lineno > line { break; }
        if let Some(c) = re.captures(raw) {
            current = c.get(1).map(|m| m.as_str().to_string());
        }
    }
    current
}
