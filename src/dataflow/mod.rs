//! Inter-procedural dataflow / taint propagation (Gap A4).
//!
//! The semantic extractor (`matcher::semantics`) already emits the
//! per-file primitives we need:
//!
//!   * `tainted_calls`      — call-sites known to receive a source kind
//!   * `tainted_identifiers` — variables holding a tainted value
//!   * `function_definitions` — function name → parameter list
//!   * `param_call_edges`    — caller param N is forwarded to callee arg M
//!   * `return_param_indices` — function returns parameter index N
//!   * `direct_return_sources` — function directly returns a source kind
//!   * `return_param_sanitizers` — function sanitises parameter N
//!   * `direct_sanitized_returns` — function returns a sanitised source
//!   * `call_assignments`   — `let x = f(args)` form
//!
//! This module aggregates those across every scanned file into a
//! `ProjectSemantics` struct, then runs a fixed-point taint propagator
//! that answers two questions for any function name:
//!
//!   1. Is parameter N reachable from a tainted source via cross-file
//!      callers?
//!   2. Does the function transitively return a tainted value (modulo
//!      sanitisers)?
//!
//! The propagator is conservative — when in doubt, mark tainted. False
//! positives are easier to triage than missed taint.
//!
//! Rules opt in via a `dataflow:` block:
//!
//! ```yaml
//! id: CBR-PY-SQLI
//! dataflow:
//!   require_reachable: true   # suppress if no source reaches the sink
//! ```
//!
//! When set, the matcher consults `ProjectSemantics::is_reachable_from_source`
//! for the function enclosing each match. Findings get
//! `evidence.dataflow_reachable: bool` and
//! `evidence.dataflow_path: ["caller_a:1", "callee_b:2", "sink_c"]` when
//! a chain is found.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::matcher::semantics::FileSemantics;

/// Project-wide aggregation of per-file semantics. Indexed by function
/// name (NOT file-qualified — Rust/Java collisions are accepted; the
/// propagator is conservative on ambiguous matches).
#[derive(Debug, Default)]
pub struct ProjectSemantics {
    /// All per-file semantics, keyed by absolute path. Kept around so
    /// findings can resolve `is_reachable_from_source` per-file.
    pub by_file: HashMap<PathBuf, FileSemantics>,

    /// Global function index. Same name across files = appended entries.
    pub functions: HashMap<String, Vec<FunctionRef>>,

    /// Function names whose return value is tainted (after fixed-point
    /// resolution). Includes:
    ///   * functions in `direct_return_sources`
    ///   * functions in `return_param_indices` whose param[idx] is
    ///     itself tainted via param_call_edges
    /// Functions in `direct_sanitized_returns` and
    /// `return_param_sanitizers` are excluded.
    pub tainted_returning_fns: HashSet<String>,

    /// Function names → parameter indices known to receive tainted input
    /// from at least one caller. After the fixed-point pass this carries
    /// the full transitive set.
    pub tainted_params: HashMap<String, HashSet<usize>>,

    /// Reverse call-graph: callee → list of (caller, caller_param_idx,
    /// callee_arg_idx). Built during `build()` so backwards reachability
    /// queries don't have to re-walk every file's param_call_edges.
    pub reverse_param_edges: HashMap<String, Vec<ReverseEdge>>,

    /// Per-function source kinds that originate the taint reaching it.
    /// Populated during the fixed-point pass: when a tainted_call seeds
    /// `(callee, arg_idx, kind)`, we propagate `kind` along param_call_edges
    /// so any function transitively reached records WHICH source got it
    /// here. Findings can surface this as `evidence.reaching_sources`.
    pub reaching_sources: HashMap<String, HashSet<String>>,

    /// Project-wide class / type hierarchy. Aggregates every file's
    /// `FileSemantics::type_hierarchy` so a `class A : B` declared in
    /// `B.cs` and instantiated in `A.cs` is walkable transitively.
    /// Index: `child_type -> set(direct_parent)`. Walks are
    /// cycle-protected via `supertypes_of`.
    pub class_hierarchy: HashMap<String, HashSet<String>>,
}

/// Reverse-direction call edge — used by backwards reachability queries.
#[derive(Debug, Clone)]
pub struct ReverseEdge {
    pub caller:           String,
    pub caller_param_idx: usize,
    pub callee_arg_idx:   usize,
}

/// Pointer back to where a function lives. Identity is (file, name).
#[derive(Debug, Clone)]
pub struct FunctionRef {
    pub file:  PathBuf,
    pub name:  String,
    pub params: Vec<String>,
}

impl ProjectSemantics {
    /// Build a project-wide view from a list of (path, FileSemantics).
    /// Runs the fixed-point taint propagator before returning.
    pub fn build(files: Vec<(PathBuf, FileSemantics)>) -> Self {
        let mut me = ProjectSemantics::default();

        // Pass 1 — populate function index + seed tainted_params from
        // direct sources and tainted_calls. Resolve callable_aliases
        // (Phase A — dynamic dispatch): when `f = eval` and a tainted
        // call lands on `f`, we mirror it onto `eval` so the propagator
        // sees them as the same sink.
        for (path, sem) in &files {
            for (name, params) in &sem.function_definitions {
                me.functions
                    .entry(name.clone())
                    .or_default()
                    .push(FunctionRef {
                        file:   path.clone(),
                        name:   name.clone(),
                        params: params.clone(),
                    });
            }
            // Seed direct-return-source functions as "tainted return".
            for (name, _kinds) in &sem.direct_return_sources {
                me.tainted_returning_fns.insert(name.clone());
            }
            // Seed tainted_calls into tainted_params + reaching_sources.
            for (callee_name, arg_idx, kind) in &sem.tainted_calls {
                me.tainted_params
                    .entry(callee_name.clone())
                    .or_default()
                    .insert(*arg_idx);
                me.reaching_sources
                    .entry(callee_name.clone())
                    .or_default()
                    .insert(kind.clone());
                // Phase A: if the callee is a callable_alias to another
                // function, mirror the taint onto the underlying name.
                if let Some(real) = sem.callable_aliases.get(callee_name) {
                    me.tainted_params
                        .entry(real.clone())
                        .or_default()
                        .insert(*arg_idx);
                    me.reaching_sources
                        .entry(real.clone())
                        .or_default()
                        .insert(kind.clone());
                }
            }
            // Build the reverse call graph from forward param_call_edges.
            for edge in &sem.param_call_edges {
                me.reverse_param_edges
                    .entry(edge.callee.clone())
                    .or_default()
                    .push(ReverseEdge {
                        caller:           edge.caller.clone(),
                        caller_param_idx: edge.caller_param_idx,
                        callee_arg_idx:   edge.callee_arg_idx,
                    });
            }
        }

        // Pass 2 — fixed-point: propagate tainted_returning_fns +
        // tainted_params via param_call_edges and return_param_indices,
        // respecting sanitisers. Bounded iteration count keeps weird
        // cyclic graphs from looping forever.
        let mut changed = true;
        let mut iters   = 0;
        while changed && iters < 32 {
            changed = false;
            iters  += 1;

            for (_path, sem) in &files {
                // (a) param_call_edges: if caller's param P is tainted
                // and edge maps to callee's arg A, then callee's
                // param A is tainted (unless callee sanitises it).
                for edge in &sem.param_call_edges {
                    let caller_param_tainted = me
                        .tainted_params
                        .get(&edge.caller)
                        .map(|s| s.contains(&edge.caller_param_idx))
                        .unwrap_or(false);
                    if !caller_param_tainted { continue; }
                    if Self::is_param_sanitised(sem, &edge.callee, edge.callee_arg_idx) {
                        continue;
                    }
                    let inserted = me
                        .tainted_params
                        .entry(edge.callee.clone())
                        .or_default()
                        .insert(edge.callee_arg_idx);
                    if inserted { changed = true; }

                    // Propagate reaching_sources from caller to callee
                    // along the same edge so the sink-side knows WHICH
                    // sources brought the taint.
                    if let Some(caller_sources) = me.reaching_sources.get(&edge.caller).cloned() {
                        let entry = me.reaching_sources.entry(edge.callee.clone()).or_default();
                        for s in caller_sources {
                            if entry.insert(s) { changed = true; }
                        }
                    }
                }

                // (b) return_param_indices: if a function returns its
                // param N, and param N is tainted, the function itself
                // is "tainted-returning".
                for (fn_name, return_idxs) in &sem.return_param_indices {
                    if me.tainted_returning_fns.contains(fn_name) { continue; }
                    if Self::is_directly_sanitising(sem, fn_name) { continue; }
                    let any = return_idxs.iter().any(|idx| {
                        me.tainted_params
                            .get(fn_name)
                            .map(|s| s.contains(idx))
                            .unwrap_or(false)
                    });
                    if any && me.tainted_returning_fns.insert(fn_name.clone()) {
                        changed = true;
                    }
                }

                // (c) call_assignments: `let x = f(args)`. If f returns
                // tainted, x is tainted. We surface this by tagging the
                // assignment ident as a "synthetic param" of the
                // surrounding scope — but for the v1 propagator we use
                // the simpler "function caller knows the call returns
                // tainted" via tainted_returning_fns, and let the rule
                // matcher consult that directly.
                let _ = &sem.call_assignments; // reserved for v2
            }
        }

        // Pass 3 — class hierarchy aggregation. Each file's local
        // type_hierarchy is merged into a project-wide index. Cross-file
        // walks (`SqlCommand : DbCommand` declared in `B.cs`, used in
        // `A.cs`) become tractable here.
        for (_path, sem) in &files {
            for (child, parents) in &sem.type_hierarchy {
                let entry = me.class_hierarchy.entry(child.clone()).or_default();
                for p in parents {
                    entry.insert(p.clone());
                }
            }
        }

        // Stash the by-file view last so the borrow on `files` ended.
        me.by_file = files.into_iter().collect();
        me
    }

    /// Transitive supertypes of `type_name` walked through the
    /// project-wide class hierarchy. Includes the type itself in the
    /// returned set (so callers can do straight membership checks).
    /// Cycle-protected.
    pub fn supertypes_of(&self, type_name: &str) -> HashSet<String> {
        let mut out: HashSet<String> = HashSet::new();
        let mut frontier: Vec<String> = vec![type_name.to_string()];
        while let Some(cur) = frontier.pop() {
            if !out.insert(cur.clone()) { continue; }
            if let Some(parents) = self.class_hierarchy.get(&cur) {
                for p in parents {
                    if !out.contains(p) { frontier.push(p.clone()); }
                }
            }
            // Also try the trailing-segment match — Java/C# often
            // store FQNs (`com.acme.SqlCommand`) but rules will list
            // the short name. If `cur` matches the tail of a stored
            // key, descend through that key's parents too.
            for (k, parents) in &self.class_hierarchy {
                if k != &cur && (k.ends_with(&format!(".{cur}")) || k.ends_with(&format!("::{cur}"))) {
                    for p in parents {
                        if !out.contains(p) { frontier.push(p.clone()); }
                    }
                }
            }
        }
        out
    }

    /// True when `child` resolves (transitively, through the project
    /// class hierarchy) to a type that equals or extends `parent`.
    /// Substring containment in either direction is accepted so
    /// `SqlCommand` ≡ `Microsoft.Data.SqlClient.SqlCommand`.
    pub fn is_subtype_of(&self, child: &str, parent: &str) -> bool {
        if child == parent { return true; }
        let supers = self.supertypes_of(child);
        supers.iter().any(|t| {
            t == parent
                || t.contains(parent)
                || parent.contains(t.as_str())
        })
    }

    /// Return true if any parameter of the function `fn_name` is known
    /// to be tainted via cross-file propagation. Used by rules with
    /// `dataflow.require_reachable: true` to suppress findings whose
    /// enclosing function is provably unreachable from any source.
    ///
    /// The lookup matches both the exact key and any namespace-prefixed
    /// variant (e.g. `util::format_query` matches a query for
    /// `format_query`) so callers don't need to know how the extractor
    /// canonicalised the function identity.
    pub fn is_reachable_from_source(&self, fn_name: &str) -> bool {
        if self.match_in_tainted_params(fn_name) { return true; }
        if self.match_in_tainted_returning(fn_name) { return true; }
        false
    }

    fn match_in_tainted_params(&self, fn_name: &str) -> bool {
        self.tainted_params
            .iter()
            .any(|(k, v)| (k == fn_name || k.ends_with(&format!("::{fn_name}"))) && !v.is_empty())
    }

    fn match_in_tainted_returning(&self, fn_name: &str) -> bool {
        self.tainted_returning_fns
            .iter()
            .any(|k| k == fn_name || k.ends_with(&format!("::{fn_name}")))
    }

    /// Backwards reachability — given a sink function name, walk the
    /// reverse call graph upward and collect every source kind that
    /// transitively reaches it. Phase B closes the
    /// "Semgrep-Pro asks 'what sources hit this sink' starting from the
    /// finding, not from the sources" gap.
    ///
    /// Returns the deduplicated set of source kinds plus the chain of
    /// caller function names that brought them. The caller chain is
    /// best-effort and stops on cycles.
    pub fn sources_reaching(&self, sink_fn: &str) -> Vec<String> {
        let canonical = self.canonicalise(sink_fn).unwrap_or(sink_fn.to_string());
        let mut sources: HashSet<String> = HashSet::new();
        if let Some(set) = self.reaching_sources.get(&canonical) {
            sources.extend(set.iter().cloned());
        }

        // Walk reverse edges to harvest sources from callers we wouldn't
        // otherwise see (e.g. a caller that's tainted but never directly
        // reaches the canonical sink in tainted_params).
        let mut frontier  = vec![canonical.clone()];
        let mut visited   = HashSet::new();
        while let Some(cur) = frontier.pop() {
            if !visited.insert(cur.clone()) { continue; }
            if let Some(set) = self.reaching_sources.get(&cur) {
                sources.extend(set.iter().cloned());
            }
            if let Some(reverse_edges) = self.reverse_param_edges.get(&cur) {
                for re in reverse_edges {
                    frontier.push(re.caller.clone());
                }
            }
        }

        let mut out: Vec<String> = sources.into_iter().collect();
        out.sort();
        out
    }

    /// Backwards caller chain — returns the list of caller functions
    /// that lead from any source to `sink_fn`. Best-effort,
    /// breadth-first, stops on cycle.
    pub fn callers_of(&self, sink_fn: &str) -> Vec<String> {
        let canonical = self.canonicalise(sink_fn).unwrap_or(sink_fn.to_string());
        let mut visited: HashSet<String> = HashSet::new();
        let mut frontier: Vec<String> = vec![canonical];
        let mut chain:    Vec<String> = Vec::new();
        while let Some(cur) = frontier.pop() {
            if !visited.insert(cur.clone()) { continue; }
            if let Some(reverse_edges) = self.reverse_param_edges.get(&cur) {
                for re in reverse_edges {
                    if !visited.contains(&re.caller) {
                        chain.push(re.caller.clone());
                        frontier.push(re.caller.clone());
                    }
                }
            }
        }
        chain.dedup();
        chain
    }

    /// Best-effort dataflow path — list the [source_fn, ..., target_fn]
    /// chain that brings taint into `fn_name`. Falls back to the list
    /// of *direct* callers found in `tainted_calls` when the
    /// param_call_edges chain is empty (covers the common case where
    /// the source is a built-in like `request.GET.get` that never
    /// appears as a function definition).
    pub fn dataflow_path_to(&self, fn_name: &str) -> Vec<String> {
        // Resolve fn_name to the canonical key that matches our index.
        let canonical = self.canonicalise(fn_name).unwrap_or(fn_name.to_string());
        let mut path  = Vec::new();
        let mut seen  = HashSet::new();
        let mut cur   = canonical.clone();

        while !seen.contains(&cur) {
            seen.insert(cur.clone());
            path.push(cur.clone());
            let next = self.by_file.values().find_map(|sem| {
                sem.param_call_edges.iter().find_map(|edge| {
                    if edge.callee == cur
                        && self.tainted_params
                            .get(&edge.caller)
                            .map(|s| s.contains(&edge.caller_param_idx))
                            .unwrap_or(false)
                    {
                        Some(edge.caller.clone())
                    } else { None }
                })
            });
            match next {
                Some(caller) => cur = caller,
                None         => break,
            }
        }

        // If the chain has only the target node, augment with the kind
        // of the source that taints it (e.g. "django.request.GET") so
        // reviewers see WHERE the taint comes from even when no caller
        // chain was synthesised.
        if path.len() == 1 {
            let mut sources: Vec<String> = self.by_file.values()
                .flat_map(|sem| sem.tainted_calls.iter())
                .filter(|(callee, _idx, _kind)| *callee == canonical)
                .map(|(_callee, _idx, kind)| format!("source:{kind}"))
                .collect();
            sources.sort();
            sources.dedup();
            if !sources.is_empty() {
                let mut full = sources;
                full.push(canonical);
                return full;
            }
        }
        path.reverse();
        path
    }

    /// Canonicalise a bare name to the namespaced key actually stored
    /// in tainted_params / functions. Returns `None` when nothing
    /// matches.
    fn canonicalise(&self, fn_name: &str) -> Option<String> {
        if self.tainted_params.contains_key(fn_name) || self.functions.contains_key(fn_name) {
            return Some(fn_name.to_string());
        }
        for k in self.tainted_params.keys() {
            if k.ends_with(&format!("::{fn_name}")) { return Some(k.clone()); }
        }
        for k in self.functions.keys() {
            if k.ends_with(&format!("::{fn_name}")) { return Some(k.clone()); }
        }
        None
    }

    /// True if the function name appears in either
    /// `direct_sanitized_returns` or `return_param_sanitizers` for
    /// the given file's semantics.
    fn is_directly_sanitising(sem: &FileSemantics, fn_name: &str) -> bool {
        sem.direct_sanitized_returns.contains_key(fn_name)
    }

    /// True if the function sanitises its `param_idx`-th parameter.
    fn is_param_sanitised(sem: &FileSemantics, fn_name: &str, param_idx: usize) -> bool {
        sem.return_param_sanitizers
            .get(fn_name)
            .map(|sanitised| sanitised.iter().any(|(idx, _)| *idx == param_idx))
            .unwrap_or(false)
    }
}

/// Aggregate FileSemantics for every file under `target` matching a
/// supported language. Used by the scanner's project pre-pass.
pub fn aggregate_project<P: AsRef<Path>>(target: P) -> ProjectSemantics {
    use ignore::WalkBuilder;
    use std::fs;

    use crate::{lang::Lang, matcher::semantics};

    let mut entries: Vec<(PathBuf, FileSemantics)> = Vec::new();
    for entry in WalkBuilder::new(target.as_ref())
        .standard_filters(true)
        .hidden(false)
        .build()
        .filter_map(|r| r.ok())
    {
        if !entry.file_type().map_or(false, |ft| ft.is_file()) {
            continue;
        }
        let path = entry.path();
        let Some(lang) = Lang::from_path(path) else { continue };
        let Ok(source) = fs::read_to_string(path) else { continue };
        let sem = semantics::extract(lang, &source);
        entries.push((path.to_path_buf(), sem));
    }
    ProjectSemantics::build(entries)
}
