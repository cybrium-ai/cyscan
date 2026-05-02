//! Rule pack — loading, validation, and the rule shape callers match against.

use std::{collections::HashMap, fs, path::Path};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{finding::Severity, lang::Lang, supply::policy::DependencyPolicy};

/// CIA impact level for a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CiaImpact {
    #[default]
    None,
    Low,
    Medium,
    High,
}

impl CiaImpact {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None   => "none",
            Self::Low    => "low",
            Self::Medium => "medium",
            Self::High   => "high",
        }
    }

    pub fn score(self) -> u32 {
        match self {
            Self::None   => 0,
            Self::Low    => 1,
            Self::Medium => 2,
            Self::High   => 3,
        }
    }
}

/// CIA triad impact classification for a rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CiaTriad {
    #[serde(default)]
    pub confidentiality: CiaImpact,
    #[serde(default)]
    pub integrity:       CiaImpact,
    #[serde(default)]
    pub availability:    CiaImpact,
}

/// A single detection rule as authored in YAML.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub id:        String,
    pub title:     String,
    pub severity:  Severity,
    /// Source-code rules declare which languages they apply to. Policy
    /// rules (`dependency:` set) may leave this empty.
    #[serde(default)]
    pub languages: Vec<Lang>,
    /// Tree-sitter query — structured, language-aware pattern.
    #[serde(default)]
    pub query:     Option<String>,
    /// Regex fallback — runs line-by-line when `query` is absent.
    /// Mutually exclusive with `query` — `query` wins if both set.
    #[serde(default)]
    pub regex:     Option<String>,
    /// Semgrep-style pattern — treated as regex for matching.
    /// Alias so imported rules with `pattern:` field work without conversion.
    #[serde(default)]
    pub pattern:   Option<String>,
    // ── Semgrep-DSL filters (Gap 3 / B1) ────────────────────────────────
    /// Conjunctive list of patterns. ALL must match for the rule to fire.
    #[serde(default)]
    pub patterns:  Vec<String>,
    /// Disjunctive list of patterns. At least ONE must match.
    #[serde(default)]
    pub pattern_either:        Vec<String>,
    /// Grouped any-of patterns. At least one *group* must match, and
    /// every entry inside that group must match together.
    #[serde(default)]
    pub pattern_either_groups: Vec<Vec<String>>,
    /// Negative pattern filter. If matched, the rule is suppressed.
    #[serde(default)]
    pub pattern_not:           Option<String>,
    /// Positive enclosing-context filter — match must occur inside a
    /// larger snippet matching this pattern.
    #[serde(default)]
    pub pattern_inside:        Option<String>,
    /// Negative enclosing-context filters. If the match occurs inside
    /// any of these contexts, the rule is suppressed.
    #[serde(default)]
    pub pattern_not_inside:    Vec<String>,
    /// Capture-aware comparison filter such as `len($arg) > 10` or
    /// `$fn == "eval"`. Singular form (legacy).
    #[serde(default)]
    pub metavariable_comparison: Option<String>,
    /// Boolean all-of comparisons.
    #[serde(default)]
    pub metavariable_comparisons: Vec<String>,
    /// Capture type constraints such as `arg: string` or `fn: identifier`.
    #[serde(default)]
    pub metavariable_types: HashMap<String, String>,
    /// Per-capture regex constraint — `{ arg: "^https?://" }`. The capture
    /// must satisfy its regex for the match to fire. Semgrep parity for
    /// `metavariable-regex`.
    #[serde(default)]
    pub metavariable_regex:   HashMap<String, String>,
    /// Per-capture sub-pattern — `{ arg: "TAINTED" }`. The capture's text
    /// must additionally contain a substring/regex matching the supplied
    /// pattern. Semgrep parity for `metavariable-pattern` (regex form;
    /// nested AST patterns deferred to a future release).
    #[serde(default)]
    pub metavariable_pattern: HashMap<String, String>,
    /// Negative regex filter on the matched span. If any of these regexes
    /// match the matched text, the finding is suppressed. Semgrep parity
    /// for `pattern-not-regex`.
    #[serde(default)]
    pub pattern_not_regex:    Vec<String>,
    /// Per-capture analyzers — `{ x: redos }`, `{ token: entropy }`,
    /// or `{ regex: redos, secret: entropy }`. The capture must
    /// satisfy the analyzer for the match to fire. Closes the
    /// Semgrep Pro `metavariable-analysis` gap; Semgrep OSS doesn't
    /// have this.
    ///
    /// Currently supported analyzer keys:
    ///   * `redos`   — catastrophic-backtracking risk in a regex literal
    ///   * `entropy` — high-entropy string (likely a secret / token)
    #[serde(default)]
    pub metavariable_analysis: HashMap<String, String>,
    /// Nested AST / cross-language sub-patterns. Each entry runs an
    /// inner pattern against the captured node's text, optionally
    /// re-parsing it as a different language. Closes the Semgrep
    /// `metavariable-pattern: { language: ..., pattern: ... }` gap.
    ///
    /// Example — match JS inside an HTML <script> block:
    ///
    /// ```yaml
    /// query: |
    ///   (script_element (raw_text) @js)
    /// metavariable_pattern_ast:
    ///   js:
    ///     language: javascript
    ///     pattern: eval(...)
    /// ```
    #[serde(default)]
    pub metavariable_pattern_ast: HashMap<String, NestedPatternSpec>,
    /// Compound boolean expression over metavariables — Semgrep beta
    /// `pattern-where`. Supports `and`, `or`, `not`, and the same
    /// comparison primitives as `metavariable-comparison`. Empty =
    /// no constraint.
    ///
    /// Example: `len($x) > 10 and $fn != "eval" and not $x contains "test"`
    #[serde(default)]
    pub pattern_where: Option<String>,
    pub message:   String,
    #[serde(default)]
    pub fix_recipe: Option<String>,
    /// Literal replacement text spliced over the matched range when
    /// `cyscan fix` is invoked. Rules without a `fix:` block are skipped
    /// by the fix subcommand.
    #[serde(default)]
    pub fix:       Option<String>,
    /// Supply-chain policy block — rule applies to lockfile dependencies
    /// rather than source code. Mutually exclusive with regex / query.
    #[serde(default)]
    pub dependency: Option<DependencyPolicy>,
    #[serde(default)]
    pub cwe:       Vec<String>,
    /// Frameworks this rule applies to (e.g., ["django", "flask"]).
    /// Empty = all frameworks. Used for filtering and reporting.
    #[serde(default)]
    pub frameworks: Vec<String>,
    /// Source attribution (e.g., "semgrep/rule-id", "peridex/auto").
    #[serde(default)]
    pub source:    Option<String>,
    /// CIA triad impact classification. Rules without explicit `cia:` get
    /// auto-classified by the heuristic in `cia_auto_classify()`.
    #[serde(default)]
    pub cia:       Option<CiaTriad>,
    /// Inter-procedural dataflow gate (Gap A4). When set, the matcher
    /// consults `ProjectSemantics::is_reachable_from_source` for the
    /// function enclosing each match and either suppresses or tags the
    /// finding accordingly.
    #[serde(default)]
    pub dataflow:  Option<DataflowSpec>,
}

/// Nested-pattern spec used by `metavariable_pattern_ast`. Mirrors
/// Semgrep's `metavariable-pattern` shape: an inner pattern (regex or
/// AST query) optionally re-parsed in a different language.
///
///   pattern  — inner Semgrep-style pattern (lowered to regex by our
///              regex matcher; passed as a tree-sitter query string
///              when `language` resolves to a tier-1 grammar).
///   regex    — explicit regex; takes precedence over `pattern`.
///   language — language to re-parse the captured text as. Required
///              for cross-language nesting (`<script>` JS-in-HTML);
///              optional otherwise (defaults to the host rule's
///              language).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NestedPatternSpec {
    #[serde(default)]
    pub pattern:  Option<String>,
    #[serde(default)]
    pub regex:    Option<String>,
    #[serde(default)]
    pub language: Option<Lang>,
}

/// Dataflow gating block on a rule.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct DataflowSpec {
    /// When true, the rule only fires if at least one tainted source
    /// reaches the matched function via cross-file propagation.
    /// Default false — rule still fires, but findings get
    /// `evidence.dataflow_reachable: false` so reviewers can sort.
    #[serde(default)]
    pub require_reachable: bool,
}

impl Rule {
    /// Returns the CIA impact for this rule — explicit if set, otherwise
    /// auto-classified from the rule's CWE, title, and category.
    pub fn cia_impact(&self) -> CiaTriad {
        if let Some(ref cia) = self.cia {
            return cia.clone();
        }
        cia_auto_classify(self)
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            bail!("rule has empty id");
        }
        let is_policy = self.dependency.is_some();
        if is_policy {
            if self.query.is_some() || self.regex.is_some() {
                bail!("rule {}: dependency rule cannot also declare query/regex", self.id);
            }
            return Ok(());
        }
        if self.languages.is_empty() {
            bail!("rule {}: no languages declared", self.id);
        }
        if self.query.is_none() && self.regex.is_none() && self.pattern.is_none() {
            bail!("rule {}: neither query, regex, nor pattern set", self.id);
        }
        Ok(())
    }
}

/// Heuristic CIA classification based on CWE, rule ID, and title.
fn cia_auto_classify(rule: &Rule) -> CiaTriad {
    let id = rule.id.to_uppercase();
    let title = rule.title.to_lowercase();
    let cwes: Vec<&str> = rule.cwe.iter().map(|s| s.as_str()).collect();

    // Secret / credential rules → C:high, I:medium, A:low
    if id.contains("SEC-") || id.contains("SECRET") || id.contains("CREDENTIAL")
        || id.contains("PASSWORD") || id.contains("TOKEN") || id.contains("API-KEY")
        || cwes.contains(&"CWE-798") || cwes.contains(&"CWE-312")
    {
        return CiaTriad {
            confidentiality: CiaImpact::High,
            integrity: CiaImpact::Medium,
            availability: CiaImpact::Low,
        };
    }

    // Encryption rules → C:high, I:low, A:low
    if title.contains("encrypt") || title.contains("tls") || title.contains("ssl")
        || cwes.contains(&"CWE-311") || cwes.contains(&"CWE-326") || cwes.contains(&"CWE-319")
    {
        return CiaTriad {
            confidentiality: CiaImpact::High,
            integrity: CiaImpact::Low,
            availability: CiaImpact::Low,
        };
    }

    // Injection / RCE rules → C:high, I:high, A:high
    if title.contains("injection") || title.contains("rce") || title.contains("command")
        || title.contains("deserialization") || title.contains("code execution")
        || cwes.contains(&"CWE-78") || cwes.contains(&"CWE-79") || cwes.contains(&"CWE-89")
        || cwes.contains(&"CWE-94") || cwes.contains(&"CWE-502")
    {
        return CiaTriad {
            confidentiality: CiaImpact::High,
            integrity: CiaImpact::High,
            availability: CiaImpact::High,
        };
    }

    // Access control / RBAC / privilege rules → C:high, I:high, A:medium
    if title.contains("privilege") || title.contains("rbac") || title.contains("wildcard")
        || title.contains("root") || title.contains("admin") || title.contains("permission")
        || cwes.contains(&"CWE-269") || cwes.contains(&"CWE-250") || cwes.contains(&"CWE-732")
        || cwes.contains(&"CWE-284")
    {
        return CiaTriad {
            confidentiality: CiaImpact::High,
            integrity: CiaImpact::High,
            availability: CiaImpact::Medium,
        };
    }

    // Public access / exposure rules → C:high, I:medium, A:low
    if title.contains("public") || title.contains("exposed") || title.contains("open to")
        || title.contains("0.0.0.0") || title.contains("ingress")
    {
        return CiaTriad {
            confidentiality: CiaImpact::High,
            integrity: CiaImpact::Medium,
            availability: CiaImpact::Low,
        };
    }

    // Backup / availability rules → C:low, I:low, A:high
    if title.contains("backup") || title.contains("redundan") || title.contains("health check")
        || title.contains("rate limit") || title.contains("dos") || title.contains("timeout")
        || cwes.contains(&"CWE-693") || cwes.contains(&"CWE-770")
    {
        return CiaTriad {
            confidentiality: CiaImpact::Low,
            integrity: CiaImpact::Low,
            availability: CiaImpact::High,
        };
    }

    // Logging / audit rules → C:medium, I:medium, A:low
    if title.contains("logging") || title.contains("audit") || title.contains("monitor")
        || cwes.contains(&"CWE-778")
    {
        return CiaTriad {
            confidentiality: CiaImpact::Medium,
            integrity: CiaImpact::Medium,
            availability: CiaImpact::Low,
        };
    }

    // Integrity-focused (signing, hashing, verification)
    if title.contains("sign") || title.contains("hash") || title.contains("verif")
        || title.contains("integrity") || title.contains("tampering")
        || cwes.contains(&"CWE-354") || cwes.contains(&"CWE-345")
    {
        return CiaTriad {
            confidentiality: CiaImpact::Low,
            integrity: CiaImpact::High,
            availability: CiaImpact::Low,
        };
    }

    // License compliance → C:none, I:none, A:none (legal, not security)
    if id.contains("LIC-") {
        return CiaTriad {
            confidentiality: CiaImpact::None,
            integrity: CiaImpact::None,
            availability: CiaImpact::None,
        };
    }

    // Default: medium across the board
    CiaTriad {
        confidentiality: CiaImpact::Medium,
        integrity: CiaImpact::Medium,
        availability: CiaImpact::Low,
    }
}

#[derive(Debug, Default)]
pub struct RulePack {
    rules: Vec<Rule>,
}

impl RulePack {
    pub fn rules(&self) -> &[Rule] { &self.rules }

    /// Return a new RulePack containing only rules for the given languages.
    pub fn filter_languages(&self, langs: &[&str]) -> Self {
        let rules = self.rules.iter()
            .filter(|r| {
                r.languages.iter().any(|l| langs.contains(&l.as_str()))
            })
            .cloned()
            .collect();
        Self { rules }
    }

    /// Parse every `.yml` / `.yaml` file under `dir` as a rule.
    pub fn load_dir(dir: &Path) -> Result<Self> {
        if !dir.exists() {
            bail!("rules path does not exist: {}", dir.display());
        }

        let mut rules = Vec::new();
        for entry in walkdir(dir)? {
            let path = entry;
            let Some(ext) = path.extension().and_then(|s| s.to_str()) else { continue };
            if ext != "yml" && ext != "yaml" { continue; }

            let raw = fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let rule: Rule = serde_yaml::from_str(&raw)
                .with_context(|| format!("parsing {}", path.display()))?;
            rule.validate()
                .with_context(|| format!("validating {}", path.display()))?;
            rules.push(rule);
        }

        log::info!("loaded {} rule(s) from {}", rules.len(), dir.display());
        Ok(Self { rules })
    }
}

/// Minimal recursive directory walk. We deliberately don't use `walkdir`
/// as a dep here — rule packs are small and flat, and keeping an extra
/// crate out pays off in binary size.
fn walkdir(dir: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        for entry in fs::read_dir(&cur).with_context(|| format!("reading {}", cur.display()))? {
            let entry = entry?;
            let ft = entry.file_type()?;
            let path = entry.path();
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                out.push(path);
            }
        }
    }
    Ok(out)
}
