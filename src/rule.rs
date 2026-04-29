//! Rule pack — loading, validation, and the rule shape callers match against.

use std::{fs, path::Path};

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
