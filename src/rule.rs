//! Rule pack — loading, validation, and the rule shape callers match against.

use std::{fs, path::Path};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{finding::Severity, lang::Lang, supply::policy::DependencyPolicy};

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
}

impl Rule {
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

#[derive(Debug, Default)]
pub struct RulePack {
    rules: Vec<Rule>,
}

impl RulePack {
    pub fn rules(&self) -> &[Rule] { &self.rules }

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
