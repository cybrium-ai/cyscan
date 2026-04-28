//! Finding + Severity types. Shared between the matcher and the output
//! layer; structured once so we serialise to JSON / SARIF without
//! reshaping.

use std::{cmp::Ordering, collections::HashMap, fmt, path::PathBuf, str::FromStr};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    const fn rank(self) -> u8 {
        match self {
            Self::Info     => 0,
            Self::Low      => 1,
            Self::Medium   => 2,
            Self::High     => 3,
            Self::Critical => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl Ord for Severity {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}
impl PartialOrd for Severity {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info"     => Ok(Self::Info),
            "low"      => Ok(Self::Low),
            "medium"   => Ok(Self::Medium),
            "high"     => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other      => Err(format!("unknown severity: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id:    String,
    pub title:      String,
    pub severity:   Severity,
    pub message:    String,
    pub file:       PathBuf,
    pub line:       usize,
    pub column:     usize,
    pub end_line:   usize,
    pub end_column: usize,
    /// Byte offsets into the scanned file — used by `cyscan fix` to splice
    /// replacement text precisely. Not serialised (internal use only).
    #[serde(skip)]
    pub start_byte: usize,
    #[serde(skip)]
    pub end_byte:   usize,
    pub snippet:    String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_recipe: Option<String>,
    /// Literal replacement text carried over from the rule. Skipped from
    /// JSON/SARIF — the `fix` subcommand consumes it directly.
    #[serde(skip)]
    pub fix:        Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cwe:        Vec<String>,
    /// Evidence metadata — package info, reachability, vulnerable symbols.
    #[serde(default, skip_serializing_if = "evidence_empty")]
    pub evidence:   HashMap<String, serde_json::Value>,
    /// Reachability verdict: reachable / unreachable / unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachability: Option<String>,
}

fn evidence_empty(m: &HashMap<String, serde_json::Value>) -> bool { m.is_empty() }

impl Finding {
    /// Create a Finding with only the required fields, defaulting evidence + reachability.
    pub fn defaults() -> (HashMap<String, serde_json::Value>, Option<String>) {
        (HashMap::new(), None)
    }
}
