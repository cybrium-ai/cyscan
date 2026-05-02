use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::finding::{Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
#[clap(rename_all = "snake_case")]
pub enum TriageStatus {
    New,
    Confirmed,
    FalsePositive,
    AcceptedRisk,
    Fixed,
}

impl TriageStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Confirmed => "confirmed",
            Self::FalsePositive => "false_positive",
            Self::AcceptedRisk => "accepted_risk",
            Self::Fixed => "fixed",
        }
    }

    pub fn hides_by_default(self) -> bool {
        matches!(self, Self::FalsePositive | Self::AcceptedRisk | Self::Fixed)
    }

    pub fn blocks_fail_on(self) -> bool {
        matches!(self, Self::FalsePositive | Self::AcceptedRisk | Self::Fixed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageEvent {
    pub status: TriageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageEntry {
    pub fingerprint: String,
    pub status: TriageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<TriageEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageStore {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub entries: BTreeMap<String, TriageEntry>,
}

impl Default for TriageStore {
    fn default() -> Self {
        Self {
            version: default_version(),
            entries: BTreeMap::new(),
        }
    }
}

fn default_version() -> u32 {
    1
}

fn now_string() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs.to_string()
}

#[derive(Debug, Clone, Default)]
pub struct TriageSetOptions {
    pub note: Option<String>,
    pub author: Option<String>,
    pub rule_id: Option<String>,
    pub file: Option<String>,
    pub title: Option<String>,
    pub severity: Option<Severity>,
}

impl TriageStore {
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                version: default_version(),
                entries: BTreeMap::new(),
            });
        }
        let body = fs::read_to_string(path)
            .with_context(|| format!("reading triage store {}", path.display()))?;
        let mut store: Self = serde_json::from_str(&body)
            .with_context(|| format!("parsing triage store {}", path.display()))?;
        if store.version == 0 {
            store.version = default_version();
        }
        Ok(store)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json).with_context(|| format!("writing triage store {}", path.display()))
    }

    pub fn set(
        &mut self,
        fingerprint: String,
        status: TriageStatus,
        opts: TriageSetOptions,
    ) -> &TriageEntry {
        let timestamp = now_string();
        let event = TriageEvent {
            status,
            note: opts.note.clone(),
            author: opts.author.clone(),
            timestamp: timestamp.clone(),
        };
        let entry = self.entries.entry(fingerprint.clone()).or_insert(TriageEntry {
            fingerprint,
            status,
            note: opts.note.clone(),
            author: opts.author.clone(),
            updated_at: timestamp.clone(),
            rule_id: opts.rule_id.clone(),
            file: opts.file.clone(),
            title: opts.title.clone(),
            severity: opts.severity,
            history: Vec::new(),
        });

        entry.status = status;
        entry.note = opts.note.or_else(|| entry.note.clone());
        entry.author = opts.author.or_else(|| entry.author.clone());
        entry.updated_at = timestamp;
        if opts.rule_id.is_some() {
            entry.rule_id = opts.rule_id;
        }
        if opts.file.is_some() {
            entry.file = opts.file;
        }
        if opts.title.is_some() {
            entry.title = opts.title;
        }
        if opts.severity.is_some() {
            entry.severity = opts.severity;
        }
        entry.history.push(event);
        entry
    }
}

pub fn overlay_and_filter(
    findings: &mut Vec<Finding>,
    store: &TriageStore,
    hide_triaged: bool,
) -> usize {
    for finding in findings.iter_mut() {
        if let Some(entry) = store.entries.get(&finding.fingerprint) {
            finding.evidence.insert(
                "triage_status".into(),
                serde_json::json!(entry.status.as_str()),
            );
            finding
                .evidence
                .insert("triage_updated_at".into(), serde_json::json!(entry.updated_at));
            if let Some(note) = &entry.note {
                finding
                    .evidence
                    .insert("triage_note".into(), serde_json::json!(note));
            }
            if let Some(author) = &entry.author {
                finding
                    .evidence
                    .insert("triage_author".into(), serde_json::json!(author));
            }
            finding.evidence.insert(
                "triage_history_len".into(),
                serde_json::json!(entry.history.len()),
            );
        }
    }

    if !hide_triaged {
        return 0;
    }

    let before = findings.len();
    findings.retain(|finding| {
        !triage_status_for_finding(finding, store).is_some_and(TriageStatus::hides_by_default)
    });
    before - findings.len()
}

pub fn triage_status_for_finding(finding: &Finding, store: &TriageStore) -> Option<TriageStatus> {
    store.entries.get(&finding.fingerprint).map(|entry| entry.status)
}

pub fn is_actionable_for_fail_on(finding: &Finding, store: Option<&TriageStore>) -> bool {
    !store
        .and_then(|s| triage_status_for_finding(finding, s))
        .is_some_and(TriageStatus::blocks_fail_on)
}
