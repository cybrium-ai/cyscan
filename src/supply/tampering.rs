//! Lockfile tampering detection.
//!
//! Two phases:
//!
//!   * **Offline** (always on) — internal-consistency checks the lockfile
//!     supports without network access. Catches:
//!       - missing integrity for an ecosystem that ships one (downgrade
//!         attack signature),
//!       - malformed integrity (wrong length / illegal characters),
//!       - conflicting integrity for the same `(name, version)` pair
//!         across the project (lockfile-injection signature),
//!       - weak-hash usage (sha1 / unknown algos).
//!
//!   * **Online** (opt-in via `--verify-integrity`) — fetch the upstream
//!     registry's published checksum and compare against the declared
//!     one. The actual tampering signal: the lockfile claims one hash,
//!     the registry has another. Lives in `tampering::online`.
//!
//! Findings flow through the same SARIF + finding pipeline as advisory
//! / typosquat / license findings — `cyscan supply` runs them all and
//! emits one result.
//!
//! See sprint-49 for the design doc.
//!
//! Finding IDs:
//!   CYSCAN-TAMPER-001 — Missing integrity
//!   CYSCAN-TAMPER-002 — Malformed integrity
//!   CYSCAN-TAMPER-003 — Conflicting integrity
//!   CYSCAN-TAMPER-004 — Weak hash
//!   CYSCAN-TAMPER-005 — Registry mismatch (online)
//!   CYSCAN-TAMPER-006 — Registry unavailable (online, info-level)

use std::collections::HashMap;

use crate::{
    finding::{Finding, Severity},
    supply::lockfile::{Checksum, ChecksumAlgo, Dependency, Ecosystem},
};

/// Offline-only tampering checks. Emit findings for missing,
/// malformed, conflicting, or weak-hash integrity entries. No
/// network access — runs unconditionally as part of every
/// `cyscan supply`.
pub fn scan_offline(deps: &[Dependency]) -> Vec<Finding> {
    let mut out = Vec::new();

    // Pass 1 — per-dep checks (missing / malformed / weak).
    for dep in deps {
        match dep.declared_checksum.as_ref() {
            None => {
                if expects_integrity(dep.ecosystem) {
                    out.push(missing_integrity_finding(dep));
                }
            }
            Some(checksum) => {
                if let Some(reason) = malformed_reason(checksum) {
                    out.push(malformed_integrity_finding(dep, checksum, &reason));
                }
                if is_weak(checksum) {
                    out.push(weak_hash_finding(dep, checksum));
                }
            }
        }
    }

    // Pass 2 — conflicting integrity across the project. Group by
    // (ecosystem, name, version), and if two or more entries declare
    // different checksums, flag every entry in the conflicting group.
    let mut by_pkg: HashMap<(Ecosystem, String, String), Vec<&Dependency>> = HashMap::new();
    for dep in deps {
        if dep.declared_checksum.is_none() { continue; }
        by_pkg
            .entry((dep.ecosystem, dep.name.clone(), dep.version.clone()))
            .or_default()
            .push(dep);
    }
    for ((eco, name, version), group) in by_pkg {
        // Collect distinct checksums in this group.
        let mut distinct: Vec<&Checksum> = Vec::new();
        for d in &group {
            let c = d.declared_checksum.as_ref().unwrap();
            if !distinct.iter().any(|x| *x == c) {
                distinct.push(c);
            }
        }
        if distinct.len() > 1 {
            for d in &group {
                out.push(conflicting_integrity_finding(
                    d, eco, &name, &version, &distinct,
                ));
            }
        }
    }

    out
}

// ── Per-ecosystem expectations ───────────────────────────────────────

/// True when the ecosystem's lockfile format normally carries an
/// integrity field — used to decide whether a missing checksum is
/// suspicious. Cargo, npm, Yarn, Go, Composer all ship integrity by
/// default; PyPI requirements/poetry/Pipfile only when the user opts
/// in (so a missing one isn't suspicious for plain `requirements.txt`).
fn expects_integrity(eco: Ecosystem) -> bool {
    matches!(eco, Ecosystem::Crates | Ecosystem::Npm | Ecosystem::Go | Ecosystem::Composer)
}

// ── Validation helpers ──────────────────────────────────────────────

fn malformed_reason(c: &Checksum) -> Option<String> {
    if c.value.is_empty() {
        return Some("empty checksum value".into());
    }
    if let Some(expected_len) = c.algo.expected_len() {
        if c.value.len() != expected_len {
            return Some(format!(
                "{} value length {} does not match expected {}",
                c.algo.as_str(), c.value.len(), expected_len,
            ));
        }
    }
    // Algorithm-specific character validation.
    match c.algo {
        ChecksumAlgo::Sha256 | ChecksumAlgo::Sha1 => {
            // Hex.
            if !c.value.chars().all(|x| x.is_ascii_hexdigit()) {
                return Some(format!("{} value contains non-hex characters", c.algo.as_str()));
            }
        }
        ChecksumAlgo::Sha512 | ChecksumAlgo::GoH1 => {
            // Standard base64 with optional `=` padding.
            if !c.value.chars().all(is_base64_char) {
                return Some(format!("{} value contains non-base64 characters", c.algo.as_str()));
            }
        }
        ChecksumAlgo::Other(_) => {} // can't validate unknown algos
    }
    None
}

fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
}

fn is_weak(c: &Checksum) -> bool {
    matches!(c.algo, ChecksumAlgo::Sha1)
        || matches!(&c.algo, ChecksumAlgo::Other(s) if s == "md5")
}

// ── Finding builders ────────────────────────────────────────────────

fn missing_integrity_finding(dep: &Dependency) -> Finding {
    Finding {
        rule_id:    "CYSCAN-TAMPER-001".to_string(),
        title:      format!("Missing integrity hash for {}@{}", dep.name, dep.version),
        severity:   Severity::Medium,
        message:    format!(
            "Dependency `{}@{}` ({}) has no integrity checksum in the lockfile. \
             Most ecosystems publish one by default; a missing entry is a downgrade-attack \
             signature where the lockfile was edited to remove verification.",
            dep.name, dep.version, dep.ecosystem.as_str(),
        ),
        file:       dep.lockfile.clone(),
        line: 0, column: 0, end_line: 0, end_column: 0,
        start_byte: 0, end_byte: 0,
        snippet:    format!("{}@{}", dep.name, dep.version),
        fix_recipe: None,
        fix:        None,
        cwe:        vec!["CWE-494".to_string()],
        evidence:   evidence_for_dep(dep, None),
        reachability: None,
        fingerprint: String::new(),
    }
}

fn malformed_integrity_finding(dep: &Dependency, c: &Checksum, reason: &str) -> Finding {
    Finding {
        rule_id:    "CYSCAN-TAMPER-002".to_string(),
        title:      format!("Malformed integrity hash for {}@{}", dep.name, dep.version),
        severity:   Severity::High,
        message:    format!(
            "Dependency `{}@{}` ({}) has a malformed integrity hash: {}. \
             A lockfile entry that fails to parse cleanly indicates manual editing.",
            dep.name, dep.version, dep.ecosystem.as_str(), reason,
        ),
        file:       dep.lockfile.clone(),
        line: 0, column: 0, end_line: 0, end_column: 0,
        start_byte: 0, end_byte: 0,
        snippet:    format!("{}@{} {}-{}", dep.name, dep.version, c.algo.as_str(), c.value),
        fix_recipe: None,
        fix:        None,
        cwe:        vec!["CWE-345".to_string()],
        evidence:   evidence_for_dep(dep, Some(c)),
        reachability: None,
        fingerprint: String::new(),
    }
}

fn conflicting_integrity_finding(
    dep: &Dependency,
    eco: Ecosystem,
    name: &str,
    version: &str,
    distinct: &[&Checksum],
) -> Finding {
    let summary: Vec<String> = distinct.iter()
        .map(|c| format!("{}-{}", c.algo.as_str(), c.value))
        .collect();
    let mut evidence = evidence_for_dep(dep, dep.declared_checksum.as_ref());
    evidence.insert(
        "conflicting_checksums".to_string(),
        serde_json::json!(summary),
    );
    Finding {
        rule_id:    "CYSCAN-TAMPER-003".to_string(),
        title:      format!("Conflicting integrity for {}@{} across the tree", name, version),
        severity:   Severity::High,
        message:    format!(
            "Dependency `{}@{}` ({}) appears with {} different integrity values across the \
             project. Same package + version should resolve to the same artefact bytes; \
             divergence is a lockfile-injection signature.",
            name, version, eco.as_str(), distinct.len(),
        ),
        file:       dep.lockfile.clone(),
        line: 0, column: 0, end_line: 0, end_column: 0,
        start_byte: 0, end_byte: 0,
        snippet:    format!("{}@{}", name, version),
        fix_recipe: None,
        fix:        None,
        cwe:        vec!["CWE-345".to_string()],
        evidence,
        reachability: None,
        fingerprint: String::new(),
    }
}

fn weak_hash_finding(dep: &Dependency, c: &Checksum) -> Finding {
    Finding {
        rule_id:    "CYSCAN-TAMPER-004".to_string(),
        title:      format!("Weak integrity hash ({}) for {}@{}", c.algo.as_str(), dep.name, dep.version),
        severity:   Severity::Low,
        message:    format!(
            "Dependency `{}@{}` ({}) uses {} for integrity verification. \
             SHA-1 has been considered cryptographically weak since 2017; \
             stronger algorithms (sha256 / sha512) should be preferred.",
            dep.name, dep.version, dep.ecosystem.as_str(), c.algo.as_str(),
        ),
        file:       dep.lockfile.clone(),
        line: 0, column: 0, end_line: 0, end_column: 0,
        start_byte: 0, end_byte: 0,
        snippet:    format!("{}@{} ({})", dep.name, dep.version, c.algo.as_str()),
        fix_recipe: None,
        fix:        None,
        cwe:        vec!["CWE-328".to_string()],
        evidence:   evidence_for_dep(dep, Some(c)),
        reachability: None,
        fingerprint: String::new(),
    }
}

fn evidence_for_dep(dep: &Dependency, c: Option<&Checksum>) -> HashMap<String, serde_json::Value> {
    let mut e = HashMap::new();
    e.insert("ecosystem".into(), serde_json::json!(dep.ecosystem.as_str()));
    e.insert("name".into(),      serde_json::json!(dep.name));
    e.insert("version".into(),   serde_json::json!(dep.version));
    if let Some(c) = c {
        e.insert("checksum_algo".into(),  serde_json::json!(c.algo.as_str()));
        e.insert("checksum_value".into(), serde_json::json!(c.value));
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dep(eco: Ecosystem, name: &str, ver: &str, checksum: Option<Checksum>) -> Dependency {
        Dependency {
            ecosystem: eco,
            name:      name.to_string(),
            version:   ver.to_string(),
            lockfile:  PathBuf::from("/tmp/lock"),
            license:   None,
            path:      Vec::new(),
            declared_checksum: checksum,
        }
    }

    #[test]
    fn missing_integrity_fires_for_npm_but_not_pypi() {
        let deps = vec![
            dep(Ecosystem::Npm,  "no-integrity-pkg",   "1.0.0", None),
            dep(Ecosystem::Pypi, "missing-is-fine",    "1.0.0", None),
        ];
        let findings = scan_offline(&deps);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "CYSCAN-TAMPER-001");
        assert!(findings[0].message.contains("no-integrity-pkg"));
    }

    #[test]
    fn malformed_integrity_fires_on_wrong_length() {
        let deps = vec![dep(
            Ecosystem::Crates,
            "bad-len-crate",
            "1.0.0",
            Some(Checksum {
                algo:  ChecksumAlgo::Sha256,
                value: "deadbeef".to_string(), // 8 chars, expected 64
            }),
        )];
        let findings = scan_offline(&deps);
        assert!(findings.iter().any(|f| f.rule_id == "CYSCAN-TAMPER-002"
            && f.message.contains("length 8")));
    }

    #[test]
    fn conflicting_integrity_fires_when_same_pkg_has_two_hashes() {
        let deps = vec![
            dep(Ecosystem::Npm, "qs", "6.5.2", Some(Checksum {
                algo: ChecksumAlgo::Sha512,
                value: "A".repeat(88),
            })),
            dep(Ecosystem::Npm, "qs", "6.5.2", Some(Checksum {
                algo: ChecksumAlgo::Sha512,
                value: "B".repeat(88),
            })),
        ];
        let findings = scan_offline(&deps);
        let conflicts: Vec<_> = findings.iter()
            .filter(|f| f.rule_id == "CYSCAN-TAMPER-003")
            .collect();
        // Both lockfile entries get flagged so reviewers see them
        // wherever they appear in the tree.
        assert_eq!(conflicts.len(), 2);
        for f in conflicts {
            assert!(f.evidence.get("conflicting_checksums").is_some());
        }
    }

    #[test]
    fn conflicting_integrity_does_not_fire_on_consistent_dupes() {
        let deps = vec![
            dep(Ecosystem::Npm, "qs", "6.5.2", Some(Checksum {
                algo: ChecksumAlgo::Sha512, value: "A".repeat(88),
            })),
            dep(Ecosystem::Npm, "qs", "6.5.2", Some(Checksum {
                algo: ChecksumAlgo::Sha512, value: "A".repeat(88),
            })),
        ];
        let findings = scan_offline(&deps);
        assert!(!findings.iter().any(|f| f.rule_id == "CYSCAN-TAMPER-003"));
    }

    #[test]
    fn weak_hash_fires_for_sha1() {
        let deps = vec![dep(
            Ecosystem::Composer,
            "old-pkg",
            "1.0.0",
            Some(Checksum {
                algo:  ChecksumAlgo::Sha1,
                value: "0123456789abcdef0123456789abcdef01234567".to_string(),
            }),
        )];
        let findings = scan_offline(&deps);
        assert!(findings.iter().any(|f| f.rule_id == "CYSCAN-TAMPER-004"));
    }

    #[test]
    fn well_formed_sha512_passes_clean() {
        let deps = vec![dep(
            Ecosystem::Npm,
            "good-pkg",
            "1.0.0",
            Some(Checksum {
                algo:  ChecksumAlgo::Sha512,
                value: "A".repeat(88),
            }),
        )];
        let findings = scan_offline(&deps);
        assert_eq!(findings.len(), 0);
    }
}
