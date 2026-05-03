//! Online tampering verification — fetch each dependency's published
//! checksum from its upstream registry and compare against the
//! lockfile's declared value. Mismatch = the actual tampering signal.
//!
//! Opt-in via `cyscan supply --verify-integrity`. Off by default for
//! CI friendliness (no network calls when the user hasn't asked).
//!
//! Behaviour on transient failure (timeout, 5xx, DNS): log the dep
//! under CYSCAN-TAMPER-006 (info-level) and skip — never fail the
//! whole scan because a registry was briefly unavailable.

use std::{collections::HashMap, time::Duration};

use crate::{
    finding::{Finding, Severity},
    supply::lockfile::{Checksum, ChecksumAlgo, Dependency, Ecosystem},
};

/// Knobs for the online scan.
#[derive(Debug, Clone)]
pub struct OnlineOpts {
    pub request_timeout: Duration,
    pub max_concurrent:  usize,
}

impl Default for OnlineOpts {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(8),
            max_concurrent:  8,
        }
    }
}

/// What a registry call returned. Decoupled from the network so tests
/// can drive the comparator with hand-supplied data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryLookup {
    Found(Checksum),
    NotFound,
    Unreachable(String),
    /// Private / non-public registry — we don't have credentials and
    /// shouldn't pretend to verify what we can't reach. No finding
    /// emitted.
    SkippedPrivate,
}

/// Trait for per-ecosystem registry clients. The default impl uses
/// reqwest::blocking; tests override with a fake.
pub trait RegistryClient: Sync {
    fn lookup(&self, dep: &Dependency, opts: &OnlineOpts) -> RegistryLookup;
}

/// Compare each dep's declared checksum against what the registry
/// reports. Pure — does no network. Tests inject the lookups they
/// want via `lookups` parameter; the real CLI path lives in
/// `scan_with_client`.
pub fn compare(deps: &[Dependency], lookups: &[RegistryLookup]) -> Vec<Finding> {
    assert_eq!(deps.len(), lookups.len(),
        "compare requires one lookup per dep");
    let mut out = Vec::new();
    for (dep, lookup) in deps.iter().zip(lookups.iter()) {
        let Some(declared) = dep.declared_checksum.as_ref() else { continue };
        match lookup {
            RegistryLookup::Found(upstream) => {
                if !same_checksum(declared, upstream) {
                    out.push(registry_mismatch_finding(dep, declared, upstream));
                }
            }
            RegistryLookup::NotFound => {
                // Registry doesn't have the version we're asking about
                // — could be a yanked release or a typo. Treat as info,
                // not a tampering signal.
                out.push(registry_unavailable_finding(dep, "registry returned 404"));
            }
            RegistryLookup::Unreachable(why) => {
                out.push(registry_unavailable_finding(dep, why));
            }
            RegistryLookup::SkippedPrivate => {
                // Silent — private registries are expected.
            }
        }
    }
    out
}

/// Two checksums agree when their algorithm matches and their value
/// matches case-insensitively (Cargo lowercases hex, npm preserves
/// case for base64). For sha512/h1 we also normalise base64 padding
/// so a `=`-stripped registry response equals a padded lockfile entry.
fn same_checksum(a: &Checksum, b: &Checksum) -> bool {
    if a.algo != b.algo { return false; }
    let av = normalize_b64_padding(&a.value);
    let bv = normalize_b64_padding(&b.value);
    match a.algo {
        ChecksumAlgo::Sha256 | ChecksumAlgo::Sha1 => av.eq_ignore_ascii_case(&bv),
        _ => av == bv,
    }
}

fn normalize_b64_padding(v: &str) -> String {
    v.trim_end_matches('=').to_string()
}

// ── Finding builders ────────────────────────────────────────────────

fn registry_mismatch_finding(dep: &Dependency, declared: &Checksum, upstream: &Checksum) -> Finding {
    let mut evidence: HashMap<String, serde_json::Value> = HashMap::new();
    evidence.insert("ecosystem".into(),         serde_json::json!(dep.ecosystem.as_str()));
    evidence.insert("name".into(),              serde_json::json!(dep.name));
    evidence.insert("version".into(),           serde_json::json!(dep.version));
    evidence.insert("declared_algo".into(),     serde_json::json!(declared.algo.as_str()));
    evidence.insert("declared_value".into(),    serde_json::json!(declared.value));
    evidence.insert("upstream_algo".into(),     serde_json::json!(upstream.algo.as_str()));
    evidence.insert("upstream_value".into(),    serde_json::json!(upstream.value));

    Finding {
        rule_id:    "CYSCAN-TAMPER-005".to_string(),
        title:      format!("Registry mismatch for {}@{}", dep.name, dep.version),
        severity:   Severity::Critical,
        message:    format!(
            "Lockfile declares {}-{} for `{}@{}` ({}), but the upstream registry \
             publishes {}-{}. The lockfile and registry disagree about the \
             artefact bytes — strong tampering signal.",
            declared.algo.as_str(), declared.value,
            dep.name, dep.version, dep.ecosystem.as_str(),
            upstream.algo.as_str(), upstream.value,
        ),
        file:       dep.lockfile.clone(),
        line: 0, column: 0, end_line: 0, end_column: 0,
        start_byte: 0, end_byte: 0,
        snippet:    format!("{}@{}", dep.name, dep.version),
        fix_recipe: None,
        fix:        None,
        cwe:        vec!["CWE-345".to_string(), "CWE-494".to_string()],
        evidence,
        reachability: None,
        fingerprint: String::new(),
    }
}

fn registry_unavailable_finding(dep: &Dependency, reason: &str) -> Finding {
    let mut evidence: HashMap<String, serde_json::Value> = HashMap::new();
    evidence.insert("ecosystem".into(), serde_json::json!(dep.ecosystem.as_str()));
    evidence.insert("name".into(),      serde_json::json!(dep.name));
    evidence.insert("version".into(),   serde_json::json!(dep.version));
    evidence.insert("reason".into(),    serde_json::json!(reason));

    Finding {
        rule_id:    "CYSCAN-TAMPER-006".to_string(),
        title:      format!("Registry unavailable while verifying {}@{}", dep.name, dep.version),
        severity:   Severity::Info,
        message:    format!(
            "Could not reach the upstream registry to verify `{}@{}` ({}): {}. \
             The integrity of this dependency was NOT confirmed by this scan.",
            dep.name, dep.version, dep.ecosystem.as_str(), reason,
        ),
        file:       dep.lockfile.clone(),
        line: 0, column: 0, end_line: 0, end_column: 0,
        start_byte: 0, end_byte: 0,
        snippet:    format!("{}@{}", dep.name, dep.version),
        fix_recipe: None,
        fix:        None,
        cwe:        vec![],
        evidence,
        reachability: None,
        fingerprint: String::new(),
    }
}

// ── Default registry client (HTTP-backed) ───────────────────────────

pub struct HttpRegistryClient;

impl RegistryClient for HttpRegistryClient {
    fn lookup(&self, dep: &Dependency, opts: &OnlineOpts) -> RegistryLookup {
        match dep.ecosystem {
            Ecosystem::Npm      => lookup_npm(dep, opts),
            Ecosystem::Crates   => lookup_crates(dep, opts),
            Ecosystem::Pypi     => lookup_pypi(dep, opts),
            Ecosystem::Composer => lookup_composer(dep, opts),
            Ecosystem::Go       => lookup_go(dep, opts),
        }
    }
}

fn http_client(opts: &OnlineOpts) -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(opts.request_timeout)
        .user_agent("cyscan-supply-tampering")
        .build()
        .expect("reqwest client construction is infallible")
}

fn lookup_npm(dep: &Dependency, opts: &OnlineOpts) -> RegistryLookup {
    let url = format!("https://registry.npmjs.org/{}/{}", dep.name, dep.version);
    match http_client(opts).get(&url).send() {
        Err(e) => RegistryLookup::Unreachable(format!("npm: {e}")),
        Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => RegistryLookup::NotFound,
        Ok(r) if !r.status().is_success() => {
            RegistryLookup::Unreachable(format!("npm: HTTP {}", r.status()))
        }
        Ok(r) => match r.json::<serde_json::Value>() {
            Err(e) => RegistryLookup::Unreachable(format!("npm json: {e}")),
            Ok(v) => {
                let dist = v.get("dist");
                if let Some(integrity) = dist
                    .and_then(|d| d.get("integrity"))
                    .and_then(|x| x.as_str())
                {
                    if let Some(c) = crate::supply::lockfile::parse_npm_integrity_pub(integrity) {
                        return RegistryLookup::Found(c);
                    }
                }
                if let Some(shasum) = dist.and_then(|d| d.get("shasum")).and_then(|x| x.as_str()) {
                    return RegistryLookup::Found(Checksum {
                        algo:  ChecksumAlgo::Sha1,
                        value: shasum.to_string(),
                    });
                }
                RegistryLookup::Unreachable("npm: response missing dist.integrity/shasum".into())
            }
        }
    }
}

fn lookup_crates(dep: &Dependency, opts: &OnlineOpts) -> RegistryLookup {
    let url = format!("https://crates.io/api/v1/crates/{}/{}", dep.name, dep.version);
    match http_client(opts).get(&url).send() {
        Err(e) => RegistryLookup::Unreachable(format!("crates: {e}")),
        Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => RegistryLookup::NotFound,
        Ok(r) if !r.status().is_success() => {
            RegistryLookup::Unreachable(format!("crates: HTTP {}", r.status()))
        }
        Ok(r) => match r.json::<serde_json::Value>() {
            Err(e) => RegistryLookup::Unreachable(format!("crates json: {e}")),
            Ok(v) => {
                let checksum = v.get("version")
                    .and_then(|ver| ver.get("checksum"))
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string());
                match checksum {
                    Some(c) => RegistryLookup::Found(Checksum {
                        algo:  ChecksumAlgo::Sha256,
                        value: c,
                    }),
                    None => RegistryLookup::Unreachable("crates: response missing version.checksum".into()),
                }
            }
        }
    }
}

fn lookup_pypi(dep: &Dependency, opts: &OnlineOpts) -> RegistryLookup {
    let url = format!("https://pypi.org/pypi/{}/{}/json", dep.name, dep.version);
    match http_client(opts).get(&url).send() {
        Err(e) => RegistryLookup::Unreachable(format!("pypi: {e}")),
        Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => RegistryLookup::NotFound,
        Ok(r) if !r.status().is_success() => {
            RegistryLookup::Unreachable(format!("pypi: HTTP {}", r.status()))
        }
        Ok(r) => match r.json::<serde_json::Value>() {
            Err(e) => RegistryLookup::Unreachable(format!("pypi json: {e}")),
            Ok(v) => {
                // Prefer sdist (.tar.gz) digest; fall back to first artefact.
                let urls = v.get("urls").and_then(|u| u.as_array());
                let sha256 = urls.and_then(|arr| {
                    arr.iter().find(|u| {
                        u.get("packagetype").and_then(|x| x.as_str()) == Some("sdist")
                    }).or_else(|| arr.first())
                      .and_then(|u| u.get("digests"))
                      .and_then(|d| d.get("sha256"))
                      .and_then(|x| x.as_str())
                      .map(|s| s.to_string())
                });
                match sha256 {
                    Some(v) => RegistryLookup::Found(Checksum {
                        algo:  ChecksumAlgo::Sha256, value: v,
                    }),
                    None => RegistryLookup::Unreachable("pypi: response missing urls[].digests.sha256".into()),
                }
            }
        }
    }
}

fn lookup_composer(dep: &Dependency, opts: &OnlineOpts) -> RegistryLookup {
    // composer names are `vendor/name`; URL matches.
    let url = format!("https://repo.packagist.org/p2/{}.json", dep.name);
    match http_client(opts).get(&url).send() {
        Err(e) => RegistryLookup::Unreachable(format!("packagist: {e}")),
        Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => RegistryLookup::NotFound,
        Ok(r) if !r.status().is_success() => {
            RegistryLookup::Unreachable(format!("packagist: HTTP {}", r.status()))
        }
        Ok(r) => match r.json::<serde_json::Value>() {
            Err(e) => RegistryLookup::Unreachable(format!("packagist json: {e}")),
            Ok(v) => {
                // packages.<name> is an array of versions; find the
                // one matching dep.version.
                let entry = v.get("packages")
                    .and_then(|p| p.get(&dep.name))
                    .and_then(|x| x.as_array())
                    .and_then(|arr| arr.iter().find(|item| {
                        item.get("version").and_then(|x| x.as_str())
                            .map(|s| s.trim_start_matches('v') == dep.version)
                            .unwrap_or(false)
                    }));
                let shasum = entry
                    .and_then(|e| e.get("dist"))
                    .and_then(|d| d.get("shasum"))
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string());
                match shasum {
                    Some(v) => RegistryLookup::Found(Checksum { algo: ChecksumAlgo::Sha1, value: v }),
                    None => RegistryLookup::NotFound,
                }
            }
        }
    }
}

fn lookup_go(dep: &Dependency, opts: &OnlineOpts) -> RegistryLookup {
    // proxy.golang.org publishes `<module>/@v/<version>.ziphash` as
    // plain text containing the h1: hash that go.sum records.
    let url = format!("https://proxy.golang.org/{}/@v/{}.ziphash",
        urlencoding::encode(&dep.name), dep.version);
    match http_client(opts).get(&url).send() {
        Err(e) => RegistryLookup::Unreachable(format!("go proxy: {e}")),
        Ok(r) if r.status() == reqwest::StatusCode::NOT_FOUND => RegistryLookup::NotFound,
        Ok(r) if !r.status().is_success() => {
            RegistryLookup::Unreachable(format!("go proxy: HTTP {}", r.status()))
        }
        Ok(r) => match r.text() {
            Err(e) => RegistryLookup::Unreachable(format!("go proxy body: {e}")),
            Ok(body) => {
                let trimmed = body.trim();
                if let Some(rest) = trimmed.strip_prefix("h1:") {
                    RegistryLookup::Found(Checksum {
                        algo:  ChecksumAlgo::GoH1,
                        value: rest.to_string(),
                    })
                } else {
                    RegistryLookup::Unreachable("go proxy: response missing h1: prefix".into())
                }
            }
        }
    }
}

/// Production scan path — invokes the HTTP-backed client once per
/// dep, in parallel. Used by the CLI when `--verify-integrity` is set.
pub fn scan_with_client(
    deps: &[Dependency],
    client: &dyn RegistryClient,
    opts: &OnlineOpts,
) -> Vec<Finding> {
    use rayon::prelude::*;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(opts.max_concurrent.max(1))
        .build()
        .expect("rayon pool construction is infallible");
    let lookups: Vec<RegistryLookup> = pool.install(|| {
        deps.par_iter()
            .map(|d| if d.declared_checksum.is_some() {
                client.lookup(d, opts)
            } else {
                // No declared checksum to compare against — skip
                // silently. Missing-integrity is the offline scanner's
                // job (CYSCAN-TAMPER-001).
                RegistryLookup::SkippedPrivate
            })
            .collect()
    });
    compare(deps, &lookups)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dep(eco: Ecosystem, name: &str, ver: &str, c: Option<Checksum>) -> Dependency {
        Dependency {
            ecosystem: eco,
            name:      name.to_string(),
            version:   ver.to_string(),
            lockfile:  PathBuf::from("/tmp/lock"),
            license:   None,
            path:      Vec::new(),
            declared_checksum: c,
        }
    }

    fn cs(v: &str) -> Checksum {
        Checksum { algo: ChecksumAlgo::Sha512, value: v.to_string() }
    }

    #[test]
    fn matching_checksums_emit_no_finding() {
        let deps = vec![dep(Ecosystem::Npm, "ok", "1.0.0", Some(cs(&"A".repeat(88))))];
        let lookups = vec![RegistryLookup::Found(cs(&"A".repeat(88)))];
        let f = compare(&deps, &lookups);
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn mismatching_checksums_emit_005_critical() {
        let deps = vec![dep(Ecosystem::Npm, "tampered", "1.0.0", Some(cs(&"A".repeat(88))))];
        let lookups = vec![RegistryLookup::Found(cs(&"B".repeat(88)))];
        let f = compare(&deps, &lookups);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "CYSCAN-TAMPER-005");
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0].evidence.get("declared_value").is_some());
        assert!(f[0].evidence.get("upstream_value").is_some());
    }

    #[test]
    fn unreachable_emits_006_info() {
        let deps = vec![dep(Ecosystem::Npm, "offline", "1.0.0", Some(cs(&"A".repeat(88))))];
        let lookups = vec![RegistryLookup::Unreachable("DNS failed".to_string())];
        let f = compare(&deps, &lookups);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule_id, "CYSCAN-TAMPER-006");
        assert_eq!(f[0].severity, Severity::Info);
    }

    #[test]
    fn private_registry_silent() {
        let deps = vec![dep(Ecosystem::Npm, "private-pkg", "1.0.0", Some(cs(&"A".repeat(88))))];
        let lookups = vec![RegistryLookup::SkippedPrivate];
        let f = compare(&deps, &lookups);
        assert_eq!(f.len(), 0);
    }

    #[test]
    fn b64_padding_normalised_for_equality() {
        // Same value, one padded one not — should compare equal.
        let padded   = Checksum { algo: ChecksumAlgo::Sha512, value: format!("{}=", "A".repeat(87)) };
        let unpadded = Checksum { algo: ChecksumAlgo::Sha512, value: "A".repeat(87) };
        assert!(super::same_checksum(&padded, &unpadded));
    }

    #[test]
    fn hex_compare_case_insensitive() {
        let lower = Checksum { algo: ChecksumAlgo::Sha256, value: "deadbeef".repeat(8) };
        let upper = Checksum { algo: ChecksumAlgo::Sha256, value: "DEADBEEF".repeat(8) };
        assert!(super::same_checksum(&lower, &upper));
    }
}
