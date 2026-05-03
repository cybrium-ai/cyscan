//! Lockfile parsers. Each ecosystem has a wildly different format but
//! they all boil down to `(ecosystem, name, version, source lockfile)`.
//!
//! We deliberately prefer lockfiles (exact pinned versions) over manifests
//! (`Cargo.toml`, `package.json`, `go.mod`) because manifest ranges would
//! force us to resolve dependencies, which is the package manager's job.
//! If a project has only a manifest and no lockfile, we skip it — the
//! user will see a "no dependencies found" line and can commit the lock.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use ignore::WalkBuilder;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Crates,
    Npm,
    Pypi,
    Go,
    Composer,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Crates   => "crates.io",
            Self::Npm      => "npm",
            Self::Pypi     => "PyPI",
            Self::Go       => "Go",
            Self::Composer => "Packagist",
        }
    }
}

/// Hash algorithm declared by a lockfile entry. Different ecosystems
/// publish different algorithms — npm uses sha512 (base64), Cargo uses
/// sha256 (hex), Go uses h1 (sha256-tree, base64). The encoding format
/// is preserved verbatim in `Checksum::value` so the tampering scanner
/// can compare without re-parsing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChecksumAlgo {
    Sha512,
    Sha256,
    Sha1,
    /// Go's `h1:<b64>` format — sha256 of a directory hash tree.
    GoH1,
    /// Anything else we don't normalise. Recorded so we can flag
    /// weak-hash usage but won't validate against a registry.
    Other(String),
}

impl ChecksumAlgo {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Sha512   => "sha512",
            Self::Sha256   => "sha256",
            Self::Sha1     => "sha1",
            Self::GoH1     => "h1",
            Self::Other(s) => s.as_str(),
        }
    }

    /// Expected encoded length (in characters) for the canonical
    /// encoding used in lockfiles. Used by the malformed-integrity
    /// detector. None = no fixed length we can check (e.g. Other).
    pub fn expected_len(&self) -> Option<usize> {
        match self {
            Self::Sha512 => Some(88), // 64 bytes → base64 with padding
            Self::Sha256 => Some(64), // 32 bytes → hex
            Self::Sha1   => Some(40), // 20 bytes → hex
            Self::GoH1   => Some(44), // 32 bytes → base64 with padding
            Self::Other(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Checksum {
    pub algo:  ChecksumAlgo,
    /// Encoded value, verbatim from the lockfile (hex for Cargo, base64
    /// for npm/Go). Comparison is on the (algo, value) pair.
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub ecosystem: Ecosystem,
    pub name:      String,
    pub version:   String,
    pub lockfile:  PathBuf,
    /// SPDX license identifier (if available from lockfile/manifest).
    pub license:   Option<String>,
    /// Top-down dependency path that brought this package in
    /// (e.g. ["app", "express", "qs"]). Empty when the lockfile parser
    /// can't resolve the chain — `extract_dependency_path` falls back
    /// to `[name]` in that case. Populated by the walkers added in
    /// Gap 4 / C3.
    pub path:      Vec<String>,
    /// Declared cryptographic checksum from the lockfile. Used by
    /// `supply::tampering` to detect missing / conflicting / malformed
    /// integrity entries (offline) and to verify against the upstream
    /// registry's published checksum (online, opt-in via
    /// `--verify-integrity`). None = the lockfile format doesn't
    /// carry a checksum for this entry.
    pub declared_checksum: Option<Checksum>,
}

/// Walk `root`, parsing every lockfile into a flat list of deps.
pub fn discover(root: &Path) -> Result<Vec<Dependency>> {
    if !root.exists() {
        anyhow::bail!("target does not exist: {}", root.display());
    }

    let mut deps = Vec::new();
    for entry in WalkBuilder::new(root).standard_filters(true).hidden(false).build() {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().map_or(false, |ft| ft.is_file()) { continue; }
        let path = entry.path();

        match path.file_name().and_then(|s| s.to_str()) {
            Some("Cargo.lock")        => deps.extend(parse_cargo_lock(path)?),
            Some("package-lock.json") => deps.extend(parse_npm_lock(path)?),
            Some("yarn.lock")         => deps.extend(parse_yarn_lock(path)?),
            Some("go.sum")            => deps.extend(parse_go_sum(path)?),
            Some("requirements.txt")  => deps.extend(parse_requirements(path)?),
            Some("poetry.lock")       => deps.extend(parse_poetry_lock(path)?),
            Some("Pipfile.lock")      => deps.extend(parse_pipfile_lock(path)?),
            Some("composer.lock")     => deps.extend(parse_composer_lock(path)?),
            _ => {}
        }
    }
    Ok(deps)
}

// ── Cargo.lock (TOML) ────────────────────────────────────────────────

fn parse_cargo_lock(path: &Path) -> Result<Vec<Dependency>> {
    #[derive(Deserialize)]
    struct Lock { package: Option<Vec<Pkg>> }
    #[derive(Deserialize)]
    struct Pkg  {
        name: String,
        version: String,
        source: Option<String>,
        checksum: Option<String>,
    }

    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: Lock = toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;

    Ok(lock.package.unwrap_or_default().into_iter()
        // Path + git deps have no crates.io source — skip; advisories
        // only apply to registry releases.
        .filter(|p| p.source.as_deref().map_or(false, |s| s.starts_with("registry+")))
        .map(|p| Dependency {
            ecosystem: Ecosystem::Crates,
            name:      p.name,
            version:   p.version,
            lockfile:  path.to_path_buf(),
            license:   None, // Cargo.lock doesn't carry license; Cargo.toml would
            path:      Vec::new(),
            declared_checksum: p.checksum.map(|v| Checksum {
                algo: ChecksumAlgo::Sha256,
                value: v,
            }),
        }).collect())
}

// ── package-lock.json (v1 + v2/v3) ───────────────────────────────────

fn parse_npm_lock(path: &Path) -> Result<Vec<Dependency>> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {}", path.display()))?;

    let mut out = Vec::new();

    // npm v2+: `packages` is a map of path → metadata. Keys look like
    // `"node_modules/<name>"` or `""` for root. Root has no version info
    // we care about; skip it.
    if let Some(pkgs) = v.get("packages").and_then(|x| x.as_object()) {
        for (key, meta) in pkgs {
            if key.is_empty() { continue; }
            // Strip the leading `node_modules/` prefix; what remains may
            // still nest (`node_modules/a/node_modules/b`) — take the
            // last `node_modules/` segment.
            let name = key.rsplit("node_modules/").next().unwrap_or(key).to_string();
            let Some(ver) = meta.get("version").and_then(|x| x.as_str()) else { continue };
            // npm v2+ packages carry a "license" field
            let license = meta.get("license").and_then(|l| l.as_str()).map(|s| s.to_string());
            let declared_checksum = meta.get("integrity")
                .and_then(|x| x.as_str())
                .and_then(parse_npm_integrity);
            out.push(Dependency {
                ecosystem: Ecosystem::Npm,
                name,
                version:   ver.to_string(),
                lockfile:  path.to_path_buf(),
                license,
                path:      Vec::new(),
                declared_checksum,
            });
        }
        return Ok(out);
    }

    // npm v1 layout: `dependencies` is recursive.
    if let Some(deps) = v.get("dependencies").and_then(|x| x.as_object()) {
        // Use the lockfile filename's parent dir as the synthetic root
        // so paths read as ["my-app", "express", "qs"] not ["express", "qs"].
        let root = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("root")
            .to_string();
        walk_npm_v1(deps, path, &[root], &mut out);
    }
    Ok(out)
}

fn walk_npm_v1(
    deps: &serde_json::Map<String, serde_json::Value>,
    lockfile: &Path,
    parent_path: &[String],
    out: &mut Vec<Dependency>,
) {
    for (name, meta) in deps {
        if let Some(ver) = meta.get("version").and_then(|x| x.as_str()) {
            let mut full = parent_path.to_vec();
            full.push(name.clone());
            let declared_checksum = meta.get("integrity")
                .and_then(|x| x.as_str())
                .and_then(parse_npm_integrity);
            out.push(Dependency {
                ecosystem: Ecosystem::Npm,
                name:      name.clone(),
                version:   ver.to_string(),
                lockfile:  lockfile.to_path_buf(),
                license:   None,
                path:      full.clone(),
                declared_checksum,
            });
            if let Some(nested) = meta.get("dependencies").and_then(|x| x.as_object()) {
                walk_npm_v1(nested, lockfile, &full, out);
            }
        }
    }
}

/// Parse an npm `integrity` field. Format: `<algo>-<base64>` where
/// `<algo>` is `sha512` (preferred), `sha384`, `sha256`, or legacy
/// `sha1`. Multi-hash form (`sha512-... sha256-...`) takes the
/// strongest entry.
///
/// Re-exported as `parse_npm_integrity_pub` for the tampering_online
/// module which receives this format from the npm registry response.
pub fn parse_npm_integrity_pub(raw: &str) -> Option<Checksum> {
    parse_npm_integrity(raw)
}

fn parse_npm_integrity(raw: &str) -> Option<Checksum> {
    let mut best: Option<Checksum> = None;
    for token in raw.split_whitespace() {
        let (algo_str, value) = token.split_once('-')?;
        let algo = match algo_str {
            "sha512" => ChecksumAlgo::Sha512,
            "sha256" => ChecksumAlgo::Sha256,
            "sha1"   => ChecksumAlgo::Sha1,
            other    => ChecksumAlgo::Other(other.to_string()),
        };
        let candidate = Checksum { algo: algo.clone(), value: value.to_string() };
        // Prefer stronger algos: sha512 > sha256 > sha1 > other.
        let candidate_strength = match algo {
            ChecksumAlgo::Sha512   => 4,
            ChecksumAlgo::Sha256   => 3,
            ChecksumAlgo::GoH1     => 3,
            ChecksumAlgo::Sha1     => 2,
            ChecksumAlgo::Other(_) => 1,
        };
        let current_strength = best.as_ref().map(|b| match b.algo {
            ChecksumAlgo::Sha512   => 4,
            ChecksumAlgo::Sha256   => 3,
            ChecksumAlgo::GoH1     => 3,
            ChecksumAlgo::Sha1     => 2,
            ChecksumAlgo::Other(_) => 1,
        }).unwrap_or(0);
        if candidate_strength > current_strength {
            best = Some(candidate);
        }
    }
    best
}

// ── yarn.lock (classic v1 text format) ───────────────────────────────
//
// Entries look like:
//   "event-stream@^3.3.6":
//     version "3.3.6"
//     resolved "..."
//
// We deliberately parse the minimum: the name from the heading and the
// quoted version on the `version` line. Yarn Berry (v2+) uses YAML
// which is more robust but most projects still on classic.

fn parse_yarn_lock(path: &Path) -> Result<Vec<Dependency>> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut current_integrity: Option<Checksum> = None;

    let flush = |name: &mut Option<String>,
                 version: &mut Option<String>,
                 integrity: &mut Option<Checksum>,
                 out: &mut Vec<Dependency>| {
        if let (Some(n), Some(v)) = (name.take(), version.take()) {
            out.push(Dependency {
                ecosystem: Ecosystem::Npm,
                name:      n,
                version:   v,
                lockfile:  path.to_path_buf(),
                license:   None,
                path:      Vec::new(),
                declared_checksum: integrity.take(),
            });
        }
        *name = None;
        *version = None;
        *integrity = None;
    };

    for line in raw.lines() {
        let trimmed = line.trim_end();
        if !trimmed.starts_with(' ') && trimmed.ends_with(':') {
            // New entry — flush the previous one if present.
            flush(&mut current_name, &mut current_version, &mut current_integrity, &mut out);
            // Heading — grab the first specifier, everything before `@`.
            let spec = trimmed.trim_end_matches(':').split(',').next().unwrap_or("").trim();
            let spec = spec.trim_matches('"');
            let at = if spec.starts_with('@') {
                spec[1..].find('@').map(|i| i + 1)
            } else {
                spec.find('@')
            };
            current_name = at.map(|i| spec[..i].to_string());
        } else if current_name.is_some() {
            let inner = trimmed.trim_start();
            if let Some(rest) = inner.strip_prefix("version ") {
                current_version = Some(rest.trim().trim_matches('"').to_string());
            } else if let Some(rest) = inner.strip_prefix("integrity ") {
                current_integrity = parse_npm_integrity(rest.trim().trim_matches('"'));
            }
        }
    }
    // Flush the trailing entry.
    flush(&mut current_name, &mut current_version, &mut current_integrity, &mut out);
    Ok(out)
}

// ── go.sum ───────────────────────────────────────────────────────────
//
// Lines look like:
//   github.com/foo/bar v1.2.3 h1:...
//   github.com/foo/bar v1.2.3/go.mod h1:...
// We want each `(module, version)` exactly once — dedupe by skipping
// the `/go.mod` lines.

fn parse_go_sum(path: &Path) -> Result<Vec<Dependency>> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else { continue };
        let Some(version) = parts.next() else { continue };
        if version.ends_with("/go.mod") { continue; }
        let hash = parts.next();
        // Strip +incompatible suffixes that go.sum appends for v2+ modules
        // living at the module root.
        let version = version.trim_end_matches("+incompatible").to_string();
        let declared_checksum = hash
            .and_then(|h| h.strip_prefix("h1:"))
            .map(|v| Checksum { algo: ChecksumAlgo::GoH1, value: v.to_string() });
        out.push(Dependency {
            ecosystem: Ecosystem::Go,
            name:      name.to_string(),
            version,
            lockfile:  path.to_path_buf(),
            license:   None,
            path:      Vec::new(),
            declared_checksum,
        });
    }
    Ok(out)
}

// ── requirements.txt ─────────────────────────────────────────────────
//
// Only the `name==version` form gives us a precise pin. Range specs
// (`name>=1.2`) are skipped with a log line — advisory matching needs
// exact versions.

fn parse_requirements(path: &Path) -> Result<Vec<Dependency>> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    // pip's `--hash=sha256:<hex>` flag attaches to the previous package
    // line. Buffer the most-recent hash and apply it to whichever line
    // it follows.
    let mut pending_hash: Option<Checksum> = None;
    for (line_no, line) in raw.lines().enumerate() {
        let line_no_disp = line_no + 1;
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() { continue; }
        // pip line continuation: --hash=sha256:<hex>
        if let Some(rest) = line.strip_prefix("--hash=") {
            if let Some((algo_str, value)) = rest.split_once(':') {
                let algo = match algo_str {
                    "sha512" => ChecksumAlgo::Sha512,
                    "sha256" => ChecksumAlgo::Sha256,
                    "sha1"   => ChecksumAlgo::Sha1,
                    other    => ChecksumAlgo::Other(other.to_string()),
                };
                pending_hash = Some(Checksum { algo, value: value.to_string() });
            }
            continue;
        }
        let Some((name, version)) = line.split_once("==") else {
            log::debug!("{}:{} skipping non-pinned requirement: {line}", path.display(), line_no_disp);
            continue;
        };
        // Strip extras like `package[extra]==1.0` → name = "package"
        let name = name.split('[').next().unwrap_or(name).trim().to_string();
        let version = version.split(';').next().unwrap_or(version).trim().to_string();
        if name.is_empty() || version.is_empty() { continue; }
        out.push(Dependency {
            ecosystem: Ecosystem::Pypi,
            name,
            version,
            lockfile: path.to_path_buf(),
            license:  None,
            path:      Vec::new(),
            declared_checksum: pending_hash.take(),
        });
    }
    Ok(out)
}

// ── poetry.lock (TOML) ───────────────────────────────────────────────

fn parse_poetry_lock(path: &Path) -> Result<Vec<Dependency>> {
    #[derive(Deserialize)]
    struct Lock { package: Option<Vec<Pkg>> }
    #[derive(Deserialize)]
    struct Pkg  {
        name: String,
        version: String,
        files: Option<Vec<PoetryFile>>,
    }
    #[derive(Deserialize)]
    struct PoetryFile { hash: String, file: Option<String> }

    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: Lock = toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    Ok(lock.package.unwrap_or_default().into_iter().map(|p| {
        // Prefer the sdist hash (the `.tar.gz` artefact); fall back to
        // the first wheel. Different lockfiles ship different orderings
        // so we sort sdist-first explicitly.
        let declared_checksum = p.files.as_ref().and_then(|fs| {
            let sdist = fs.iter().find(|f| {
                f.file.as_deref().map_or(false, |n| n.ends_with(".tar.gz"))
            });
            let chosen = sdist.or_else(|| fs.first());
            chosen.and_then(|f| parse_pep503_hash(&f.hash))
        });
        Dependency {
            ecosystem: Ecosystem::Pypi,
            name:      p.name,
            version:   p.version,
            lockfile:  path.to_path_buf(),
            license:   None,
            path:      Vec::new(),
            declared_checksum,
        }
    }).collect())
}

/// Parse a PEP 503 / pip-style hash string (`sha256:<hex>`,
/// `sha512:<hex>`, etc.). Used by poetry.lock and Pipfile.lock.
fn parse_pep503_hash(raw: &str) -> Option<Checksum> {
    let (algo_str, value) = raw.split_once(':')?;
    let algo = match algo_str {
        "sha512" => ChecksumAlgo::Sha512,
        "sha256" => ChecksumAlgo::Sha256,
        "sha1"   => ChecksumAlgo::Sha1,
        other    => ChecksumAlgo::Other(other.to_string()),
    };
    Some(Checksum { algo, value: value.to_string() })
}

// ── Pipfile.lock (JSON) ──────────────────────────────────────────────
//
// Pipfile.lock has `default` and `develop` sections, each a map of
// `name -> { version: "==1.2.3", hashes: ["sha256:abc...", ...] }`.

fn parse_pipfile_lock(path: &Path) -> Result<Vec<Dependency>> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {}", path.display()))?;

    let mut out = Vec::new();
    for section in &["default", "develop"] {
        let Some(pkgs) = v.get(*section).and_then(|x| x.as_object()) else { continue };
        for (name, meta) in pkgs {
            let Some(ver_raw) = meta.get("version").and_then(|x| x.as_str()) else { continue };
            // Pipfile.lock encodes pinned versions as `==1.2.3`.
            let version = ver_raw.trim_start_matches("==").to_string();
            let declared_checksum = meta
                .get("hashes")
                .and_then(|h| h.as_array())
                .and_then(|arr| arr.first())
                .and_then(|s| s.as_str())
                .and_then(parse_pep503_hash);
            out.push(Dependency {
                ecosystem: Ecosystem::Pypi,
                name:      name.clone(),
                version,
                lockfile:  path.to_path_buf(),
                license:   None,
                path:      Vec::new(),
                declared_checksum,
            });
        }
    }
    Ok(out)
}

// ── composer.lock (JSON, PHP / Packagist) ────────────────────────────
//
// Top-level `packages` (and optionally `packages-dev`) — each entry has
// `name`, `version`, `dist.shasum`. Packagist publishes sha1.

fn parse_composer_lock(path: &Path) -> Result<Vec<Dependency>> {
    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {}", path.display()))?;

    let mut out = Vec::new();
    for section in &["packages", "packages-dev"] {
        let Some(pkgs) = v.get(*section).and_then(|x| x.as_array()) else { continue };
        for pkg in pkgs {
            let Some(name) = pkg.get("name").and_then(|x| x.as_str()) else { continue };
            let Some(version) = pkg.get("version").and_then(|x| x.as_str()) else { continue };
            let license = pkg.get("license")
                .and_then(|l| l.as_array())
                .and_then(|a| a.first())
                .and_then(|s| s.as_str())
                .map(|s| s.to_string());
            let declared_checksum = pkg.get("dist")
                .and_then(|d| d.get("shasum"))
                .and_then(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(|v| Checksum { algo: ChecksumAlgo::Sha1, value: v.to_string() });
            out.push(Dependency {
                ecosystem: Ecosystem::Composer,
                name:      name.to_string(),
                version:   version.trim_start_matches('v').to_string(),
                lockfile:  path.to_path_buf(),
                license,
                path:      Vec::new(),
                declared_checksum,
            });
        }
    }
    Ok(out)
}
