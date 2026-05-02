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
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Crates => "crates.io",
            Self::Npm    => "npm",
            Self::Pypi   => "PyPI",
            Self::Go     => "Go",
        }
    }
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
    struct Pkg  { name: String, version: String, source: Option<String> }

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
            out.push(Dependency {
                ecosystem: Ecosystem::Npm,
                name,
                version:   ver.to_string(),
                lockfile:  path.to_path_buf(),
                license,
                path:      Vec::new(),
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
            out.push(Dependency {
                ecosystem: Ecosystem::Npm,
                name:      name.clone(),
                version:   ver.to_string(),
                lockfile:  lockfile.to_path_buf(),
                license:   None,
                path:      full.clone(),
            });
            if let Some(nested) = meta.get("dependencies").and_then(|x| x.as_object()) {
                walk_npm_v1(nested, lockfile, &full, out);
            }
        }
    }
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

    for line in raw.lines() {
        let trimmed = line.trim_end();
        if !trimmed.starts_with(' ') && trimmed.ends_with(':') {
            // Heading — grab the first specifier, everything before `@`.
            let spec = trimmed.trim_end_matches(':').split(',').next().unwrap_or("").trim();
            let spec = spec.trim_matches('"');
            // Scoped packages start with `@`; skip that when finding the
            // version separator.
            let at = if spec.starts_with('@') {
                spec[1..].find('@').map(|i| i + 1)
            } else {
                spec.find('@')
            };
            current_name = at.map(|i| spec[..i].to_string());
        } else if let Some(name) = &current_name {
            if let Some(rest) = trimmed.trim_start().strip_prefix("version ") {
                let version = rest.trim().trim_matches('"').to_string();
                out.push(Dependency {
                    ecosystem: Ecosystem::Npm,
                    name:      name.clone(),
                    version,
                    lockfile:  path.to_path_buf(),
                    license:   None,
                    path:      Vec::new(),
                });
                current_name = None;
            }
        }
    }
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
        // Strip +incompatible suffixes that go.sum appends for v2+ modules
        // living at the module root.
        let version = version.trim_end_matches("+incompatible").to_string();
        out.push(Dependency {
            ecosystem: Ecosystem::Go,
            name:      name.to_string(),
            version,
            lockfile:  path.to_path_buf(),
            license:   None,
            path:      Vec::new(),
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
    for (line_no, line) in raw.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() { continue; }
        let Some((name, version)) = line.split_once("==") else {
            log::debug!("{}:{} skipping non-pinned requirement: {line}", path.display(), line_no + 1);
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
        });
    }
    Ok(out)
}

// ── poetry.lock (TOML) ───────────────────────────────────────────────

fn parse_poetry_lock(path: &Path) -> Result<Vec<Dependency>> {
    #[derive(Deserialize)]
    struct Lock { package: Option<Vec<Pkg>> }
    #[derive(Deserialize)]
    struct Pkg  { name: String, version: String }

    let raw = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: Lock = toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    Ok(lock.package.unwrap_or_default().into_iter().map(|p| Dependency {
        ecosystem: Ecosystem::Pypi,
        name:      p.name,
        version:   p.version,
        lockfile:  path.to_path_buf(),
        license:   None,
        path:      Vec::new(),
    }).collect())
}
