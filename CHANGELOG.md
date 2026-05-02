# Changelog

All notable changes to cyscan are documented here.

## [0.12.0] — 2026-05-02

### Added
- **Inter-procedural dataflow / taint propagation (Gap A4)** — closes the last major parity gap in the Semgrep Pro / Checkmarx One audit. New `src/dataflow/mod.rs` aggregates per-file `FileSemantics` from every scanned file, then runs a fixed-point taint propagator that walks `param_call_edges` (caller param N → callee arg M), `return_param_indices` (function returns its param), `direct_return_sources`, and `return_param_sanitizers` across file boundaries. Rules opt in via a `dataflow:` block; with `require_reachable: true`, findings are suppressed unless a real tainted source reaches the matched function. Findings always get `evidence.dataflow_function`, `evidence.dataflow_reachable`, and (when reachable) `evidence.dataflow_path` + `evidence.dataflow_path_string` showing the `caller → callee → … → sink` chain. The path payload falls back to `"source:<kind>"` when the chain ends at a built-in source so reviewers always see where the taint originated.
- New `matcher::run_rules_with_project` orchestrator. The single-file `run_rules` is preserved as a wrapper so non-project tests stay cheap.
- Project pre-pass in `scanner::run` runs only when at least one rule has a `dataflow:` block — rule packs that don't use dataflow pay zero overhead.
- 2 integration tests covering the cross-file path: `dataflow_require_reachable_suppresses_when_no_source_reaches_sink`, `dataflow_path_carries_source_kind_when_caller_chain_unavailable`.

## [0.11.0] — 2026-05-02

### Added
- **Local triage workflow (Gap D2)** — new `cyscan triage init / set / list / history` subcommand. Findings get a stable `fingerprint` (DefaultHasher over rule_id, file, line, normalised snippet → 16 hex chars). `cyscan scan --triage <file>` enriches findings with `triage_status / note / author / history_len` evidence; `--hide-triaged` drops `false_positive / accepted_risk / fixed`. `--fail-on` honours the same suppression so adopting cyscan in CI doesn't mean a permanent red build for known risks.
- **Semgrep DSL operators (Gap B1)** — rule YAML now accepts `pattern_either_groups` (any-of-all-of), `pattern_not_inside` (negative enclosing context), `metavariable_comparison(s)` (`len($x) > 10`, `$fn == "eval"`, `$arg starts_with "http://"`, etc.), and `metavariable_types` (per-capture node-kind constraint). The treesitter matcher feeds `node.kind()` into type checks; the regex matcher exposes a synthetic `match` capture so rules without AST captures still work.
- **Reachability dependency-path evidence (Gap C3)** — every advisory finding now carries `reachable_package`, `reachable_dependency_path[_string|_length]`, `reachable_import_name`, `reachable_callsite_count`, `reachable_callsites`, `reachable_symbol`, and `reachability_confidence` in evidence, plus a `reachability` verdict (`reachable / unreachable / unknown`). The npm v1 lockfile walker now produces top-down `["app", "express", "qs"]` chains so transitive vulnerabilities surface their full bring-in path.
- **Per-file FileSemantics + framework propagation (Gaps A5 + B2)** — new `src/matcher/semantics.rs` (~5,100 lines) extracts per-language semantics (imports, frameworks, variable types, function definitions, call assignments, param-call edges, taint sources/sanitisers, return-param indices, type hierarchy) for Python, JS/TS, Ruby, Java, C#, Go, Rust, PHP, Swift, Scala, C, Bash. Rule YAML can declare `frameworks: [django]` and the dispatcher only runs the rule on files where that framework was detected — eliminating "Django rule fires on a Flask file" false positives. Findings tagged with `evidence.framework` so reviewers see why the rule applied.
- **Apple notarization + Windows Authenticode signing** — release workflow now signs every macOS binary with Developer ID + notarytool and every Windows binary with signtool (SHA-256 timestamped). Existing Cosign keyless signing preserved. New repo secrets required: `APPLE_DEVELOPER_ID_CERT`, `APPLE_DEVELOPER_ID_CERT_PWD`, `APPLE_KEYCHAIN_PWD`, `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD`, `WINDOWS_CERT`, `WINDOWS_CERT_PWD`.

### Changed
- `Finding` gains a `fingerprint: String` field (empty by default; populated by `Finding::compute_fingerprint()` for triage / future baseline use).
- `lockfile::Dependency` gains a `path: Vec<String>` field carrying the top-down dep chain.
- `ImportIndex` gains `is_any_package_imported`, `get_import_sites_any`, and `matched_import_name` so reachability can probe alias variants (PyYAML → pyyaml + yaml).
- `matcher::run_rules` extracts `FileSemantics` once per file before dispatch; framework-tagged rules are filtered out when the file's frameworks don't intersect.

### Tests
- 14 integration + 39 unit + 0 doc tests pass.
- New tests: `triage_init_set_list_and_history_work`, `scan_applies_triage_status_and_hide_triaged`, `triaged_findings_do_not_trigger_fail_on`, `dsl_pattern_either_groups_match_complete_branch`, `dsl_pattern_not_inside_excludes_enclosing_context`, `dsl_metavariable_comparisons_filter_capture`, `supply_reachability_emits_dependency_path_and_callsite_evidence`, `semantics_extracts_imports_for_python`, `semantics_framework_filter_only_fires_in_matching_files`.

## [0.9.1] — 2026-04-30

### Fixed
- **Entropy secret scanning UTF-8 panic** — high-entropy snippet truncation now respects Unicode character boundaries, preventing crashes on multibyte characters such as `→` during secrets scanning.
- **GitHub Actions advisory loading** — CI and release workflows now fetch Git LFS advisory snapshots so `cyscan supply` tests and release packaging see real advisory data instead of LFS pointer files.
- **GitHub Actions runtime deprecation** — upgraded `actions/checkout` from `v4` to `v5` to align with GitHub's Node 24 transition.

## [0.9.0] — 2026-04-29

### Added
- **CIA triad posture scoring** — `cyscan scan --cia` produces Confidentiality, Integrity, and Availability scores (0-100) with top risks per dimension. Every finding auto-classified via CWE + rule heuristic. Rules can also declare explicit `cia:` blocks. Supports JSON output for dashboards.
- **Application package scanner** — `cyscan app` scans .app, .ipa, .pkg, .apk, .aab, .exe, .msi, .deb, .rpm for security issues (moved from 0.8.2 patch to this release).
- **Git LFS** for advisory snapshots (npm.jsonl 185MB exceeds GitHub limit).
- **NOTICE file** with trademark protection for all Cybrium marks.

## [0.8.2] — 2026-04-29

### Added
- **Application package scanner** — `cyscan app` scans .app, .ipa, .pkg, .apk, .aab, .exe, .msi, .deb, .rpm for security issues. macOS .app checks (12+): code signing, entitlements, sandbox, ATS, Hardened Runtime, notarization, privacy manifest, binary secrets, framework signing. iOS .ipa: provisioning profile, ATS, privacy manifest, binary secrets. Android .apk: debuggable flag, backup, cleartext traffic, permissions (13 dangerous), DEX secrets. Package installers (.pkg/.deb/.rpm): script analysis (curl-pipe-bash, chmod 777, hardcoded passwords), signing, SUID binaries.
- **NOTICE file** with trademark protection for all Cybrium marks (Cybrium, CyConscious, Cymind, PeriDex, Dexter, cyscan, cyweb, cyprobe, cysense, cyguard, cywave, cydeep, cymail).

## [0.8.1] — 2026-04-29

### Added
- **Endpoint security scanner** — `cyscan endpoint` scans the local machine for security posture issues. 23 macOS checks (FileVault, Gatekeeper, SIP, Firewall, auto-update, screen lock, SSH, ARD, sharing services, XProtect, Find My Mac, guest account, unsigned kexts) and 12 Linux checks (LUKS, UFW/iptables, SELinux/AppArmor, SSH hardening, SUID binaries, ASLR, auditd). Scored 0-100 weighted by severity. Supports `--format json` and `--fail-below` for CI gates.

## [0.8.0] — 2026-04-28

### Added
- **Kubernetes cluster scanning** — `cyscan k8s` connects to live clusters via kubectl, extracts manifests from 19 resource types, scans for misconfigurations/secrets, and renders a Trivy-style summary table. Supports `--report summary|full`, `--format json|sarif`, `--namespace`, `--scan-images`, `--fail-on`.
- **Native container image CVE scanning** — `cyscan k8s --scan-images` extracts OS packages (dpkg, apk, rpm, pacman) from image layers and queries OSV + NVD + GitHub Advisories. No grype/trivy dependency required.
- **296 secret detection rules** — full GitLeaks rule set (222 patterns) plus 74 custom rules covering AI providers, database URIs, IaC secrets, and generic patterns. Covers 100+ providers including 1Password, Adobe, Alibaba, Facebook, Fly.io, Grafana, HubSpot, Notion, Twitter/X, and more.
- **Entropy-based secret detection** — Shannon entropy analysis catches high-randomness strings that don't match any known pattern. Thresholds: hex >= 3.0, base64 >= 4.0, generic >= 4.5 bits/char. False positive suppression for UUIDs, git SHAs, URLs, file paths, semver.
- **Secret liveness verification** — `cyscan scan --verify` tests if detected credentials are live via safe, read-only API calls. 20+ providers supported (GitHub, Slack, Stripe, OpenAI, Anthropic, etc.). Live secrets escalated to CRITICAL.
- **License compliance scanning** — `cyscan supply` now flags risky licenses (AGPL, GPL, LGPL, SSPL, BUSL, Elastic). Handles compound SPDX expressions. Five risk categories: permissive, weak-copyleft, copyleft, network-copyleft, restricted.
- **Cloud-native IaC rules** — 59 rules for AWS CloudFormation (22), Azure ARM templates (19), GCP Deployment Manager (18). Covers S3, RDS, IAM, NSG, SQL Server, Key Vault, Compute, Firewall, GKE, and more.
- **.env and config file scanning** — `.env`, `.npmrc`, `.pypirc`, `.netrc`, `.pgpass`, `.git-credentials`, `.pem`, `.key` files now scanned for secrets.
- **Generic rules apply to all files** — rules tagged `generic` now fire on Python, JavaScript, Go, Java, etc. Not just files classified as Generic.

### Changed
- `RulePack.filter_languages()` for scoping rules to specific language sets (used by K8s scanner)
- `Dependency` struct gains `license` field (populated from package-lock.json v2+)
- `tempfile` moved from dev to regular dependency

### Stats
- 1,815 total rules (up from 1,067)
- 296 secret detection rules (up from ~30)
- 767 IaC rules across Terraform, CloudFormation, ARM, GCP DM, Kubernetes, Docker
- 75+ languages
- Native K8s cluster + container image scanning
- Multi-source CVE database (OSV + NVD + GitHub Advisories)

## [0.7.0] — 2026-04-28

### Added
- **75+ language support** — expanded from 19 to 75+ languages including Perl, Lua, Dart, Elixir, Haskell, Solidity, SQL, Protobuf, Ansible, Nginx, Kubernetes YAML, and more. All new languages use regex-only matching.
- **708 IaC misconfiguration rules** — imported and converted from Trivy's open-source check library (Apache 2.0):
  - 615 Terraform rules (AWS, Azure, GCP — encryption, public access, logging, IAM, network security)
  - 48 Kubernetes manifest rules (RBAC wildcards, privileged containers, host access, capability escalation, CIS benchmarks)
  - 45 Dockerfile rules (root user, secrets in ENV, package cache, ADD vs COPY, exposed ports)
- **1,460 total rules** (up from 1,067 in v0.6.1)

### Changed
- `Lang` enum now covers blockchain (Solidity, Vyper, Move, Cairo), database (SQL, PL/SQL, T-SQL), build systems (Makefile, CMake, Gradle, Maven, Bazel), IaC/config management (Ansible, Puppet, Chef, Salt), server configs (Nginx, Apache, Caddy), system configs (systemd, crontab), schemas (Protobuf, Thrift, GraphQL, Avro), and documentation (LaTeX, RST)
- Special filename detection in `from_path()` for Makefile, CMakeLists.txt, Gemfile, BUILD.bazel, Caddyfile, pom.xml, systemd units, Salt states, and more

## [0.6.1] — 2026-04-28

### Fixed
- Rules path resolution — canonicalize symlinks for Homebrew installs
- Self-update tarball extraction — was writing raw `.tar.gz` as binary causing "exec format error"

## [0.6.0] — 2026-04-28

### Added
- `cyscan health` — repository health check with 14 security hygiene checks (score 0-100)
- `cyscan frameworks` — detect 35 frameworks across 9 languages (Django, React, Spring, Rails, etc.)

## [0.5.0] — 2026-04-27

### Added
- **Reachability engine** — trace imports to function calls to vulnerable symbols. Findings now include reachability verdict (Reachable / Unreachable / Unknown) with confidence score.
- Semgrep pattern to regex converter — `$VAR` maps to `\w+`, `...` maps to `.*`, metacharacters escaped. Broad-pattern filter skips rules with fewer than 3 meaningful characters.
- All 1,067 rules now pass CI with the regex converter

## [0.4.0] — 2026-04-27

### Added
- **19 language support** — Python, JavaScript, TypeScript, Go (tree-sitter AST) + Java, Ruby, PHP, C/C++, C#, Rust, Kotlin, Swift, Scala, Bash, JSON, YAML, Terraform, Docker (regex-only)
- **1,025 curated rules** imported from the Semgrep OSS registry (Apache 2.0 licensed)
- `pattern:` field in rule schema for Semgrep-style patterns
- ASCII art banner on scan/supply/fix output

### Changed
- License switched from MIT to Apache 2.0

## [0.3.0] — 2026-04-26

### Added
- `cyscan supply` — software composition analysis
  - Lockfile parsing (package-lock.json, yarn.lock, Pipfile.lock, go.sum, Cargo.lock, Gemfile.lock, pom.xml, composer.lock)
  - OSV.dev vulnerability lookup
  - Typosquat detection (edit distance + popularity heuristics)
  - License compliance checking
  - Policy enforcement (severity thresholds, blocked CWEs)

## [0.2.0] — 2026-04-25

### Added
- `cyscan fix` — span-based autofix application
  - Dry-run mode (preview patches without applying)
  - Interactive mode (approve/reject per fix)
  - Automatic backup before applying
  - Rule schema gains `fix:` block with `replacement:` and `action:` fields

## [0.1.0] — 2026-04-24

### Added
- Initial release — multi-language SAST engine with tree-sitter (Python, JS, Go) + regex fallback
- SARIF, JSON, and text output formats
- `--fail-on` severity gate for CI/CD
- Self-update (`cyscan update`) with GitHub release detection
- Keyless Cosign signing for all release artifacts
- Homebrew tap: `brew install cybrium-ai/cli/cyscan`
