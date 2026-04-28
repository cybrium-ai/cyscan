# Changelog

All notable changes to cyscan are documented here.

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
