# Changelog

All notable changes to cyscan are documented here.

## [0.21.0] — 2026-05-02

### Added
- **`metavariable-receiver-type`** — Checkmarx-style semantic disambiguation. The match fires only when the captured identifier resolves (via the per-file symbol / import / type-hierarchy graph already built in `FileSemantics`) to one of the listed types.

  Closes the false-positive class where two libraries name a method the same way:
  ```yaml
  query: |
    (call function: (attribute object: (identifier) @recv attribute: (identifier) @method))
  metavariable_receiver_type:
    recv:
      - sqlite3
      - psycopg2
      - Microsoft.Data.SqlClient
  ```

  Resolution order:
  1. `variable_types[$X]` — `db = sqlite3.connect(...)` style direct receiver typing
  2. `imported_symbols[$X]` — `using SqlConnection;` style qualified imports
  3. `alias_to_module[$X]` — `import sqlite3 as sql` style module aliases

  Type matching against each allow-list entry tries: exact equality, substring containment in either direction (`SqlConnection` matches `Microsoft.Data.SqlClient.SqlConnection` and vice-versa), and finally regex.

  Type-hierarchy walk: each resolved type is followed up through `type_hierarchy` so a rule listing `DbCommand` accepts `SqlCommand : DbCommand`.

  Available in both regex- and tree-sitter-based rules. Works for the 12 languages the semantics layer already covers (Python, JS, TS, Ruby, Java, C#, Go, Rust, PHP, Swift, Scala, C, Bash).

### Notes
This was the last meaningful gap vs. Checkmarx One's "semantic engine" pitch — false-positive elimination via receiver-type disambiguation. Combined with the existing inter-procedural taint engine, `pattern-where`, and `metavariable-pattern: { language }` (v0.20.0), cyscan now ships every commercial-tier disambiguation primitive.

4 new integration tests:
- `receiver_type_accepts_call_on_imported_module`
- `receiver_type_rejects_unrelated_local_class_with_same_method_name`
- `receiver_type_substring_match_works_in_either_direction`
- `receiver_type_filter_is_skipped_when_unset`

## [0.20.0] — 2026-05-02

### Added
- **`metavariable-pattern` (nested AST)** — rule YAML now accepts a `metavariable_pattern_ast: { capture: { pattern: ..., regex: ..., language: ... } }` block. The inner pattern runs against the captured node's text, optionally re-parsed in a different language. Closes the Semgrep `metavariable-pattern: { language, pattern }` gap.
- **Cross-language sub-patterns** — the `language:` field on a nested-pattern spec lets the inner pattern target a different grammar than the outer rule. Example: capture JS inside an HTML `<script>` block, then run an `eval(...)` pattern against the captured JS:
  ```yaml
  regex: "<script[^>]*>([^<]*)</script>"
  metavariable_pattern_ast:
    match:
      language: javascript
      regex: "eval\\s*\\("
  ```
- **`pattern-where`** — Semgrep beta operator. Accepts compound boolean expressions over metavariables: `and`, `or`, `not`, parentheses for grouping, plus the same comparison primitives as `metavariable-comparison` (`==`, `!=`, `>`, `<`, `>=`, `<=`, `contains`, `starts_with`, `ends_with`, `matches`, `len(...)`).
  ```yaml
  pattern_where: '(len($x) > 10 and $x contains "admin") or $x matches "^TOKEN_"'
  ```

### Notes
This closes every advertised metavariable-* / pattern-* operator from the Semgrep DSL surface. cyscan now ships every operator that Semgrep OSS, Semgrep Pro (publicly), and the beta operators target. The metavariable-* family is fully covered: `comparison` (single + list), `regex`, `pattern` (regex flavour), `pattern-ast` (with cross-language re-parse), `types`, `analysis` (redos + entropy). Plus the structural family: `pattern`, `patterns`, `pattern-either`, `pattern-either-groups`, `pattern-not`, `pattern-inside`, `pattern-not-inside`, `pattern-not-regex`, `pattern-where`.

## [0.19.0] — 2026-05-02

### Added
- **`metavariable-analysis` (Semgrep Pro parity).** Rule YAML now accepts a `metavariable_analysis: { capture_name: analyzer }` block. Two analyzers ship: `redos` (catastrophic-backtracking detector — flags nested unbounded quantifiers `(...)+`/`(...)*`, multiple `.* / .+` repeats, overlapping-alternation-in-quantifier patterns) and `entropy` (Shannon-entropy gate ≥ 3.5 bits/char + ≥ 2 character classes + length ≥ 16 — matches real API keys / JWTs without flagging English sentences). Wired into both `regex::match_rule` and `treesitter::match_rule`.
  - Semgrep OSS doesn't have `metavariable-analysis`; it's a Semgrep Pro feature. Shipping it puts cyscan **ahead of Semgrep OSS** on this surface.
- **Capturing-group support in the regex matcher.** When a rule's `regex:` has a capturing group, all metavariable filters (regex / pattern / types / analysis / comparisons) see group 1 instead of the whole match. Lets rules like `regex: TOKEN\s*=\s*['\"]([^'\"]+)['\"]` feed only the literal value into entropy / redos checks.
- 2 new integration tests + 5 unit tests covering ReDoS detection (positive + negative), entropy gating (positive + negative + char-class diversity), and end-to-end rule matching.

### Notes
- The metavariable-* family now shipped: `metavariable-comparison` (single + list), `metavariable-regex`, `metavariable-pattern` (regex flavor), `metavariable-types`, `metavariable-analysis` (redos + entropy), plus the `pattern-*` siblings (`pattern-either`, `pattern-either-groups`, `pattern-not`, `pattern-inside`, `pattern-not-inside`, `pattern-not-regex`).
- Still deferred: nested-AST `metavariable-pattern` (needs sub-AST parser, complex) and cross-language `metavariable-pattern` with `language:` (rare; deferred to follow-up).

## [0.18.0] — 2026-05-02

### Added
- **GraphQL schema parsing.** `*.graphql` / `*.gql` / `*.schema.graphql` files now feed the cross-service spec layer. `type Query`, `type Mutation`, `type Subscription`, and `extend type X` blocks are extracted into `SpecOperation`s. Embedded GraphQL queries in source code (any tier-1 language — Python / JS/TS / C# / Java / Go / Ruby / Rust / Swift / Elixir) are matched against the schema as `POST /graphql#Mutation.createUser`-style synthetic paths so a JS Apollo `gql\`mutation CreateUser { ... }\`` pairs with the schema's `createUser` field.
- **Kubernetes / Helm topology resolution.** `xservice/k8s.rs` walks every `*.yaml` / `*.yml` looking for `kind: Service` / `kind: Deployment` / `kind: StatefulSet` / `kind: DaemonSet` definitions and builds a `K8sTopology` with service-name → port-and-selector + label → deployment-name maps. `resolve_url("http://user-svc/api/users", &topology)` returns the Service info plus the Deployment names whose labels match the selector. Handler-side findings get tagged `evidence.cross_service_k8s_resolution` listing the resolved service + deployments.
- **Cross-service taint propagation (graph-level).** New `xservice/taint.rs` walks the link graph after the `dataflow:` propagator runs and emits `CrossServiceTaint` entries for chains where a tainted source on the caller side reaches a handler whose enclosing function is sink-receiving. Findings on the handler side get `evidence.cross_service_taint` listing the chain. **This is not full IR-level taint** (we don't trace the value across runtimes), but it answers the practical question "is the path source → sink across services reachable in principle?" Confidence is reported (0.5 heuristic, 0.85 explicit).
- **8 new framework patterns.** Echo + Gin (Go), Actix-web + Axum + Rocket (Rust), Sanic + Tornado (Python), Vapor (Swift), Phoenix (Elixir), HTTPoison (Elixir client). Plus `reqwest` direct + builder for Rust clients, `URLSession` for Swift clients.

### Notes
- The cross-service taint engine is a meaningful step, not the full IR layer. Customers asking "I want Auth.cs:Login's tainted password to be traced through UserService.java:login into Db.py:execute" get a yes/no answer with caller chain — they don't get value-level provenance. The IR layer remains a future research effort.
- `CrossServiceMap` now serialises with `k8s` + `taint_links` fields. JSON consumers should treat them as additive.
- Total spec kinds supported: OpenAPI (2 + 3, YAML + JSON), Protobuf (`.proto`), GraphQL (`.graphql` / `.gql`).
- Total handler frameworks recognised: 18 (was 10): flask, fastapi, django, sanic, tornado, express, nestjs, fastify (via express patterns), aspnet, aspnet-minimal, spring, net/http, gin, echo, axum, actix-web, rocket, vapor, phoenix, rails.

## [0.17.0] — 2026-05-02

### Added
- **Cross-service evidence wired into scan-time findings.** Every finding inside an HTTP handler now carries `evidence.cross_service_callers` listing every controller / upstream caller that routes into it — even across language boundaries. A SQL-injection finding in `db.py:lookup` shows up tagged with the C# `AuthController.cs:Login` and the Java `UserService.java:login` that reach it. SARIF emission turns the list into `relatedLocations` so CodeQL-style viewers render the chain inline.
- **Composite cross-service finding aggregation.** When the same `rule_id` fires inside both an HTTP handler and a controller that calls it, the scanner emits a synthetic `<RULE>-XSVC` finding tagged `evidence.cross_service_chain` listing every linked finding location. SARIF consumers see the chain as a single reviewable result with related-locations, instead of N disconnected findings.
- **Path-prefix composition.** Spring `@RequestMapping("/api") + @PostMapping("/users")` → `/api/users`, ASP.NET Core `[Route("/api")] + [HttpPost("/users")]` → `/api/users`, NestJS `@Controller("/api") + @Post("/users")` → `/api/users`. Class-level prefixes are tracked as the file is walked and composed onto every method-level mapping below them. Closes the cross-service-pairing false-negative where the client called `/api/users` but the handler showed up as `/users`.
- **DOT + Mermaid graph output for `cyscan xservice`.** `cyscan xservice -f dot | dot -Tsvg > xservice.svg` for Graphviz; `cyscan xservice -f mermaid` produces inline-renderable Mermaid for GitHub markdown / Notion. Edges labelled with method + path; unmatched (external) calls drawn dashed.
- 3 new integration tests: path-prefix composition, scanner-side cross_service_callers evidence, DOT/Mermaid output shape.

### Notes
SARIF related-locations also surface the linked findings from `cross_service_chain` and the upstream callers from `cross_service_callers`, so any SARIF consumer (GitHub Code Scanning, VS Code SARIF Viewer, IDEA SARIF plugin) will render the cross-service chain natively.

## [0.16.0] — 2026-05-02

### Added
- **`cyscan xservice` — cross-service API contract scanner.** Discovers every HTTP/gRPC client call and server endpoint in a polyglot repo, pairs them by `(method, normalised_path)`, and surfaces the cross-service map as text or JSON. **No other OSS scanner ships this.** Closes the "C# controller calls Java service calls Python DB helper" visibility gap that pure SAST doesn't address (and that Semgrep Pro / Checkmarx One don't address either — they trace within a language, not across).
  - **Client detection:** Python `requests`/`httpx`/`aiohttp`, JS/TS `fetch`/`axios`/`got`, C# `HttpClient`, Java `RestTemplate`/`WebClient`, Go `net/http`, Ruby `Net::HTTP`/`HTTParty`/`RestClient`/`Faraday`.
  - **Handler detection:** Flask/FastAPI/Django, Express/NestJS, ASP.NET Core (attributes + minimal API), Spring MVC (`@*Mapping` + `@RequestMapping`), Go `http.HandleFunc`, Rails routes.
  - **Spec parsing:** OpenAPI YAML/JSON (Swagger 2 + 3), Protobuf service definitions (`rpc Foo(Bar) returns (Baz);` → `/Service/Foo` POST). When spec files are committed they become a third match source.
  - **Path normalisation:** `/users/{id}` ≡ `/users/:id` ≡ `/users/<id>` ≡ `/users/<int:id>` ≡ `/users/(?P<id>[^/]+)` all collapse to `/users/{}` so cross-framework matches work without per-style hacks.
  - **Match engine output:** Each link reports `client → handler` plus `matched_via` of `direct`, `spec:<file>`, or `unmatched` (for calls to external APIs).
  - 2 new integration tests: cross-language pair (C# → Java → Python) + path-style normalisation (OpenAPI/Flask styles).

## [0.15.0] — 2026-05-02

### Added
- **Backwards reachability** in the taint engine. `ProjectSemantics::sources_reaching(sink_fn)` walks the reverse call graph upward from a sink function and returns every source kind that transitively reaches it. `ProjectSemantics::callers_of(sink_fn)` returns the caller chain. Findings now carry `evidence.dataflow_reaching_sources` (set of source kinds) and `evidence.dataflow_caller_chain` (BFS caller list) when reachable. Closes the Semgrep-Pro "ask the question from the sink, not the source" gap.
- **Dynamic dispatch via callable aliases.** `FileSemantics.callable_aliases: HashMap<String, String>` maps identifiers bound to callable sinks (`f = eval` → `f -> eval`). `ProjectSemantics::build` mirrors taint onto the underlying name so `f(x)` is treated identically to `eval(x)` in the propagator. Allowlist-restricted to known sink callables to keep the alias map high-signal.
- **Decorator-implied framework binding.** `FileSemantics.decorated_functions: HashMap<fn_name, Vec<decorator>>`. The matcher's framework filter now considers a rule with `frameworks: [flask]` as eligible when the file has any function decorated `@app.route` or `@blueprint.route`, even if the file's import set didn't catch flask. Same logic for fastapi (`@router.get/post/put/delete/patch`), django (`@login_required`, `@csrf_exempt`, `@require_*`, `@permission_required`), express (`@app.*`, `@router.*`), spring (`@RequestMapping`, `@GetMapping`, `@PostMapping`, `@Controller`, `@RestController`), and rails (`before_action`).
- **Metaprogrammed-class evidence (Phase D).** `FileSemantics.metaprogrammed_classes: HashMap<class, reasons>` flags classes declared with `metaclass=...` or that override `__init_subclass__`. Findings inside a flagged class get `evidence.metaprogrammed_class = { class, reasons }` so reviewers know to double-check rule applicability — the engine doesn't *resolve* what the metaclass does, but it doesn't pretend it isn't there either.
- 4 new integration / unit tests cover the four new behaviours.

### Notes
This release narrows but does not fully close the gap to Semgrep Pro / Checkmarx One on engine depth. The taint engine is still forward-only fixed-point at its core (Phase B's backwards reachability is a query layer over the same data); we don't do constant propagation, alias analysis is identifier-only (`f = eval`, not `f = obj.method`), and metaprogramming is surfaced rather than resolved. See README parity scorecard.

## [0.14.0] — 2026-05-02

### Added
- **Scope-aware JavaScript / TypeScript symbol table** — extends the Python work in v0.13.0. `build_javascript_symbol_table(source) -> SymbolTable` walks curly braces (string-literal-aware) to track lexical scopes, recognises `var`/`let`/`const`/`function`/`class` bindings plus all four ES module import forms (`import X from`, `import { a, b as c } from`, `import * as`, CommonJS `require` + destructure). Same `resolve(line, name)` API as Python — narrowest enclosing scope wins. 4 unit tests cover default-import, named-import-with-alias, function-scope-shadows-module, require-destructure.

### Security
- **Switched HTTP TLS backend from rustls (ring) to native-tls** — closes the GHSA-4p46-pwfr-66x6 advisory (`ring < 0.17.12` AES panic on overflow check) by removing `ring` from the dep tree entirely. `reqwest` now uses the system crypto stack: SecureTransport on macOS, SChannel on Windows, OpenSSL on Linux. `cargo audit`: no vulnerabilities found.

## [0.13.0] — 2026-05-02

### Added
- **Semgrep-max DSL operators** — `metavariable_regex` (per-capture regex constraint), `metavariable_pattern` (per-capture sub-pattern, regex flavour; nested AST patterns deferred), and `pattern_not_regex` (matched-line negative regex filter). Closes the remaining headline DSL gap from the parity audit. Wired into both `regex::match_rule` and `treesitter::match_rule`. Two new integration tests cover the operators.
- **Scope-aware Python symbol table (`src/symbols/`)** — start of compiler-grade resolution. `build_python_symbol_table(source)` returns a `SymbolTable` whose `resolve(line, name)` walks the lexical scope stack (Module / Function / Class) outward and returns the *narrowest* binding that covers the line — shadowing resolves correctly, unlike the flat `variable_types: HashMap` from the semantic extractor. Indentation-driven scope detection over Python source; bindings extracted from `=`, `import [as]`, and `from M import a, b [as c]`. Three unit tests cover module-level resolution, function-scope shadowing, and `from`-import unpacking. Other languages follow in subsequent releases.

### Changed
- `Lang::Objective_c` → `Lang::ObjectiveC` (Rust naming convention). The display string `objective_c` is unchanged so existing rules / SARIF output keep matching.
- Cleaned all 17 compiler warnings from the lib build (`cargo build --release` now emits 0 warnings). Auto-fix dropped 6 unused imports and 3 unused variables; manual changes resolved 4 unreachable-pattern warnings (collapsed `Format::Sarif | Format::Json` arms in cli.rs) plus 2 unread-assignment warnings.

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
