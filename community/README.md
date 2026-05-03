# cyscan / community

Open-source contributions cyscan is incubating for the broader SAST and
security-tooling community. Each sub-project lives in its own directory
with its own README, schema, and contribution guide.

These are intentionally **scope-limited reference implementations**, not
products. The goal is to give other security tools — open or closed
— a shared substrate to depend on, the same way `tree-sitter`,
`jsonschema`, or `OSV` give the ecosystem a shared substrate today.

## Active sub-projects

| Sub-project | Status | What it gives the ecosystem |
|---|---|---|
| [type-hierarchy-harvester](./type-hierarchy-harvester/) | spec | A canonical JSON corpus mapping `fully.qualified.Class` → its parent types and interfaces, mined from real package metadata across popular ecosystems. Replaces every SAST tool's hand-maintained `known_library_member` table. |
| [dsl-conformance](./dsl-conformance/) | spec | A portable YAML test corpus that exercises every Semgrep DSL operator across every shipped engine behaviour. Any SAST engine — cyscan, custom in-house engines, future re-implementations — can claim "passes the conformance suite at version X." |

## Why these two first

Both are concrete deliverables (~2 weeks each), have **no existing peer
in the ecosystem**, and benefit cyscan immediately while the corpus is
being built. They turn cyscan from "another SAST scanner" into "the
reference implementation for X" — which is a more durable position than
feature-by-feature parity races against commercial vendors.

## Contributing

Open a PR against this repo. Each sub-project has its own
`CONTRIBUTING.md` describing the schema, the test fixtures, and the
review bar. Quality > coverage — a small corpus that's verified
correct beats a large corpus that's wrong.

## Future sub-projects

Tracked here so contributors can pick them up:

- **hard-sast-corpus** — ~50 cases that every commercial tool currently
  misses or mis-labels. Hibernate criteria builder taint, JS prototype
  pollution through lodash, Python `__getattr__` sink-hiding,
  C# extension-method shadows, Ruby `method_missing` dispatch,
  Rust `Deref`-chain method resolution.
- **reachability-ground-truth** — curated OSS repos with hand-labelled
  CVE reachability, so reachability claims (Endor / Backslash style)
  have a public benchmark. ~200 repos.
- **ai-generated-code-fpr** — measure SAST FPR/FNR on AI-generated
  code (Cursor / Claude / Copilot outputs for OWASP Top 10 prompt
  set). Probably reveals new false-positive classes that need new
  operators.
- **cyscan-engine** — pull cyscan's matcher + dataflow + symbol-table
  layer out into a published Rust crate that other security tools
  can consume directly.

## License

Apache-2.0 (matches cyscan). Contributions imply the same license.
