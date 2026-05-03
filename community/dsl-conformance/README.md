# dsl-conformance

A portable YAML test corpus that exercises every Semgrep DSL operator
against a small, hand-verified source fixture. Any SAST engine —
cyscan, custom in-house engines, future re-implementations — can
declare "passes the conformance suite at version X" by running the
corpus and checking that the actual matches equal the expected ones.

## The problem

The Semgrep DSL is the de-facto syntax for cross-engine rule authoring.
Multiple engines now claim to support it: Semgrep OSS, Semgrep Pro,
cyscan, several closed-source tools. **None of them agree on edge
cases.** Operators interact in subtle ways:

- Does `metavariable-pattern` honour `metavariable-comparison` on the
  same capture?
- When both `pattern-not-inside` and `pattern-either-groups` apply,
  in what order are they evaluated?
- Does `pattern-where` short-circuit on `false and ...`?
- Does `metavariable-receiver-type` walk the type hierarchy before or
  after substring matching?

There's no public test that answers these. Every engine guesses.

## The deliverable

A directory of YAML files, one per operator-behaviour-case:

```
operators/
  metavariable-pattern/
    01-regex-flavour-substring.yml
    02-regex-flavour-anchor.yml
    03-nested-ast-cross-language.yml
    04-interaction-with-comparison.yml
  metavariable-receiver-type/
    01-direct-binding.yml
    02-shadow-suppresses-outer-match.yml
    03-cross-file-class-hierarchy.yml
    04-substring-match-either-direction.yml
  pattern-where/
    01-basic-and-or.yml
    02-not-with-grouping.yml
    03-keyword-collision-contains-and.yml
  ...
```

Each file is self-contained:

```yaml
# Conformance test schema v0.1
test_id: metavariable-receiver-type/02-shadow-suppresses-outer-match
description: |
  Inner block declares a String shadow of an outer Connection variable.
  The receiver-type filter on java.sql.Connection should match the OUTER
  call but NOT the INNER one — even though the method-name regex matches
  both.
language: java
source: |
  import java.sql.Connection;
  class App {
      void run(Connection makeConn) {
          Connection conn = makeConn;
          conn.prepareStatement("SELECT outer");   // should match
          if (true) {
              String conn = "shadowed";
              conn.prepareStatement("SELECT inner"); // should NOT match
          }
      }
  }
rule:
  id: TEST-RECV-SHADOW
  severity: high
  languages: [java]
  regex: '(\w+)\s*\.\s*prepareStatement\('
  metavariable_receiver_type:
    match:
      - java.sql.Connection
  message: matched
expected:
  - line: 5
    snippet_contains: "SELECT outer"
  - not_line: 8
    snippet_contains: "SELECT inner"
```

The schema is defined in [schema.md](./schema.md).

## How engines run it

A reference runner ships with cyscan that consumes the YAML, invokes
the engine, and asserts. Other engines write their own runner — the
YAML format is engine-agnostic.

```
$ cyscan conformance run community/dsl-conformance/operators/
operators/
  metavariable-pattern         (12/12 passing)
  metavariable-receiver-type   ( 8/8  passing)
  pattern-where                ( 6/6  passing)
  pattern-not-inside           ( 5/5  passing)
  pattern-either-groups        ( 4/4  passing)
  ...
Total: 73/73 passing
```

Engines that don't support a given operator skip its directory entirely
and report skip count in their conformance badge:

```
cyscan v0.23.0:        73/73 passing, 0 skipped
semgrep-oss v1.50.0:   65/73 passing, 8 skipped (metavariable-receiver-type, metavariable-analysis)
hypothetical-tool v2:  58/73 passing, 15 skipped, 0 failing
```

## Coverage targets (v1)

Every operator cyscan ships, mapped to its current cyscan release:

| Operator | Tests | First shipped in |
|---|---|---|
| `pattern` | 4 | v0.11 |
| `patterns` (and-of) | 3 | v0.11 |
| `pattern-either` | 3 | v0.11 |
| `pattern-either-groups` | 4 | v0.13 |
| `pattern-not` | 2 | v0.11 |
| `pattern-inside` | 3 | v0.13 |
| `pattern-not-inside` | 5 | v0.13 |
| `pattern-not-regex` | 3 | v0.13 |
| `metavariable-comparison` | 4 | v0.13 |
| `metavariable-comparisons` (list) | 3 | v0.13 |
| `metavariable-regex` | 3 | v0.13 |
| `metavariable-pattern` (regex) | 4 | v0.13 |
| `metavariable-pattern` (nested AST) | 3 | v0.20 |
| `metavariable-pattern` (cross-language) | 2 | v0.20 |
| `metavariable-types` | 3 | v0.13 |
| `metavariable-analysis` redos | 4 | v0.19 |
| `metavariable-analysis` entropy | 4 | v0.19 |
| `metavariable-receiver-type` | 8 | v0.21 |
| `pattern-where` | 6 | v0.20 |

Plus interaction tests in `operators/_interactions/` — the cases
where multiple operators apply to the same rule and order matters.

## Why YAML, not JSON

Rule authors already write Semgrep rules in YAML. Block-literal `|`
preserves source code formatting cleanly. Comments are supported.
Engine implementers import their existing YAML rule loader.

## Status

**Spec v0.1 — corpus pending.** First milestone: extract cyscan's
existing 38 integration tests into operator-bucketed conformance
files. That gives ~38 cases at ship and proves the runner works
against a real engine.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). The review bar is:

1. The expected output is hand-verified — at least one human ran the
   case mentally and confirmed the rule should fire / not fire.
2. The fixture is minimal — strip everything that isn't load-bearing
   for the operator being tested.
3. The case has a written rationale — why does this case exercise
   this operator's edge case, not some generic property.

## License

Apache-2.0. Each test fixture's source code is contributed under the
same license.
