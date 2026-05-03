# Conformance Test Schema (v0.1)

Each test file is a single YAML document with the following keys.

## Required

### `test_id` — string

Stable, human-readable identifier. Convention:
`<operator-name>/<NN>-<short-description>`. Example:
`metavariable-receiver-type/02-shadow-suppresses-outer-match`.

The runner uses this for filtering and reporting. Renaming a
`test_id` breaks downstream conformance dashboards.

### `description` — string (block scalar `|` recommended)

What the test exercises and why. **Mandatory.** Reviewers reject
PRs without rationale — the corpus is meant to teach engine
implementers what each case is testing, not just whether they pass.

### `language` — string

Source-language identifier for the fixture. Use the lowercase
`Lang::name()` convention: `python`, `javascript`, `typescript`,
`java`, `csharp`, `go`, `rust`, `php`, `ruby`, `swift`, `scala`,
`c`, `bash`, `generic`.

### `source` — string (block scalar `|`)

The fixture source code. Lines are 1-indexed in the `expected`
section. The first line of the block scalar is line 1.

### `rule` — object

The rule under test, in Semgrep DSL form. Engines load this with
their existing YAML rule loader. Keys correspond 1:1 to Semgrep
operator names; cyscan-specific extensions are documented under
`extensions:` (see below).

### `expected` — array

The matches the engine MUST emit. See "Match assertions" below.

## Optional

### `multi_file` — object

When set, the fixture is multi-file. `source` is ignored; the
contents of this object replace it:

```yaml
multi_file:
  files:
    A.cs: |
      class A : B { void run() { ... } }
    B.cs: |
      class B { ... }
```

Used for cross-file class hierarchy and import-resolution tests.

### `extensions` — array of strings

Operator names this test depends on that aren't in the Semgrep OSS
core. Engines that don't support an extension SKIP the test rather
than fail it. Recognised values:

| Extension | Source |
|---|---|
| `metavariable-analysis-redos` | Semgrep Pro |
| `metavariable-analysis-entropy` | Semgrep Pro |
| `metavariable-receiver-type` | cyscan v0.21+ |
| `pattern-where` | Semgrep beta + cyscan v0.20+ |

### `tags` — array of strings

Free-form tags for filtering. Conventional tags:

- `interaction` — exercises multiple operators together
- `edge-case` — tests a corner cyscan or Semgrep got wrong historically
- `cross-file` — requires multi-file fixture

## Match assertions

The `expected` array is interpreted match-set semantics: the engine's
emitted findings, when filtered to the test's `rule.id`, must equal
this set. Element order is irrelevant.

Each element is one of:

### Positive assertion

```yaml
- line: 5
  column: 9                         # optional
  snippet_contains: "SELECT outer"  # optional substring check
  capture:                          # optional metavar checks
    match: "conn"
```

The runner asserts: there exists a finding at `(line[, column])`
whose snippet contains the given substring AND whose capture map
matches.

### Negative assertion

```yaml
- not_line: 8
  snippet_contains: "SELECT inner"
```

Asserts: no finding exists at `not_line` whose snippet contains
the substring. Useful for shadowing tests where the same regex
matches multiple lines but only some should fire.

### Set assertion

```yaml
expected_count: 3
```

Asserts the engine emitted exactly N findings for this rule. Use
when individual line numbers aren't load-bearing — only the
**count** matters.

## Engines and skipping

Engines without a given operator skip the test entirely. Skipped
tests don't contribute to pass-rate, but the runner reports
skip counts so dashboards stay honest:

```
semgrep-oss: 65/73 passing, 8 skipped (metavariable-receiver-type, metavariable-analysis)
```

A test author can mark a test as semgrep-oss-incompatible by
listing the operator under `extensions`. If the test happens to
work in semgrep-oss anyway, that's a runner-side override, not
a schema concern.

## Versioning

The schema itself is versioned at the top of this file. Breaking
changes (renaming required keys, changing assertion semantics)
bump the major version and the corpus directory version-suffixes:
`operators-v1/`, `operators-v2/`. Engines pin to a corpus version.

## Reference implementation

cyscan ships `cyscan conformance run <dir>` which loads the YAML,
invokes the matcher, and prints a per-test result. Other engines
are encouraged to write their own runner — the format is
engine-agnostic. A minimal Python runner template lives at
`runners/python-template/`.
