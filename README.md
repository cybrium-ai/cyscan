# `cyscan` — Cybrium Scan engine

Fast, multi-language static analysis. Rust binary. Runs as the SAST
worker inside the Cybrium platform and as a standalone CLI for
developer / CI use.

```
$ cyscan scan ./src --format text
[high]  CBR-PY-SQLI-STRING-CONCAT  src/db.py:12:5
        String-concatenated SQL into cursor.execute
        │ cursor.execute("SELECT * FROM t WHERE email = '" + email + "'")
        → fix: CWE-89-PARAMETERIZE

[crit]  CBR-SECRETS-AWS-KEY        src/config.py:3:18
        Hardcoded AWS access key
        │ AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"
        → fix: CWE-798-HARDCODED

2 finding(s)
```

## Install

```bash
# From source (for now)
git clone https://github.com/cybrium-ai/cybrium
cd cybrium/scanner
cargo install --path .

cyscan --help
```

Prebuilt binaries for darwin-arm64 / darwin-amd64 / linux-amd64 /
linux-arm64 are planned for the v0.1 tag (see Sprint 32 acceptance).

## Commands

| Command | Purpose |
|---|---|
| `cyscan scan <path>` | Scan a file or directory against the rule pack |
| `cyscan scan <path> --format {text,json,sarif}` | Output format |
| `cyscan scan <path> --rules <dir>` | Use a specific rule pack instead of the bundled default |
| `cyscan scan <path> --fail-on high` | Exit non-zero if any finding is ≥ high severity (for CI) |
| `cyscan rules list` | Print every rule in the pack |
| `cyscan rules validate` | Parse + lint the pack — useful in rule-author CI |

## Rule format

Each rule is a single YAML file:

```yaml
id:        CBR-PY-SQLI-STRING-CONCAT
title:     "String-concatenated SQL into cursor.execute"
severity:  high            # info | low | medium | high | critical
languages: [python]
cwe:       [CWE-89]
fix_recipe: CWE-89-PARAMETERIZE   # cross-links into cybrium-fixes
message:   |
  A SQL query is assembled via string concatenation …

# One of these two must be present. `query` wins if both are set.

# Tree-sitter query — structured, language-aware.
query: |
  (call
    function: (attribute attribute: (identifier) @m (#eq? @m "execute"))
    arguments: (argument_list (binary_operator) @concat))

# Or a regex fallback — runs line-by-line.
regex: |
  cursor\.execute\([^)]*\+
```

### Languages supported in v0.1

- Python
- JavaScript (`.js`, `.mjs`, `.cjs`)
- TypeScript (`.ts`, `.tsx` — currently aliased to the JS grammar)
- Go

Sprint 33 adds Java/Kotlin and C#/Rust/C++.

## Output formats

- `text` — coloured, one-finding-per-block, human-readable. Honours
  `NO_COLOR`.
- `json` — pretty array of Finding records. Stable shape for
  downstream tools.
- `sarif` — SARIF 2.1.0. GitHub Code Scanning and VS Code will render
  these natively.

## Integration with Cybrium

The scan agent runs:

```bash
cyscan scan /repo \
  --rules /opt/cybrium/rules \
  --format sarif \
  --fail-on high \
  > /tmp/findings.sarif
```

The agent's existing SARIF-ingest path consumes the output and the
platform takes over — findings storage, CTEM scoring, AI Fix Bot,
tenant notifications, reports.

## Development

```bash
cargo build            # dev build
cargo test             # integration tests run the binary against tests/fixtures
cargo run -- scan tests/fixtures --format text
cargo build --release  # strip-symbolled, LTO'd, ~15MB static binary
```

## Design principles

- **One parse per file.** Every tree-sitter rule shares the same parse
  tree; regex-only packs don't trigger parsing at all.
- **Stable ordering.** Findings sort severity → file → line so diffs
  between runs are meaningful.
- **Zero-setup defaults.** `cyscan scan .` with no flags Just Works
  using the bundled rule pack.
- **Shell-friendly.** Exit 1 on `--fail-on` match, exit 2 on fatal
  error, exit 0 clean. Makes CI gating trivial.

## License

Apache 2.0.
