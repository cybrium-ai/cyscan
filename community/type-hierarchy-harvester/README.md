# type-hierarchy-harvester

A canonical, ecosystem-wide JSON corpus mapping fully-qualified type
names to their direct parents and interfaces, mined from real package
metadata.

## The problem

Every SAST tool ships a hand-maintained table of known library members:

```rust
// cyscan/src/matcher/semantics.rs:1696
fn known_library_member(receiver_type: &str, method: &str) -> bool {
    matches!(
        (short, method),
        ("SqlCommand", "ExecuteReader" | "ExecuteScalar" | ...)
        | ("PreparedStatement", "execute" | "executeQuery" | ...)
        | ...
    )
}
```

Semgrep, Snyk Code, CodeQL, Checkmarx, Bandit, gosec, ESLint security
plugins — all of them have a version of this table. **Every one is
manually curated, incomplete, and inconsistent.** When a rule says
"flag any `DbCommand.Execute` call", the engine has to know that
`SqlCommand : DbCommand`. Today every engine answers that question
differently, often wrongly.

## The deliverable

A versioned JSON corpus shipped per ecosystem:

```
corpus/
  java/maven-top-1000.json
  csharp/nuget-top-1000.json
  python/pypi-top-1000.json
  javascript/npm-top-1000.json
  go/proxy-top-1000.json
  rust/crates-top-1000.json
  ruby/gem-top-500.json
  php/packagist-top-500.json
```

Schema ([formal definition](./schema.json)):

```json
{
  "ecosystem": "csharp",
  "package": "Microsoft.Data.SqlClient",
  "version": "5.2.0",
  "harvested_at": "2026-05-02T00:00:00Z",
  "harvester": "csharp/v0.1.0",
  "types": {
    "Microsoft.Data.SqlClient.SqlConnection": {
      "parents":  ["System.Data.Common.DbConnection"],
      "interfaces": ["System.IDisposable", "System.ICloneable"],
      "kind": "class"
    },
    "Microsoft.Data.SqlClient.SqlCommand": {
      "parents":  ["System.Data.Common.DbCommand"],
      "interfaces": ["System.IDisposable", "System.ICloneable"],
      "kind": "class",
      "methods": {
        "ExecuteReader":   { "returns": "Microsoft.Data.SqlClient.SqlDataReader" },
        "ExecuteScalar":   { "returns": "object" },
        "ExecuteNonQuery": { "returns": "int" }
      }
    }
  }
}
```

## Why JSON-per-package, not a single mega-file

- Diffable: a new package version is one file changed, not 100MB rewritten.
- Selectively loadable: a Rust scanner only needs the imports it sees.
- License attribution: each file carries the source package's license.
- Reproducible: the harvester output is deterministic per (package, version).

## Coverage targets (v1)

| Ecosystem | Source | First 1000 picked by |
|---|---|---|
| Java | Maven Central | download count, last 90 days |
| C# | NuGet | download count, last 90 days |
| Python | PyPI | download count, last 30 days (PyPI BigQuery) |
| JavaScript / TypeScript | npm | download count, last 30 days |
| Go | proxy.golang.org | unique import count |
| Rust | crates.io | recent download count |
| Ruby | RubyGems.org | total downloads |
| PHP | Packagist | install count |

For Java / C# the harvester reads compiled metadata directly (class
files / assembly metadata) — fully accurate. For dynamically-typed
languages we mine the source under the same regex patterns cyscan's
own `extract_*` already uses, then deduplicate against the package's
declared `__all__` / `module.exports`. The methodology is documented
in [METHODOLOGY.md](./METHODOLOGY.md).

## Per-language harvesters

Each lives in `harvesters/<lang>/`. Each is a small standalone tool
that takes a list of packages and produces JSON:

```
$ harvesters/csharp/run --packages packages.txt --out corpus/csharp/
```

This means contributors can add a new ecosystem by writing **one
harvester** without touching the rest of the codebase.

## How cyscan consumes it

The corpus is loaded once at scanner start-up into the existing
`type_hierarchy: HashMap<String, Vec<String>>` indexes inside
`ProjectSemantics`. Per-rule receiver-type filters then walk the
corpus-augmented hierarchy automatically. **No rule changes required.**

For other tools the JSON is plain — a Python or TypeScript SAST tool
can load `corpus/python/pypi-top-1000.json` directly and answer
"is `psycopg2.extensions.connection` a `DBAPIConnection`?" without
reinventing the harvester.

## Status

**Spec v0.1 — implementation pending.** First milestone: ship the C#
harvester and seed the NuGet top-100. C# was picked first because (a)
assembly metadata is fully accurate, no inference needed, and (b) it
gives the immediate win on the false-positive class cyscan documented
in v0.21.0 (`Microsoft.Data.SqlClient.SqlConnection` vs local class
`SqlConnection`).

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). The review bar for new
corpus entries is "does the resolution chain match the package's
publicly documented hierarchy at the version listed."

## License

Apache-2.0 for the harvester code. Each corpus JSON file carries the
upstream package's license in its `license` field — corpus entries
inherit that license.
