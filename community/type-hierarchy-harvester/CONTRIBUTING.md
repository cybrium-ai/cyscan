# Contributing to type-hierarchy-harvester

## Adding a new harvester

A harvester is a small standalone tool that takes a list of packages
and produces JSON conforming to [schema.json](./schema.json). It lives
in `harvesters/<lang>/` and ships its own README documenting how to
run it.

The bar for accepting a new harvester:

1. **Determinism.** Running the harvester twice on the same package
   version produces byte-identical JSON.
2. **Source faithfulness.** For Java/C# (compiled-metadata languages)
   the harvester reads the actual class files / assembly. For
   Python/JS/Ruby/PHP/Go/Rust (source languages) the harvester reads
   the package source and matches the same patterns cyscan's
   `extract_*` already uses, then deduplicates against the package's
   declared exports.
3. **License attribution.** Each output JSON file includes the
   upstream package's SPDX license. Corpus consumers inherit it.
4. **Bounded coverage.** First milestone for a new ecosystem is the
   top-100 packages by download count. We expand to top-1000 only
   after the harvester is stable and the corpus has been spot-checked.

## Adding corpus entries

PRs adding new package entries to an existing ecosystem go through
the harvester. **Do not hand-edit corpus JSON.** If you found a
hierarchy bug, fix the harvester or open an issue with the package
+ version + observed-vs-expected.

## Verification

Each new entry is spot-checked against the upstream package's public
documentation (e.g. Microsoft Docs for .NET, Javadoc for Java
Maven Central packages). The reviewer comment must include a link
to the documentation source for at least one type per file.

## Coverage gaps

Open issues are tagged by ecosystem. Pick one and ship a harvester.
If the ecosystem you want isn't tagged, open a discussion first —
some ecosystems (Kotlin, Dart, Elixir) have non-trivial type
systems that need a design pass before a harvester is worth writing.
