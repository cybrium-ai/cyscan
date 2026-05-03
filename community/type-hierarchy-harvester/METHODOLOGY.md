# Harvester Methodology

How each ecosystem's harvester resolves the hierarchy. Documented
here so corpus consumers know what guarantees they're getting.

## Compiled-metadata languages

These languages publish typed binary artefacts. The harvester reads
metadata directly — fully accurate, no inference.

### Java

Source: Maven Central. Harvester downloads the `*.jar`, walks
`META-INF/MANIFEST.MF` + every `.class` file using ASM
(or equivalent). Records `super_class`, `interfaces`, generics
signature.

- Resolution accuracy: **100%** of declared hierarchy.
- Method bodies: not read — methods listed by signature only.
- Generics: type parameters preserved verbatim from the bytecode
  signature attribute.

### C#

Source: NuGet. Harvester downloads the `.nupkg`, extracts every
assembly, walks metadata via `Mono.Cecil` (or the .NET
`System.Reflection.Metadata` API).

- Resolution accuracy: **100%** of declared hierarchy.
- Properties listed under `methods` with `get_*` / `set_*`
  prefixes.
- Generics: same as Java — preserved from metadata.

## Source-mined languages

These ecosystems publish source, not compiled metadata. The
harvester runs the same regex extraction cyscan's per-language
`extract_*` already uses, then validates against the package's
declared export surface.

### Python

Source: PyPI sdist (preferred over wheels — wheels often ship
compiled-only `.so` / `.pyd` for native modules; sdists ship `.py`).

- Pattern: `class Foo(Bar, Baz):` → `Foo` parents = `[Bar, Baz]`.
- Resolution accuracy: **~95%**. Misses dynamic class creation
  (`type(name, bases, dict)`), metaclass-injected hierarchies,
  and decorator-rewritten classes.
- Type-parameter detection: not yet implemented (PEP 695 generics
  pending).

### JavaScript / TypeScript

Source: npm tarball. For TypeScript packages, the harvester reads
`*.d.ts` declaration files (fully accurate). For pure JavaScript,
it reads source.

- TypeScript: **~99%** accuracy via `.d.ts`.
- JavaScript: ~85%, declines on packages using runtime class
  factories.
- Prefers `package.json` `types` / `typings` field when present.

### Go

Source: `proxy.golang.org`. Reads `.go` source for type
declarations. Go has no inheritance, but interfaces and embedded
structs produce hierarchy edges:
`type Foo struct { Bar }` → `Foo` parents = `[Bar]`.

- Resolution accuracy: **~98%** for declared types — Go's syntax
  is regular enough that the regex extraction is reliable.

### Rust

Source: crates.io. Reads `.rs` source. Rust hierarchy is via
trait `impl` blocks, not classes:
`impl Trait for Foo { ... }` → `Foo` interfaces = `[Trait]`.

- Resolution accuracy: **~95%**. Misses generic blanket impls
  (`impl<T: Display> Trait for T`) — those are recorded
  separately as "blanket trait impls" rather than per-type
  parents.

### Ruby / PHP

Source: RubyGems / Packagist. Reads source.

- Ruby pattern: `class Foo < Bar`, `module Foo` → recorded.
- PHP pattern: `class Foo extends Bar implements I, J` →
  recorded.
- Resolution accuracy: **~90%**. Both languages allow runtime
  class re-opening / monkey-patching that the harvester doesn't
  follow.

## Versioning

The harvester version (`harvester: csharp/v0.1.0`) is bumped
whenever the resolution methodology changes. Older corpus entries
keep their original methodology version recorded so consumers can
trust the methodology that was used at harvest time.

## What the corpus does NOT cover

- **Method-body taint behaviour.** The corpus records hierarchy +
  signatures; it does NOT record sanitiser/source classification of
  individual library methods. That's a separate corpus
  (`taint-classification`, future sub-project).
- **Cross-package inheritance from third-party.** If `package-A`
  declares `class Foo : ExternalPackage.Bar`, the corpus entry for
  package-A records `ExternalPackage.Bar` as a parent — but does
  NOT include Bar's own hierarchy. Consumers stitch packages
  together by loading both files.
- **Private types.** The harvester records public surface only.
  Internal classes are intentionally excluded.
