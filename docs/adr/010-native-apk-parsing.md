# ADR-010 — Read Android facts in-process instead of trusting a decompiler

**Status:** accepted · 2026-10-30

## Context

Every Android finding used to flow through `jadx` or `apktool`: the manifest
reader, the network security config reader, the pattern scanner and the
inventory all resolved `analyzers.SourceRoot` (`jadx/` → `apktool/` → session
root). That made the core checks depend on the slowest and most fragile part
of a run. A decompiler OOM on a large APK removed the manifest, permissions,
NSC and secret findings at once; `--stages inventory` on a fresh session
produced nothing useful.

The artifact already contains everything needed for those checks:
`AndroidManifest.xml` is compiled binary XML (AXML), resources are in
`resources.arsc`, and the DEX files carry a complete string pool.

## Decision

`inventory` reads the APK directly and uses the decoded tree only as a
fallback:

1. **AXML parser** (`internal/analyzers/axml.go`). Decodes the chunked binary
   format: string pool (UTF-8 and UTF-16), resource map, start/end element,
   namespaces, typed values and CDATA.
2. **`resources.arsc` parser** (`arsc.go`). Resolves the resource IDs carried
   by manifest attributes (`@xml/…`, `@string/…`) to their string value. Only
   the string/int/bool forms are decoded; complex entries (bags) are skipped.
3. **Native manifest** (`native_manifest.go`). Converts the AXML tree into the
   same `androidManifest` struct that `encoding/xml` produces for a decoded
   manifest, so every existing check (including the `targetSdk`-aware ones)
   runs unchanged.
4. **DEX string scanner** (`dexscan.go`). Extracts the string pool of every
   `classes*.dex` and runs `scanRules`, URL/IP/e-mail aggregation and pinning
   markers. Tree hits and DEX hits are deduplicated by category + evidence;
   DEX aggregates are merged only when the tree produced none, so a normal
   run does not double-count.
5. **Full NSC parse** (`nsc.go`). Parses base and per-domain configs,
   `debug-overrides`, `overridePins`, `pin-set`/expiration and trust anchors,
   for both decoded XML and compiled binary XML.

The fallback is explicit: if the archive cannot be opened, the binary manifest
cannot be parsed, or the caller only has a session directory (`Analyze` without
`AnalyzeTarget`), the previous tree-based path runs unchanged.

## Consequences

- Manifest, permission, NSC and secret checks work with `--stages inventory`,
  no decompiler, and on an APK that makes `jadx` OOM.
- More in-process parsing code: two binary formats and their bounds checks.
  Both parsers treat every length as untrusted and refuse implausible tables.
- DEX findings use `classes.dex` + string index as the location. They are
  deterministic but do not point at a source line; evidence is the matched
  string. A tree hit with the same category + evidence suppresses the DEX hit.
- Resource references that cannot be resolved stay as `@0x…`; that only
  affects display, not the checks.
- Finding IDs for the native path stay stable: manifest/NSC findings keep
  `AndroidManifest.xml` / `res/xml/…` as the file and the same snippets as
  before (ADR-002).

## Alternatives considered

- **Keep parsing only the decompiled tree.** Rejected: it keeps the core
  checks hostage to a 15-minute external tool and leaves `--quick`/`inventory`
  nearly empty.
- **Shell out to `aapt`/`apkanalyzer`.** Rejected: a new binary on the
  allowlist, another version to pin, and the Docker image does not ship it.
- **A third-party Go AXML/arsc library.** Rejected for now: the formats are
  small, the parser needs to be hardened against hostile input, and keeping it
  in-tree avoids a dependency whose failure modes we cannot control.
