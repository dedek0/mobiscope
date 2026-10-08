# ADR-009: Defer ASC (droidasc) integration

## Status

Accepted — the decision *is* the deferral; integration is explicitly out of
scope for now.

## Context

[MG1937/ASC](https://github.com/MG1937/ASC) ships `droidasc` (pip,
v0.1.1.post3, Apache-2.0, deps `androguard>=4.1.3`, `mutf8`): a Python CLI
that extracts Android artifacts *on demand* from a full-DEX probe without
inflating the APK — `getclass`, `listclass`, `getmanifest`, `findrefs`.
Its benchmarks are eye-catching: cross-references for a 352 MB APK in 1.79 s,
a single class in 177 ms from 141 MB.

That matters because mobiscope's Phase 1 runs apktool (10 min timeout) and
jadx (15 min timeout) against every Android target, and the whole run is
gated on them (ADR-008). Anything that shortens Phase 1 looks valuable.

## Decision

**Do not integrate ASC now.** The analysis:

- mobiscope's scanners are tree-shaped consumers, not query-shaped ones:
  gitleaks runs `--source <jadx dir>`, semgrep runs over `<dir>`, and the
  inventory stage tree-walks the decompiled sources with extension and size
  caps. ASC emits no source tree — it answers queries — so it cannot replace
  jadx/apktool in the default pipeline. Wiring it in would buy **zero
  speedup for the standard flow** while adding a second decompilation stack.
- What remains genuinely useful is *additive*, not substitutive:
  - `findrefs` as targeted enrichment for triage/correlation;
  - `listclass` as a cheap obfuscation/renaming signal;
  - `getclass` snippets as LLM triage context without shipping the full tree;
  - an optional future "fast mode" that skips jadx entirely.
- Costs and risks:
  - Young project (0.1.x, ~81 commits): the CLI/API is not stable, so any
    integration would require an exact version pin.
  - Heavy `androguard` dependency tree for a Go binary.
  - A Python CLI inside a Go toolchain — though the Docker image already
    ships `python3` + pip for semgrep, so the marginal cost there is small.

**Revisit only if** (a) a scanning mode that does *not* need a full
decompiled tree is designed, or (b) ASC stabilizes past 0.1.x. The candidate
integration shape when that happens: an optional fail-soft `asc` stage
following the existing wrapper pattern — entry in `allowedBinaries`,
`Available()` via `CheckBinary`, missing binary degrades to a skipped stage
(ADR-006) — with `droidasc==0.1.1.post3` pinned in the Dockerfile.

## Consequences

### Positive

- Phase 1 stays a single, predictable decompilation stack; scanners keep
  their full-tree contract.
- No pin-maintenance burden for an unstable 0.1.x tool; no androguard in the
  image until it earns its place.
- The deferral is conditional and testable: the two revisit triggers (a)/(b)
  are explicit, so "should we add ASC?" has a written answer.

### Negative

- We keep paying jadx's 15-minute worst case on large APKs even though a
  177 ms single-class path exists elsewhere.
- If ASC is never reconsidered, LLM triage context stays limited to whatever
  the full tree provides (per-file caps), missing cheap cross-reference
  enrichment.
- Someone may re-propose the integration without reading this ADR; the
  "zero speedup for the standard flow" argument has to be restated each
  time — this file is the canonical answer.

## References

- https://github.com/MG1937/ASC (droidasc 0.1.1.post3, Apache-2.0)
- internal/analyzers/apktool.go, jadx.go (Phase 1 timeouts)
- internal/analyzers/gitleaks.go, semgrep.go, inventory.go (tree-shaped consumers)
- internal/analyzers/analyzer.go (allowedBinaries / Available pattern)
- internal/pipeline/pipeline.go (phase structure — ADR-008)
- Dockerfile (python3 already present; pin site for `droidasc==0.1.1.post3`)
