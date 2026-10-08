# ADR-008: Parallel pipeline phases

## Status

Accepted

## Context

A run mixes two very different kinds of work: decompilers that are slow and
independent of each other (apktool 10 min / jadx 15 min timeouts on every
Android target, ipa-extract on every IPA), and scanners that can only read
what the decompilers wrote. Findings also arrive more than once on iOS,
because the inventory phase re-runs the plist/codesign/macho converters on
the same bundle, and artifacts must stay byte-stable across runs for
diffing and caching (ADR-002).

## Decision

`Pipeline.Run` (internal/pipeline/pipeline.go) executes fixed phases:

1. **Phase 1 — extractors/decompilers** (`apktool`, `jadx`, `ipa-extract`):
   independent, run concurrently in an `errgroup` bounded by
   `MaxConcurrency` (default 4, `pipeline.max_concurrency`,
   `--max-concurrency`). Each analyzer applies its own timeout via the
   command runner (ADR-005); the pipeline has no global timeout — only
   SIGINT/SIGTERM cancel the shared context.
2. **Phase 2 — scanners** (`gitleaks`, `semgrep`, `plist`, `macho`,
   `codesign`, `strings`, `classdump`): starts only after phase 1 has fully
   drained (even on error), because they read extractor output; same
   concurrency bound; skipped if the context was cancelled.
3. **Phase 3 — inventory** (sequential, in-process, no binary): Android
   `inventory` or iOS `inventory-ios`, unless `--stages` excludes
   `inventory`.
4. **Phase 4 — dedup**: exact key
   `category|file|line|hex(sha256(snippet)[:8])` removes the duplicates the
   iOS inventory phase deliberately reintroduces.
5. **Phase 5 — clustering**: `cl-` + 16 hex chars of
   sha256(`tool|category|lower(title)|file-ext`); the first member by
   (file, line) becomes `representative` and the only member with
   `needs_llm_triage` — no LLM calls happen here.
6. **Phase 6 — sort** by severity, then file, then line, then the code's
   "Phase 3b": write `inventory.json`, collect the signing identity
   (apksigner, Android only) onto the session.
7. **Phase 7 — persistence**: `meta.json`, then `findings.json`,
   `report.md`, `session.json`, `report.sarif` (re-run after `--triage`).

Determinism: analyzers write into a pre-sized `runs` slice indexed by
registration order, so `tool_results` and pre-sort finding order do not depend
on scheduling; `buildAnalyzers` fixes the registration order. Dry-run mode
returns early with `status: pending` and per-stage availability.

`--fail-fast` records the first error in registration order, marks the
session `failed` and makes `Run` return an error (after artifacts are still
written); it does **not** cancel tools already running — phases 2/3 and
persistence still execute, since no errgroup context is cancelled.

## Consequences

### Positive

- The slow, CPU-heavy decompilers overlap instead of serializing (up to
  `MaxConcurrency` at once).
- Scanners are guaranteed to see complete extractor output — no read-while-
  writing races on the jadx/extract trees.
- Dedup-after-inventory lets iOS reuse the plist/codesign/macho converters
  without double-reporting.
- Artifacts are reproducible: registration-order collection plus explicit
  sort beats map iteration order everywhere.

### Negative

- Every scanner waits for the *slowest* decompiler; a 15-minute jadx
  idle-parks gitleaks/semgrep even though they only need the tree to exist.
- Inventory is independent of the scanners but is serialized after them; it
  could run in phase 2's group (left as future work).
- Fail-fast is weaker than advertised: it changes status/exit code but lets
  already-launched tools run to completion — real cancellation only comes
  from signals.
- The phase list is hard-coded (`selectByName` name lists); a new stage name
  silently lands in neither group and would never execute (it must be added
  to the phase-1 or phase-2 selection, or wired like inventory).

## References

- internal/pipeline/pipeline.go (Run, runGroup, phases 1-7, PersistArtifacts)
- internal/pipeline/dedup.go (Dedup, Cluster, PropagateClusterVerdicts)
- internal/pipeline/triagecontext.go (post-triage context)
- cmd/mobiscope/analyze.go (buildAnalyzers registration order, --fail-fast, --max-concurrency)
- internal/analyzers/apktool.go / jadx.go (per-tool timeouts)
- ADR-002 (deterministic finding IDs), ADR-005 (per-tool exit codes)
