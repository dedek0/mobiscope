# ADR-009: Pluggable decompiler backends

## Status

Accepted — the `dexdc` backend is implemented as an opt-in stage and the
differential harness is available (`scripts/evaluate-decompiler.py`).
`jadx` remains the default until that harness passes on the target artifacts.

## Context

`jadx` is the only tree producer in the default Android pipeline. Every
tree-shaped stage (`gitleaks`, `semgrep`, `inventory`, LLM triage context)
depends on it, and the pipeline runs it with a 15-minute timeout. On large
APKs it can exhaust the JVM heap and take the whole scan down with it. The
same applies to `apktool` for resources.

A pure-Rust alternative now exists:
[`androguard/dex-decompiler`](https://github.com/androguard/dex-decompiler)
(Apache-2.0). It offers:

- full-tree `.java` export (`-d out/`) under package directories;
- a query fast path (`--getclass`, `--findrefs`) without a global index;
- built-in `--scan-vulns`, `--scan-semgrep` (MASTG) and `--taint-solve`
  (Mariana Trench-style interprocedural taint);
- a Rust library API and Python bindings;
- no JVM and a lower memory footprint than `jadx`.

It does **not** decode `res/` or `resources.arsc`, so it cannot replace
`apktool` for resource-derived checks (network security config, decoded
strings, layouts). Those need either `apktool` or the native AXML/`arsc`
parser planned in the roadmap.

## Decision

1. Treat the decompiled tree as a **backend**, not as a hardcoded `jadx`
   directory.
2. Keep `jadx` as the default and as the reference implementation.
3. Add an **optional** `dexdc` backend (CLI wrapper, phase `decompiler`) that
   can be selected with `--decompiler dexdc`, `--decompiler jadx,dexdc` or the
   matching `--stages` entry. `both` keeps its historical `apktool+jadx`
   meaning; a comma-separated list selects any mix.
4. The backend is fail-soft: a missing binary or a failed export is recorded
   as a failed tool, never as a pipeline error (ADR-005/ADR-006).
5. `SourceRoot` resolves the tree with the fixed preference
   `jadx → apktool → dexdc → session root`. A `jadx,dexdc` run therefore scans
   the jadx tree (the reference) and never mixes the two output formats.
6. Resource decoding no longer needs `apktool`: the native AXML/`arsc` reader
   in `inventory` covers the manifest, network security config and resource
   references. A `dexdc`-only run still gets those checks.
7. Security output from the backend (`--scan-vulns`, `--taint-solve`) is
   planned as an additional `SourceTool=dexdc` finding source. The converters
   stay out of the default path until the differential evaluation passes.

## Evaluation gate

Before `dexdc` can become the default (`--fast`), a differential harness must
compare it with `jadx` on the same APK:

| Metric | Target |
|--------|--------|
| Recall of known findings | ≥ 95% of the `jadx` run |
| Semgrep parse-error rate | < 5% |
| Full-tree export time (230 MB APK) | < 30 s |
| Peak RSS | < 1 GB |
| Deterministic finding IDs | stable or explicitly migrated |
| `--findrefs` on 20 known sinks | correct class/method |

The harness is `scripts/evaluate-decompiler.py` (manual runbook, not part of
the default `go test` path). It records wall time, decompiler time, peak RSS,
finding counts, a category+title+evidence recall, strict fingerprint overlap
and semgrep error notifications.

## Consequences

### Positive

- The slowest stage becomes replaceable without touching the scanners.
- The project gains a path to a tree-free fast mode and cheap cross-reference
  context.
- Taint analysis becomes available as a first-class (optional) source.
- No JVM dependency is introduced for the fast path.

### Negative

- Two decompiler stacks must be maintained during the transition.
- The candidate is young (0.1.x, no published releases); output and rule
  semantics can change. Pin an exact commit and `Cargo.lock`, run
  `cargo audit`, and keep the build in a separate Docker stage.
- Pseudocode that `semgrep` cannot parse produces silent false negatives,
  which is why the parse-error metric is a gate, not a nice-to-have.
- Backend-specific file/line locations can change deterministic finding IDs
  (ADR-002). A migration decision is required before switching defaults.

## References

- https://github.com/androguard/dex-decompiler (Apache-2.0)
- `internal/analyzers/analyzer.go` (`Phase`, `allowedBinaries`, `SourceRoot`)
- `internal/pipeline/pipeline.go` (phase execution, `FindingConverter`)
- `docs/roadmap.md` (P1 native parsing, P2 coverage)
