# Decompiler backend evaluation runbook

Manual runbook for [ADR-009](adr/009-decompiler-backends.md). This is **not**
part of `go test` or CI: the result depends on the artifact, the host memory
and the optional scanner binaries. `jadx` remains the default until the gate
below passes.

## Status (2026-10-30)

- `dexdc` wrapper and `scripts/evaluate-decompiler.py` are implemented.
- The first differential attempt on a very large target did **not** pass:
  `jadx` and `dexdc` each exceeded a 5 GB container limit and were killed
  before completing; the recall measured from the partial trees is not a
  decision input.
- `dexdc` restricted to the app package still took ~4 minutes and ~3 GB RSS
  and panicked on some non-ASCII string literals (while exiting 0).
- Conclusion: the 1 GB / 30 s gate is open; `jadx` stays default and `--fast`
  stays disabled.
- No artifact-specific names, reports or benchmark outputs are committed.

## Before the next run

1. Prefer a **small artifact**: a few DEX files and roughly < 100 MB. If the
   target is larger, use a host with **more than 8 GB RAM** and no other heavy
   containers.
2. Build `dex-decompile` from a pinned commit with Rust ≥ 1.88 (the `time`
   crate used by the dependency tree rejects 1.85):

   ```bash
   PIN=f7fa4a4853d957ebc3c54355d128a3835ef5ae22
   docker run --rm -v "$PWD/dexdc-build:/out" rust:1.88-bookworm bash -c "
     set -e
     apt-get update -qq && apt-get install -y -qq git >/dev/null
     git init -q /src && cd /src
     git remote add origin https://github.com/androguard/dex-decompiler.git
     git fetch -q --depth 1 origin $PIN
     git checkout -q FETCH_HEAD
     export PATH=/usr/local/cargo/bin:\$PATH
     cargo build --release --bin dex-decompile
     cp target/release/dex-decompile /out/dex-decompile
   "
   ```

3. Put `dex-decompile` on `PATH` and confirm `jadx`, `gitleaks` and `semgrep`
   are available (the harness records their findings and semgrep errors).
4. Do not commit the artifact, generated trees or the evaluation report.

## Run

```bash
scripts/evaluate-decompiler.py <artifact.apk> \
  --workdir targets/eval \
  --json targets/eval/report.json \
  --stages inventory,gitleaks,semgrep
```

On a memory-constrained host, cap jadx and the container. `jadx` uses
`MOBISCOPE_JADX_THREADS`; `JAVA_OPTS` controls the JVM heap.

```bash
JAVA_OPTS=-Xmx4g MOBISCOPE_JADX_THREADS=4 \
  scripts/evaluate-decompiler.py <artifact.apk> --workdir targets/eval
```

The harness writes one session per backend and reports:

- wall time, decompiler time and peak RSS;
- finding counts and recall by category+title+evidence;
- strict fingerprint overlap;
- semgrep error notifications;
- PASS/FAIL for the ADR-009 acceptance checks.

## Gate (must all pass)

| Metric | Target |
|--------|--------|
| Recall of known findings | ≥ 95% of the `jadx` run |
| Semgrep parse-error rate | < 5% |
| Full-tree export time | < 30 s |
| Peak RSS | < 1 GB |
| Finding IDs | stable or explicitly migrated |
| `--findrefs` on 20 known sinks | correct class/method |

Also verify output completeness: `dexdc` can panic on non-ASCII literals and
still exit 0. Check the generated Java file count, the backend's stderr and
the number of semgrep errors, not only `exit_code`.

## If the gate passes

1. Promote `dexdc` to the default (or gate it behind `--fast`) and update the
   default in `buildAnalyzers`.
2. Decide finding-ID compatibility (normalize locations to class/method or
   document the migration; ADR-002).
3. Wire `--scan-vulns` and `--taint-output` converters as
   `SourceTool=dexdc` findings, with category mapping and dedup by
   rule/MASVS against semgrep/gitleaks.
4. Update ADR-009 status, `docs/analyzers.md`, README and the roadmap.
5. Keep `jadx` available as the reference backend until the next release.

## If the gate fails

Keep `jadx` as default. Record the failing metric and the artifact class
(size/DEX count) in this runbook, without committing the artifact or its
findings. Re-run after either:
- reducing the target to an app-package-only workload, or
- a host with enough RAM for a full-tree differential.
