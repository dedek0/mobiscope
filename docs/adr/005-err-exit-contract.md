# ADR-005: ErrExit contract for tool wrappers

## Status

Accepted

## Context

External tools use non-zero exit codes for three different outcomes: "finished
and found something" (gitleaks exits 1 when leaks exist), "finished with an
error" (apktool, jadx, semgrep), and "we killed it" (per-tool timeout).
`exec.Cmd.Run` collapses all three into an opaque `*exec.ExitError`, which
would either turn real findings into pipeline failures or hide genuine tool
breakage. Callers also need stdout, stderr, duration and the numeric exit code
even when the command failed, because the raw output is what tool reports are
parsed from.

## Decision

`DefaultCommandRunner.Run` (internal/analyzers/analyzer.go) normalizes the
contract:

1. The executable must pass the allowlist (ADR-006) before exec.
2. `timeout > 0` becomes a context deadline (apktool 10 min, jadx 15 min,
   gitleaks 10 min, semgrep 15 min, apksigner 2 min).
3. On process exit, `CommandResult{Stdout, Stderr, Duration, ExitCode}` is
   always populated — success or failure.
4. A non-zero exit is returned as `*ErrExit{Name, Code}`; `Error()` renders
   `<name> exited with code <n>`.
5. Cancellation or deadline (`ctx.Err() != nil`) is a plain
   `command %s timed out or cancelled` error, *not* an `ErrExit`, so wrappers
   never mistake our timeout for the tool's verdict.
6. Failures that never spawned a process (binary vanished) are plain errors
   with a nil result.

Wrappers decode `ErrExit` with `errors.As` and keep a per-tool table of
acceptable codes:

| Tool | Accepted codes | Meaning |
|------|----------------|---------|
| gitleaks | 0, 1 | 0 = clean, 1 = leaks found (`gitleaksExitLeak`); mobiscope does not pass `--exit-code`, so gitleaks' default applies. >= 2 -> `gitleaks execution failed`. |
| semgrep | 0 only | Effectively: every non-zero exit fails the stage (the `code != 0` branch returns an error). |
| apktool, jadx | none | Any error fails; apktool additionally validates its output dir exists and is non-empty. |
| apksigner | n/a | Swallows `ErrExit`: the error is copied to `ToolResult.Error` and `Run` still returns nil, then falls back to the META-INF heuristic. |
| in-process stages | n/a | inventory, ipa-extract, plist, macho, codesign, classdump, strings never produce `ErrExit`. |

Pipeline handling: an analyzer error is logged, recorded in
`ToolResult.Error`/`meta.json`, and the run continues; results are collected
in registration order and the first error (registration order) is kept.
`--fail-fast` marks the session failed and makes `Run` return that error, and
`cmd/mobiscope/main.go:classifyExit` maps process exits to 0 (ok), 1 (error),
2 (`--fail-on` findings gate), 4 (LLM policy/provider) — a separate concern
from tool exit codes.

## Consequences

### Positive

- "Leaks found" never aborts the pipeline; real tool failures stay visible
  per tool in `session.json` and `meta.json`.
- Callers always get stdout/stderr/duration for debugging, even on failure
  (gitleaks/semgrep also read their report files, since stdout is noisy).
- Timeout vs tool verdict are distinguishable by error type, not by parsing
  messages.
- The contract is unit-testable with `MockCommandRunner` (exit 1 accepted,
  exit 2 rejected — see `TestGitleaks_Run_AcceptsExitCode1` /
  `TestGitleaks_Run_RejectsExitCode2`).

### Negative

- Exit-code semantics are per-tool knowledge embedded in Go; upgrading a tool
  can silently change them (the gitleaks 0/1/2 table is version-sensitive).
- `ErrExit` with code 0 is representable but meaningless; the semgrep
  tolerance branch for it is dead code in practice.
- Timeouts are only reported through the error string: `ToolResult.TimedOut`
  exists in the schema but nothing sets it today.
- Pipeline-level "continue on error" means a broken jadx still yields a
  `completed` session with fewer findings — status alone does not say the
  report is partial (check per-tool `error` fields).

## References

- internal/analyzers/analyzer.go (ErrExit, CommandResult, DefaultCommandRunner, CheckBinary, ParseVersion)
- internal/analyzers/gitleaks.go (gitleaksExitLeak, exit-code table)
- internal/analyzers/semgrep.go, apktool.go, jadx.go (per-tool handling)
- internal/analyzers/helpers_test.go (MockCommandRunner)
- internal/pipeline/pipeline.go (error collection, fail-fast)
- cmd/mobiscope/main.go (classifyExit: 0/1/2/4)
