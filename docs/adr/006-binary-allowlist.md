# ADR-006: Allowlisted external binaries

## Status

Accepted

## Context

Tool wrappers build argv for executables found on PATH and run them with the
privileges of the mobiscope process (including inside the analysis container,
where decompiled content from an untrusted app is present). Dynamic `exec` is
flagged by gosec (G204), and a PATH hijack or a bad wrapper would let the
pipeline run arbitrary programs. The project's wrapper rules already
established the house rules for wrapping tools ("add every new binary to
`allowedBinaries`", "pass the target after `--`", "`Available()` must fail
soft"), but the rule was not yet written down as a decision.

## Decision

There is exactly one choke point: `DefaultCommandRunner.Run` refuses any
executable whose base name is not in `allowedBinaries` and returns
`ErrBinaryNotAllowed`. The allowlist is `apktool`, `jadx`, `gitleaks`,
`semgrep`, `java` and `apksigner`; matching uses `filepath.Base(name)` so
absolute wrapper paths (the Docker image's `/usr/local/bin/apktool` shim)
still pass. Nothing else in the codebase execs external tools except
`ParseVersion`, which runs `<binary> --version` for analyzer constants only
behind a per-process `versionCache` (`ResetVersionCache` for tests).

Adding a wrapper therefore means:

1. Implement `Analyzer` (`Name`, `Available`, `Run`).
2. Add the binary name to `allowedBinaries`.
3. Pass the target after `--`; prefer writing tool output to a file under the
   session dir over scraping stdout.

`Available()` is fail-soft by construction:

- External wrappers (`apktool`, `jadx`, `gitleaks`, `semgrep`) return
  `CheckBinary`'s "not found in PATH" error.
- In-process wrappers (`ipa-extract`, `plist`, `macho`, `codesign`,
  `classdump`, `inventory`) always return nil — `macho` even probes
  `llvm-objdump` first but still returns nil. `strings` is the exception:
  it requires `llvm-strings` or `strings` on PATH although `Run` executes
  neither.
- `ApkSigner.Available` always returns nil, and `Run` degrades to a META-INF
  ZIP heuristic when the binary is absent.
- `Available()` is advisory: only `--dry-run` prints
  `(unavailable: ...)`. Real runs never pre-check; a missing binary becomes a
  `Run` error that is recorded in `ToolResult` while the pipeline continues
  (fail-soft) unless `--fail-fast`.

## Consequences

### Positive

- PATH hijack or configuration injection cannot exec arbitrary programs
  through the analyzer pipeline; there is one auditable list and one exec
  call site (its `//nolint:gosec` carries the justification).
- Every external tool gets uniform timeout, stdout/stderr capture and
  `ErrExit` handling (ADR-005).
- Minimal installs stay usable: missing semgrep/apksigner degrade to
  partial analysis instead of hard failure.
- Tests inject `MockCommandRunner` / fake binaries without touching the
  allowlist logic.

### Negative

- Every new tool needs a code change; forgetting the allowlist surfaces only
  as a runtime `binary not in allowlist` error (deliberate friction, but easy
  to miss in review).
- Base-name matching trusts PATH: any file named `jadx` anywhere on PATH is
  executable; binaries are not hashed or pinned at runtime (version pins live
  in the Dockerfile, see docs/analyzers.md).
- In-process analyzers bypass the runner entirely, so their own caps (file
  size, entry counts, symlink refusal) are the only guard there.
- The list is a maintenance burden as iOS tooling grows (ldid, ipsw would
  need entries if ever wired through the runner).

## References

- internal/analyzers/analyzer.go (allowedBinaries, ErrBinaryNotAllowed, isAllowedBinary, CheckBinary, ParseVersion)
- internal/analyzers/apksigner.go (fail-soft Available + META-INF fallback)
- internal/pipeline/pipeline.go (dry-run availability surface)
- Dockerfile (where the allowlisted binaries come from)
- [docs/roadmap.md](../roadmap.md) (current plan)
