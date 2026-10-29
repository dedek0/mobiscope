# Analyzer reference

Per-stage reference for `mobiscope analyze`: what each stage wraps, what it
extracts, which artifacts and findings it produces, and where its gaps are.
Code pointers are relative to the repo root; the stage set is assembled in
`buildAnalyzers` (cmd/mobiscope/analyze.go) and executed by
`internal/pipeline/pipeline.go`.

## Stage selection rules (`--stages`)

`--stages` takes a comma-separated list. Selection happens in three places,
and they do **not** all use the same rule:

| Stage | Default (no `--stages`)? | Rule |
|-------|--------------------------|------|
| `apktool`, `jadx` (Android) | yes | `want()` — runs by default or when named |
| `elf`, `anti-analysis`, `repack`, `sdk` (Android) | yes | `stageEnabled()` — runs by default or when named (in-process) |
| `ipa-extract`, `plist`, `macho`, `codesign`, `classdump`, `strings` (iOS) | yes | `want()` — runs by default or when named |
| `gitleaks`, `semgrep` (both platforms) | **no** | `stageSet[...]` — **only when explicitly named** |
| `inventory` | yes | Pipeline phase 3: runs when `--stages` is empty *or* contains `inventory` |
| `apksigner` | n/a | Never a stage — runs implicitly in phase 3b (Android) |

Consequences of that split:

- `analyze app.apk` runs `apktool + jadx + elf + anti-analysis + repack + sdk
  + inventory` (+ implicit apksigner).
- `analyze app.apk --stages apktool,jadx,gitleaks,semgrep` adds the scanners.
- `analyze app.apk --stages inventory` runs only the in-process inventory
  phase (no external binary).
- gitleaks/semgrep **never run by accident**, but also never run unless you
  ask — a "default" run has no scanner findings from them.
- Unknown stage names are silently ignored (no error). On iOS the inventory
  phase must be requested as `inventory`, not `inventory-ios` — the trigger
  checks `NameInventory` only, while the recorded tool is named
  `inventory-ios`.
- `apksigner` cannot be selected or disabled via `--stages`; it runs for
  Android targets whenever the context is live.
- If a needed stage is missing from the list the result is silent, not
  broken: `--stages gitleaks` without `jadx` scans the (mostly empty)
  session directory — see *gitleaks/semgrep source directory* below.

`--no-res` passes `-r` to apktool and `--no-res` to jadx (skips resource
decoding; the manifest is still decoded, but NSC findings are lost with
`res/`).

## Pinned tool versions

Pins live in the Docker image (`Dockerfile`); local installs are whatever is
on PATH (recorded per run in `meta.json`/`session.json` via
`ParseVersion <binary> --version`).

| Tool | Pin | Where |
|------|-----|-------|
| gitleaks | `8.24.3` | `Dockerfile` `ARG GITLEAKS_VERSION` |
| apktool | `2.11.1` | `Dockerfile` `ARG APKTOOL_VERSION` (jar + shell shim) |
| jadx | `1.5.1` | `Dockerfile` `ARG JADX_VERSION` |
| semgrep | `1.127.1` | `Dockerfile` `pip3 install semgrep==…` |
| JRE | Temurin 21 (jammy) | `Dockerfile` base image |
| unzip, libplist-utils, llvm | unpinned (apt) | `Dockerfile` — fallbacks only |
| ipsw, ldid | not installed by default (`IPSW_VERSION=v0.0.0`) | `Dockerfile` |
| apksigner | **not shipped in the image** | host-only; image falls back to the META-INF heuristic |

`Makefile` and `.github/workflows/ci.yml` pin only developer tools
(gofumpt v0.8.0 and golangci-lint v2.13.2 in the Makefile; CI pins
golangci-lint v2.13.2 and installs gofumpt `@latest`); the CI `docker` job
smoke-prints `gitleaks version`, `apktool --version`, `jadx --version`,
`semgrep --version` to catch broken pins. The allowed-exec set is
`internal/analyzers/analyzer.go:allowedBinaries` (ADR-006).

## Android stages

| Stage | Wraps | Timeout | Artifacts | Findings fed | Required? |
|-------|-------|---------|-----------|--------------|-----------|
| `apktool` | `apktool d -f -o <dir> [-r] -- <apk>` | 10 min | `apktool/` (decoded `AndroidManifest.xml`, `res/`, `apktool.yml`) | none directly — feeds inventory | default, fail-soft |
| `jadx` | `jadx --threads-count N -d <dir> [--no-res] -- <apk>` | 15 min | `jadx/` (sources + manifest) | none directly — feeds gitleaks/semgrep/inventory/triage context | default, fail-soft |
| `elf` | in-process (no binary) | none | fills `inventory.json.native_libs` | `binary_hardening`, `native_code`, `obfuscation` | default |
| `anti-analysis` | in-process (no binary) | none | — | `anti_analysis`, `obfuscation` | default |
| `repack` | in-process (no binary) | none | — | `manifest_issue` (repackaging) | default |
| `sdk` | in-process (no binary) | none | fills `inventory.json.sdks` | informational `manifest_issue` per library | default |
| `gitleaks` | `gitleaks detect --source <dir> --report-format json --report-path <session>/gitleaks-report.json --no-git` | 10 min | `gitleaks-report.json` | `secret` | opt-in stage |
| `semgrep` | `semgrep --config <materialized embedded pack> --sarif --output <session>/semgrep.sarif --quiet <dir>` | 15 min | `semgrep.sarif` | `code_pattern`, `secret`, `manifest_issue`, `network_config`, `pinning_indicator` | opt-in stage |
| `inventory` | in-process (no binary) | none | — (plus shared `inventory.json`) | `manifest_issue`, `network_config`, `pinning_indicator`, `secret`, `code_pattern` | default |
| `apksigner` | `apksigner verify --print-certs --verbose <apk>` | 2 min | — (fills `session.signing_cert_fp`, `signature_scheme`) | none wired (see below) | implicit, fail-soft |

Details and known gaps:

- **apktool** — output directory must exist and be non-empty or the stage
  fails (`validateOutputDir`). `apktool.yml` is merged into `inventory.json`
  (`version_name`, `version_code`, `min_os`, `target_sdk` — the manifest
  alone does not carry them). The Docker wrapper is a shell shim that execs
  `java -jar`, which is why `java` is on the binary allowlist.
- **jadx** — threads default to `runtime.NumCPU()`. DEX-related stderr lines
  are extracted into `output.dex_warnings`. OOM on large APKs is the main
  failure mode (`JAVA_OPTS=-Xmx4g`). The decoded tree is the preferred input
  for every scanner below; they resolve `analyzers.SourceRoot`
  (`jadx/` → `apktool/` → session root), so an apktool-only run still gets
  scanned.
- **elf** — reads native libraries straight from the APK (`lib/<abi>/*.so`)
  and records PIE, RELRO, NX, stack canary, FORTIFY, stripping, text
  relocations, RPATH and `Java_*` JNI exports in `inventory.json.native_libs`.
  It also surfaces the anti-analysis strings found in the binary.
- **anti-analysis** — parses the DEX class names to score obfuscation and
  scans strings for root/emulator, anti-debug, instrumentation (Frida/Xposed)
  and dynamic-code-loading markers. Emits `anti_analysis` and `obfuscation`
  findings.
- **repack** — flags a debug certificate, a certificate that does not match
  `--expect-cert`, additional `classes*.dex` files, payloads hidden in
  `assets/` and a uniform ZIP timestamp. Findings are `manifest_issue`.
- **sdk** — recognises third-party libraries from DEX class prefixes and
  recovers versions from decoded resources. Feeds `inventory.json.sdks`,
  which is what `--osv` looks up.
- **gitleaks** — exit `0` (clean) and `1` (leaks found) are success;
  `>= 2` fails the stage (ADR-005; `--exit-code` is not overridden).
  The report *file* is preferred over stdout (stdout carries banners);
  `extractJSONArray` trims any remaining preamble. Severity comes from the
  rule's tags (untagged defaults to `critical`), confidence from entropy.
  Findings are marked `needs_llm_triage` + `representative`.
- **semgrep** — rules from the embedded pack (`internal/rules/mastg/rules.yaml`,
  29 rules); severity is the SARIF
  level (`error->critical`, `warning->medium`, `note/info->info`, else
  `low`), category from rule metadata with rule-id heuristics as fallback,
  confidence fixed `0.8`; `masvs`/`mastg`/`cwe` are read from the SARIF
  rule `properties`. Any non-zero exit fails the stage. Both packs use the
  top-level `rules:` wrapper (bare rule lists are rejected by semgrep
  1.127.1 with `was not a mapping`) and are guarded by
  `TestRulePacks_SemgrepSchema`. The packs are embedded in the binary and
  materialized to a temp directory for semgrep; validate manually with
  `semgrep --validate --config internal/rules/mastg/rules.yaml`.
- **inventory** — reads `jadx/AndroidManifest.xml`, falling back to
  `apktool/AndroidManifest.xml` and then the session root,
  decodes it with `encoding/xml` (legacy regex fallback for non-XML),
  resolves the network security config via
  `android:networkSecurityConfig="@xml/…"`, then pattern-scans the tree with
  `scanRules` (AWS/GCP/GitHub/Slack tokens, Azure connection strings, JWTs,
  private keys, Firebase URLs, predictable IVs, IPs, emails, pinning
  markers). Caps: extensions
  `.java .smali .xml .kt .json .properties .cfg`, files <= 2 MiB
  (`maxScanFileSize`), symlinks never followed. Generic URLs are demoted to
  the `url_count`/`urls` aggregate in `inventory.json`. Gaps: scanner-style
  findings do not set `platform`; IP/email patterns are intentionally loose.
- **apksigner** — not selectable, and its `ToolResult` is **not** recorded
  in `session.json`/`meta.json`: only `signing_cert_fp` and
  `signature_scheme` land on the session. When the binary is missing
  (including the Docker image), `metaInfHeuristic` scans `META-INF/*.RSA|DSA|EC`
  and reports `v1`/`none`. `ConvertApkSignerFindings` (debug-signed,
  v1-only, no-signer findings) exists but is not wired into
  `pipeline.convertFindings`, so those findings are never emitted today.

## iOS stages

| Stage | Wraps | Timeout | Artifacts | Findings fed | Required? |
|-------|-------|---------|-----------|--------------|-----------|
| `ipa-extract` | in-process `archive/zip` (no `unzip` binary) | none (ctx checked at start only) | `extract/Payload/<App>.app/…` | `manifest_issue` (zip-slip) | default |
| `plist` | in-process `howett.net/plist` | none | — | `network_config` (ATS), `manifest_issue` (dangerous URL schemes), `privacy` (file sharing) | default |
| `macho` | in-process Mach-O load-command parser | none | — | `binary_hardening`, `native_code`, `obfuscation` | default |
| `codesign` | in-process entitlements/provisioning parse | none | — | `entitlement` | default |
| `classdump` | in-process symbol regexes (not `class-dump(1)`) | none | — | `code_pattern`, `privacy`, `obfuscation` | default |
| `strings` | in-process printable-string extraction | none | — | `secret`, `code_pattern`, `pinning_indicator` (shared `scanRules`) | default |
| `gitleaks` | as Android | 10 min | `gitleaks-report.json` | `secret` | opt-in |
| `semgrep` | `semgrep --config <materialized embedded iOS pack> …` | 15 min | `semgrep.sarif` | as Android | opt-in |
| `inventory-ios` | in-process (reuses plist/codesign/macho converters) | none | — | same as those stages + `obfuscation` (duplicates collapsed by dedup) | default via `inventory` |

iOS semgrep gap: semgrep has **no Objective-C parser** (`objc` is not a
supported language — the pack used to declare it and the whole config failed
to load). The pack now targets `swift`/`c` (+`json`/`xml` for ATS keys), so
`.m`/`.h` sources are not semgrep-scanned; `classdump` and `strings` cover
the Objective-C surface instead.

Details and known gaps:

- **ipa-extract** — refuses archives with > 20000 entries (stage error),
  entries > 512 MiB, absolute/`..` paths and symlink entries (each rejected
  entry becomes a zip-slip finding via `output.zip_slip`). `ipaTimeout`
  (5 min) is declared but unused — extraction only honors context
  cancellation.
- **plist** — also emits `url_schemes` and `usage_required` (all
  `*UsageDescription` keys) into its output, but no finding is derived from
  them yet (missing-usage-description checks are not implemented). Fails if
  `ipa-extract` did not run (no `Payload/*.app`).
- **macho** — `Available()` probes `llvm-objdump` but `Run` never execs it
  (comment drift; `llvm-objdump` is not even allowlisted). Parsing covers
  magic/FAT/arch slices, `LC_ENCRYPTION_INFO` cryptid and `LC_LOAD_DYLIB`
  paths. Caps: binaries <= 64 MiB (`maxScanFileSize*32`), only under
  `Frameworks/`, `PlugIns/` or Mach-O-magic at the bundle root. Gap:
  `NativeLib.InstallName` is never populated, so the "@rpath install name"
  finding can never fire; FAT-slice encryption detection reads the header as
  if it were thin.
- **codesign** — no `codesign(1)`/`ldid` is executed on Linux: entitlements
  come from `entitlements.plist`/`Entitlements.plist`, else from an
  `<plist>…</plist>` blob inside the main executable; provisioning from the
  inner plist of `embedded.mobileprovision` (regex, not a real CMS parse).
  No certificate chain verification is performed.
- **classdump** — regexes `_OBJC_CLASS_\$_…` and `$s…` over Mach-O bytes;
  dangerous-class map covers `UIWebView`, `NSURLConnection`,
  `ASIdentifierManager`. Findings always report file `class-dump`, line 1.
- **strings** — `Available()` probes `llvm-strings`/`strings` even though
  `Run` needs no binary, so `--dry-run` can report "unavailable" on hosts
  where the stage would actually work. Caps: files <= 16 MiB
  (`maxScanFileSize*8`), iOS code extensions plus Mach-O-magic files, max
  5000 strings per file; every finding has line 1 (file path + string are
  the dedup key).
- **gitleaks/semgrep source directory** — both resolve
  `analyzers.SourceRoot`: `jadx/` first, then `apktool/`, then the session
  root. On iOS (no `jadx/`, no `apktool/`) that means the *whole session
  directory* (including `extract/`) is scanned: there is no platform-aware
  resolver yet (PENDING.md §1.6). `inventory-ios` must be requested as
  `--stages inventory`.

## What each flow needs

| Goal | Stages |
|------|--------|
| Full Android report (default) | `apktool`, `jadx`, `inventory` (+ implicit apksigner) |
| Secrets from decompiled code | `jadx` **and** `gitleaks` (gitleaks alone scans a nearly empty dir) |
| MASVS/MASTG rule matches | `jadx` **and** `semgrep` (needs a full source tree) |
| Manifest/NSC findings only | `inventory` (works off `jadx/`, or a pre-seeded tree — `scripts/smoke.sh` does exactly that) |
| Fast iOS pass | defaults; add `gitleaks,semgrep` for `rules/mastg-ios` |
| Signed-artifact facts | automatic on Android — no stage needed |

Cross-cutting behavior:

- **Fail-soft:** nothing is hard-required. External binaries missing →
  stage error recorded in `tool_results[].error`, run continues (`completed`
  status) unless `--fail-fast`; `--dry-run` prints `Available()` per stage.
- **Concurrency/phases:** decompilers first, scanners after, inventory last,
  dedup → cluster → severity sort (ADR-008).
- **Timeouts** are per-tool, enforced by the command runner (ADR-005);
  in-process stages have none.
- **Universal caps:** pattern scans skip files > 2 MiB and never follow
  symlinks; ZIP extraction refuses > 20000 entries / > 512 MiB entries;
  platform detection inspects <= 4096 central-directory entries.
