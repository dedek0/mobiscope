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
| `jadx` (Android) | yes | default tree producer |
| `apktool` (Android) | **no** | only when named in `--stages` or `--decompiler apktool/both` |
| `dexdc` (Android) | **no** | only when named in `--stages` or `--decompiler dexdc/jadx,dexdc` |
| `elf`, `anti-analysis`, `repack`, `sdk` (Android) | yes | `stageEnabled()` — runs by default or when named (in-process) |
| `ipa-extract`, `plist`, `macho`, `codesign`, `classdump`, `strings` (iOS) | yes | `want()` — runs by default or when named |
| `gitleaks`, `semgrep` (both platforms) | **no** | `stageSet[...]` — **only when explicitly named** |
| `inventory` | yes | Pipeline phase 3: runs when `--stages` is empty *or* contains `inventory` |
| `apksigner` | n/a | Never a stage — runs implicitly in phase 3b (Android) |

Consequences of that split:

- `analyze app.apk` runs `jadx + elf + anti-analysis + repack + sdk + inventory`
  (+ implicit apksigner). `apktool` is no longer run by default: the native
  inventory reader covers the manifest/resources/NSC, so the second full
  decode was redundant.
- `analyze app.apk --stages apktool,jadx,gitleaks,semgrep` runs both
  decompilers and adds the scanners.
- `analyze app.apk --stages inventory` runs only the in-process inventory
  phase (no external binary). It still reads the manifest, resources and DEX
  straight from the APK, so it works on a fresh session directory with no
  decompiled tree (`--quick` is meaningful for the same reason).
- gitleaks/semgrep **never run by accident**, but also never run unless you
  ask — a "default" run has no scanner findings from them.
- Unknown stage names fail the run with the list of valid names for the
  detected platform (a typo no longer silently skips a check). Stage matching
  accepts `-` and `_` interchangeably (`anti-analysis` == `anti_analysis`).
  On iOS the
  inventory phase must be requested as `inventory`, not `inventory-ios` — the
  trigger checks `NameInventory` only, while the recorded tool is named
  `inventory-ios`.
- `apksigner` cannot be selected or disabled via `--stages`; it runs for
  Android targets whenever the context is live.
- If a needed stage is missing from the list the result is silent, not
  broken: `--stages gitleaks` without `jadx` scans the (mostly empty)
  session directory — see *gitleaks/semgrep source directory* below.

`--reuse` skips a decompiler whose `<session>/jadx` or `<session>/apktool`
tree already exists (the session directory is keyed by the APK SHA-256), so a
re-run only refreshes the scanners and reports.

`--no-res` passes `-r` to apktool and `--no-res` to jadx (skips resource
decoding; the manifest is still decoded). The native inventory reader is not
affected: it still reads `resources.arsc` and `res/xml/…` straight from the
APK, so NSC findings survive `--no-res`.

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
| apksigner | **not shipped in the image** | host-only; the image uses the in-process signing-block parser (scheme, certificate, v1 presence) |

`Makefile` and `.github/workflows/ci.yml` pin only developer tools
(gofumpt v0.8.0 and golangci-lint v2.13.2 in the Makefile; CI pins
golangci-lint v2.13.2 and installs gofumpt `@latest`); the CI `docker` job
smoke-prints `gitleaks version`, `apktool --version`, `jadx --version`,
`semgrep --version` to catch broken pins. The allowed-exec set is
`internal/analyzers/analyzer.go:allowedBinaries` (ADR-006).

## Diff, baseline and the CI gate

- `mobiscope diff old.apk new.apk` analyzes both artifacts with the same stages
  and prints new/resolved/unchanged findings. `--json <path>` writes the full
  `{new, resolved, unchanged}` object.
- `analyze --baseline <findings.json|session.json>` suppresses findings whose
  fingerprint was already present in the baseline. The count lands in
  `session.baseline_suppressed`; the baseline is applied before triage.
- `analyze --fail-on <critical|high|medium|low|info>` exits with code **2**
  when at least one remaining finding is at or above the threshold (or 0 when
  the baseline removed them all). `off`/`none` disables the gate.
- `analyze --mapping <mapping.txt>` rewrites obfuscated class paths in
  finding locations (and class names in evidence/description) through an
  R8/ProGuard mapping, then re-clusters. It runs before `--allowlist`,
  `--baseline` and triage; the count lands in `session.findings_mapped`.
- `analyze --allowlist <allowlist.yaml>` suppresses findings that match every
  populated field of a rule. Every rule needs a `reason`; a rule with no
  matching field is rejected. Fields: `tool`, `category`, `rule_id`, `title`,
  `file`, `evidence`. Patterns accept `*`/`?`/`[]` (via `path.Match`) and a
  leading `**/`; patterns without a wildcard match as substrings. The count
  lands in `session.allowlist_suppressed`.

  ```yaml
  allow:
    - reason: "Firebase API keys are public client identifiers"
      category: secret
      title: "*GCP API Key*"
    - reason: "Generated BuildConfig constant"
      file: "**/BuildConfig.java"
  ```
- Fingerprints ignore line numbers: semgrep findings use
  `source_tool|rule_id|file`; everything else uses
  `category|title|file|evidence`. A moved finding stays “unchanged”; a second
  occurrence counts as new.

## Android stages

| Stage | Wraps | Timeout | Artifacts | Findings fed | Required? |
|-------|-------|---------|-----------|--------------|-----------|
| `apktool` | `apktool d -f -o <dir> [-r] -- <apk>` | 10 min | `apktool/` (decoded `AndroidManifest.xml`, `res/`, `apktool.yml`) | none directly — feeds inventory | opt-in (or `--decompiler`) |
| `jadx` | `jadx --threads-count N -d <dir> [--no-res] -- <apk>` | 15 min | `jadx/` (sources + manifest) | none directly — feeds gitleaks/semgrep/inventory/triage context | default tree producer |
| `dexdc` | `dex-decompile -i <apk> -d <dir> [--deobf] --exclude <pkg>...` | 15 min | `dexdc/` (Java-like package tree) | none directly — feeds gitleaks/semgrep/inventory/triage context | opt-in (`--decompiler dexdc`) |
| `elf` | in-process (no binary) | none | fills `inventory.json.native_libs` | `binary_hardening`, `native_code`, `obfuscation` | default |
| `anti-analysis` | in-process (no binary) | none | — | `anti_analysis`, `obfuscation` | default |
| `repack` | in-process (no binary) | none | — | `manifest_issue` (repackaging) | default |
| `sdk` | in-process (no binary) | none | fills `inventory.json.sdks` | informational `manifest_issue` per library | default |
| `gitleaks` | `gitleaks detect --source <dir> --report-format json --report-path <session>/gitleaks-report.json --no-git` | 10 min | `gitleaks-report.json` | `secret` | opt-in stage |
| `semgrep` | `semgrep --config <materialized embedded pack> --sarif --output <session>/semgrep.sarif --quiet <dir>` | 15 min | `semgrep.sarif` | `code_pattern`, `secret`, `manifest_issue`, `network_config`, `pinning_indicator` | opt-in stage |
| `inventory` | in-process (no binary) | none | — (plus shared `inventory.json`) | `manifest_issue`, `network_config`, `pinning_indicator`, `secret`, `code_pattern` | default |
| `apksigner` | `apksigner verify --print-certs --verbose <apk>` | 2 min | — (fills `session.signing_cert_fp`, `signature_scheme`) | `manifest_issue` (debug-signed, no signer, v1-only) | implicit, fail-soft |

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
- **elf** — reads native libraries straight from the APK (`lib/<abi>/*.so`,
  plus ELF-magic `.so` files under `assets/`) and records PIE, RELRO, NX, stack
  canary, FORTIFY, stripping, text relocations, RPATH, `DT_SONAME`, `Java_*`
  JNI exports, Shannon entropy and packer signatures (UPX, 360 Jiagu, Tencent
  Legu, Alibaba, Bangcle, …) in `inventory.json.native_libs`. High-entropy
  libraries and packer signatures become `obfuscation` findings. It also
  surfaces the anti-analysis strings found in the binary, and the
  `anti-analysis` stage now flags `RegisterNatives`.
- **anti-analysis** — parses the DEX class names to score obfuscation and
  scans DEX/executable assets (`.dex`, `.jar`, `.so`, `.apk`) for
  root/emulator, anti-debug, instrumentation (Frida/Xposed),
  dynamic-code-loading, reflection and runtime string-decoding markers. Data
  assets (Unity metadata, models, fonts) are ignored to avoid generic-word
  false positives. Emits `anti_analysis`
  and `obfuscation` findings and fills `inventory.json.obfuscation` (score,
  class count, toolchain).
- **repack** — reports a certificate that does not match `--expect-cert`,
  executable payloads in `assets/` (`.dex`/`.jar`/`.apk`, high) and native
  libraries in `assets/` (low). Multidex, a v2/v3-only signature and a
  normalized ZIP timestamp are normal and are not reported. Findings are
  `manifest_issue`; the converter is wired into the pipeline.
- **sdk** — recognises third-party libraries from DEX class prefixes and
  from native-only markers (`libflutter.so`, `libunity.so`, `libil2cpp.so`,
  `libreactnativejni.so`, `libhermes.so`). Versions come from
  `META-INF/maven/*/pom.properties`, decoded string resources or decompiled
  `BuildConfig` classes. Feeds `inventory.json.sdks`,
  which is what `--osv` looks up, and emits one informational
  `manifest_issue` finding per library.
- **gitleaks** — exit `0` (clean) and `1` (leaks found) are success;
  `>= 2` fails the stage (ADR-005; `--exit-code` is not overridden).
  The report *file* is preferred over stdout (stdout carries banners);
  `extractJSONArray` trims any remaining preamble. Severity comes from the
  rule's tags (untagged defaults to `critical`), confidence from entropy.
  Findings are marked `needs_llm_triage` + `representative`.
- **semgrep** — rules from the embedded pack (`internal/rules/mastg/rules.yaml`,
  43 rules: Java, Kotlin plus taint-mode rules for intent/deeplink → WebView,
  SQL, file/exec, clipboard → log, intent redirection, reflection and
  runtime Base64 string decoding); the pack is validated with
  `semgrep --validate` during the Docker image build. Severity is the SARIF
  level (`error->critical`, `warning->medium`, `note/info->info`, else
  `low`), category from rule metadata with rule-id heuristics as fallback,
  confidence fixed `0.8`; `masvs`/`mastg`/`cwe` are read from the SARIF
  rule `properties`. Any non-zero exit fails the stage. Both packs use the
  top-level `rules:` wrapper (bare rule lists are rejected by semgrep
  1.127.1 with `was not a mapping`) and are guarded by
  `TestRulePacks_SemgrepSchema`; the Android pack also validates with
  `semgrep --validate --config internal/rules/mastg/rules.yaml`. The packs
  are embedded in the binary and materialized to a temp directory for
  semgrep.
- **inventory** — reads the APK directly first: `AndroidManifest.xml` is
  decoded from compiled binary XML (`internal/analyzers/axml.go`) and
  `resources.arsc` is parsed (`arsc.go`) so resource references such as
  `@xml/network_security_config` resolve without apktool. The decoded tree
  (`jadx/` → `apktool/` → session root) is only a fallback when the native
  parse fails (or when the caller has no APK). The manifest is then decoded
  with `encoding/xml` from that XML (legacy regex fallback for non-XML).
  Checks are `targetSdk`-aware: `android:exported` defaults, provider defaults,
  pre-API-28 cleartext, App Links without `autoVerify`, singleTask /
  singleInstance task affinity, `grant-uri-permission` children, and
  `usesCleartextTraffic` defaults. A conservative built-in allowlist skips
  exported components that belong to AndroidX and other library infrastructure
  (`androidx.work`, `androidx.startup`, `androidx.profileinstaller`,
  `android.support`, Datatransport, Play measurement, Firebase messaging), so
  library plumbing does not drown app-specific exported components.
  The network security config is fully parsed (`nsc.go`): base and per-domain
  `cleartextTrafficPermitted`, `debug-overrides`, `overridePins`,
  `pin-set`/`expiration`, and trust anchors. Only relaxations are findings;
  the structured result also populates `inventory.network.exceptions`.
  Every `classes*.dex` string pool is scanned with `scanRules` (AWS/GCP/
  GitHub/Slack tokens, Azure connection strings, JWTs, private keys, Firebase
  URLs, predictable IVs) plus the URL/IP/e-mail/pinning aggregates, so secrets
  are found even when `jadx`/`semgrep` did not run or mangled the sources.
  Caps: tree extensions
  `.java .smali .xml .kt .json .properties .cfg`, files <= 2 MiB
  (`maxScanFileSize`), DEX files <= 64 MiB and <= 500k strings, symlinks never
  followed. The tree walk skips vendor SDK directories (AndroidX, Firebase,
  GMS, OkHttp, Kotlin, …) because the DEX string scanner already covers their
  literals, and processes the remaining files with a bounded worker pool.
  Generic URLs (`url_count`/`urls`), IPs (`ip_count`/`ips`), e-mails
  (`email_count`/`emails`) and pinning markers
  (`pinning_indicators`/`pinning_count`) are aggregate inventory data, not
  findings; DEX aggregates are only merged when the tree scan produced none,
  so a full run does not double-count. Pinning produces one informational
  finding per app. Private keys require a complete PEM block with a valid
  base64 body, and the body is redacted. Client-side identifiers (GCP API key,
  Google OAuth client ID, Firebase URL) are `info`/`public`. Every finding sets
  `platform` and `origin` (`app` or `sdk:<name>`).
- **apksigner** — runs implicitly and is not selectable. Its findings
  (debug-signed, no signer, v1-only, expired certificate, weak RSA key) are
  wired through `ConvertFindings`; `signing_cert_fp` and
  `signature_scheme` also land on the session. When the binary is missing
  (including the Docker image), the in-process parser (`signing.go`) reads the
  APK Signing Block v2/v3/v3.1, extracts the signer certificate (SHA-256
  fingerprint, subject, validity, key algorithm/size), combines it with the
  v1 `META-INF/*.RSA|DSA|EC` presence, and reports the scheme. It also
  verifies the v2/v3 signature and the APK content digest (chunked SHA-256 or
  SHA-512 depending on the algorithm), so a tampered artifact is reported as
  `digest-mismatch`/`invalid-signature`. The v3 rotation lineage and source
  stamp are detected; their cryptographic chains are not validated yet.

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
  `analyzers.SourceRoot`: `jadx/` first, then `apktool/`, then `dexdc/`, then
  the session root. On iOS (no `jadx/`, no `apktool/`) that means the *whole session
  directory* (including `extract/`) is scanned: there is no platform-aware
  resolver yet (see [docs/roadmap.md](roadmap.md), P1). `inventory-ios`
  must be requested as `--stages inventory`.

## Decompiler backends

`jadx` remains the default tree producer. The optional `dexdc` stage wraps
[`androguard/dex-decompiler`](https://github.com/androguard/dex-decompiler)
and is selected explicitly:

```bash
./bin/mobiscope analyze app.apk --decompiler dexdc
./bin/mobiscope analyze app.apk --decompiler jadx,dexdc   # extract both trees
```

`--decompiler` accepts `apktool`, `jadx`, `dexdc`, the historical `both`
(`apktool+jadx`) or a comma-separated list. `dexdc` is fail-soft: a missing
binary becomes a failed stage and the run continues. By default it excludes
framework/vendor prefixes (`android.`, `androidx.`, `kotlin.`, `com.google.*`,
OkHttp, Bouncy Castle, …) because the native/DEX scanners already cover their
literals and a full tree of a very large APK is memory-hungry. `SourceRoot`
resolves `jadx → apktool → dexdc → session root`, so a `jadx,dexdc` run scans
the jadx reference tree; each backend is evaluated in its own workdir.

Differential evaluation is manual, not part of `go test`:

```bash
scripts/evaluate-decompiler.py app.apk --workdir targets/eval --json eval.json
```

It records wall time, decompiler time, peak RSS, finding counts, recall by
category+title+evidence, strict fingerprint overlap and semgrep error
notifications, and prints the ADR-009 acceptance checks. See
[ADR-009](adr/009-decompiler-backends.md). `dexdc` does not become the
default (`--fast`) until the differential result passes.

## What each flow needs

| Goal | Stages |
|------|--------|
| Full Android report (default) | `jadx`, `elf`, `anti-analysis`, `repack`, `sdk`, `inventory` (+ implicit apksigner) |
| Secrets from decompiled code | `jadx` **and** `gitleaks` (gitleaks alone scans a nearly empty dir) |
| MASVS/MASTG rule matches | `jadx` **and** `semgrep` (needs a full source tree) |
| Manifest/NSC findings only | `inventory` (reads the APK directly; a pre-seeded `jadx/` tree is only a fallback — `scripts/smoke.sh` also exercises that) |
| Fast iOS pass | defaults; add `gitleaks,semgrep` to use the embedded iOS pack |
| Signed-artifact facts | automatic on Android — no stage needed |
| Compare decompiler backends | `--decompiler jadx` and `--decompiler dexdc` in separate workdirs, then `scripts/evaluate-decompiler.py` |

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
