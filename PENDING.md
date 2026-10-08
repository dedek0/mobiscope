# Pending Work — mobiscope

Handoff document. Items still marked **not implemented** below need work;
everything else was delivered (see the checklists). Each section states the
goal, the concrete design (file-level), the acceptance criteria and the
known pitfalls, so work can resume without re-reading the codebase.

State of `test`: Fases 1–6 of the improvement plan are done (config,
correctness, security, docker, CI, performance, LLM robustness) plus the
platform/iOS/Android-depth, report/docs items and the §2.5/§3/§4/§7 passes.
`make check` green, `make test-integration` green, `govulncheck` reports 0
reachable vulns.

### Done since the first draft of this document

- [x] §1.1 Platform detection (`internal/platform`)
- [x] §1.2 Model schema (Platform, RuleID, MASVS/MASTG/MASWE/CWE, AppInventory, new categories)
- [x] §1.3–1.5 iOS analyzers (ipa-extract, plist, macho, codesign, strings) + `rules/mastg-ios/`
- [x] §1.6 Wiring (`buildAnalyzers` dispatch, `convertFindings` routes, report header)
- [x] §2.1 AndroidManifest via `encoding/xml` (typed components, modern permissions, protection levels)
- [x] §2.2 NSC resolved from the manifest + trust-anchors FP fix + `overridePins`
- [x] §2.3 `inventory.json` with AppInventory
- [x] §2.4 `apksigner` + `--expect-sha256`
- [x] §5 SARIF export (`report.sarif`)
- [x] §6 `/metrics` (minimal Prometheus text; richer instrumentation still open)
- [x] §8 README in English with Mermaid + troubleshooting, CHANGELOG, CODE_OF_CONDUCT, issue/PR templates
- [x] §7 Makefile tool pins, `test-integration` target, deterministic `autoDetect`
- [x] New secret patterns (OAuth client IDs, GitHub/Slack tokens, private keys)

### Done in this pass (branch `test`)

- [x] §2.5 scanner depth in full: incremental line counting, URL aggregate
      (`url_count`/`urls` in `inventory.json`), JWT/Azure/IV patterns, and the
      nine code rules in `rules/mastg/rules.yaml` (TrustManager,
      HostnameVerifier, `setAllowUniversalAccessFromFileURLs`,
      `addJavascriptInterface`, implicit PendingIntent, `Runtime.exec`,
      `DexClassLoader`, sensitive `Log.*`, DES/RC4 + `getInstance("AES")`
      ECB-default).
- [x] §1.7 iOS test plan: fixture ZIPs, full ATS matrix (incl. weak
      minimum-TLS exceptions), entitlement severity table incl.
      `keychain-access-groups` wildcards, category round-trip, synthetic IPA
      integration test.
- [x] §3 test gaps: `FuzzDetect`, `handleLLMTest` routing/cloud-refusal,
      concurrent + corrupt cache, semgrep exit codes, fakebin CLI e2e,
      apksigner fixtures, direct `buildAnalyzers`/`runTriage`/`countTriaged`
      coverage. Deferred: `go generate` mocks (hand-written mock stays).
- [x] §4 documentation: ADRs 004–009, `docs/artifacts.md` (full JSON
      examples), `docs/analyzers.md` (per-analyzer reference), gitleaks exit
      codes in troubleshooting, English `report.md` template.
- [x] §5 quick items: batch mode (`analyze a.apk b.ipa …`), `FindingConverter`
      interface (no more name switch), network-traffic analysis documented as
      a non-goal in README.
- [x] §6 quick items: richer `/metrics` counters (`internal/metrics`),
      `request_id` pass-through into API LLM logs, executive summary section
      in `report.md`.
- [x] §7 leftovers, all of them: dead code wired-or-deleted (`Registry` now
      backs the offline model listing; `NewFromLegacy`,
      `ProbeCapabilities`, `Preset.APIVersionHeader` deleted),
      `mock.Provider.ChatStream` honors `chatFunc`, `minInt` → builtin `min`,
      gofumpt pin in CI, goreleaser + `release.yml`, pre-commit config,
      macOS CI soft-fail job.
- [x] Bug fixes found by the new tests: `--expect-sha256` flag was never
      registered; apksigner debug detection/signer count; semgrep stdout
      SARIF fallback; atomic cache writes; `SourceRoot` resolver (jadx →
      apktool → session root) shared by scanners/manifest/triage context.
- [x] **Both semgrep packs were unloadable on the pinned 1.127.1** (bare
      rule lists → `was not a mapping`; `languages: [objc]` → unsupported
      language; `pattern-regex: |` block scalars carried a trailing newline
      that made every regex rule a dead matcher; `mastg-ecb-mode` ANDed two
      mutually exclusive regexes). Fixed: `rules:` wrapper, `|-` chomping,
      `pattern-either`, objc dropped; `TestRulePacks_SemgrepSchema` guards
      the format and all 18 Android rules were confirmed to fire under
      `semgrep/semgrep:1.127.1` in Docker.

### ASC evaluation (decision: defer — ADR-009)

MG1937/ASC (`pip install droidasc`) is a fast on-demand DEX front-end
(`getclass`/`listclass`/`getmanifest`/`findrefs`). It cannot replace jadx
here: gitleaks/semgrep/inventory need a **full** decompiled tree and ASC
emits none, so the default pipeline would not get faster. Value remains for
targeted `findrefs` enrichment, fast obfuscation class counts and
`getclass` snippets for triage context — revisit only if a tree-free scan
mode is designed or the tool stabilizes (it is 0.1.x). See
`docs/adr/009-defer-asc-decompiler.md`.

Conventions used throughout: commits in English, atomic, **no Co-Authored-By**,
`make check` must pass before delivery. Docs are standardized in English.

---

## 1. iOS / IPA support (high value — currently APK-only)

The schema and CLI are APK-named end-to-end (`APKPath`, `apk_path`, `analyze <apk>`).
An IPA fed to `analyze` runs apktool/jadx and produces an empty "clean" report.

### 1.1 Platform detection — new `internal/platform/platform.go`

APK and IPA are both ZIP (`PK\x03\x04`); magic bytes alone cannot discriminate.
Read the ZIP central directory (no full extract):

| Signal | Verdict |
|--------|---------|
| `Payload/*.app/Info.plist` entry | iOS |
| `AndroidManifest.xml` + `classes*.dex` | Android |
| `AndroidManifest.xml` alone | Android |

```go
type Platform string // "android" | "ios" | "unknown"

type Target struct {
    Path     string
    Format   string   // "apk" | "ipa"
    Platform Platform
}

func Detect(path string) (*Target, error)
```

Extension (`.apk`/`.ipa`) is a tiebreaker only. Reject `PlatformUnknown` with a
clear error before any tool runs.

### 1.2 Model extensions — `internal/models/`

- `Finding`: add `Platform`, `RuleID`, `MASVS []string`, `MASTG []string`,
  `MASWE []string`, `CWE []string`, `Metadata map[string]string`.
- New categories **must** be added to the `UnmarshalJSON` switch in
  `finding.go` or old `findings.json` files will fail to parse:
  `entitlement`, `binary_hardening`, `obfuscation`, `native_code`, `privacy`.
- `AnalysisSession`: add `Platform`, `App AppInventory` (BundleID, VersionCode,
  MinOS, TargetSDK, Debuggable, ObfuscationInfo, `[]NativeLib`, NetworkPolicy,
  Entitlements, URLSchemes).
- **Do not change `GenerateID`** — ADR-002 determinism and `e2e_test.go` depend
  on it. New fields are metadata, not identity.
- Keep `apk_path` JSON tag during transition; add `app_path` as the new name.

### 1.3 iOS analyzers (interface `Analyzer` unchanged)

| Stage | Linux toolchain | macOS extra | Artifact | Findings |
|-------|-----------------|-------------|----------|----------|
| `ipa-extract` | `unzip -X -q` | `ditto -x -k` (fast path) | `extract/Payload/*.app` | zip-slip |
| `plist` | **Go `howett.net/plist`** (no binary needed) | `plutil` fallback | `Info.plist.xml` | ATS (`network_config`), URL schemes, privacy (`*UsageDescription`) |
| `macho` | `ipsw` (Go, static) + fallback `llvm-objdump`/`jtool2` | `otool` | `macho_report.json` | `binary_hardening` (PIE, canary, `cryptid`, minOS), `native_code` (dylibs, `@rpath`, private frameworks) |
| `classdump` | `ipsw class-dump` + demangle | `class-dump` | `classes.json` | `code_pattern` (UIWebView, CC_MD5, `kSecAttrAccessibleAlways`…), `obfuscation` |
| `codesign` | `ldid` / Go parse of `LC_CODE_SIGNATURE` blob + `openssl smime` for `.mobileprovision` | `codesign -d --entitlements :-` | `entitlements.plist` | `entitlement` (`get-task-allow`, `disable-library-validation`, `task_for_pid-allow`…) |
| `strings` | `llvm-strings` | `strings` | `strings.txt` | reuse `inventory.scanRules` (secrets, pinning) |

Rules for tool wrapping (already established in `internal/analyzers/analyzer.go`):
- Add every new binary to `allowedBinaries`.
- `Available()` must fail soft per tool (`CheckBinary` pattern) — `otool`,
  `codesign`, `plutil`, `class-dump`, `ditto` are darwin-only and must never be
  hard requirements.
- Pass the target after `--`.
- Prefer writing tool output to a file under `sessionDir` over capturing stdout.

### 1.4 `InventoryIOS` — new `internal/analyzers/inventory_ios.go`

Mirror `Inventory.Analyze(workdir, sessionID)` so it satisfies
`pipeline.FindingCollector`. Cover:
- ATS: `NSAllowsArbitraryLoads`, `NSExceptionDomains` (incl.
  `NSIncludesSubdomains`, `NSTemporaryExceptionAllowsInsecureHTTPLoads`),
  `NSAllowsArbitraryLoadsInWebContent/InMediaStreaming`, `NSAllowsLocalNetworking`.
- Entitlements: `get-task-allow` (critical), `com.apple.security.cs.*`,
  `task_for_pid-allow`, `com.apple.private.*`, `keychain-access-groups` wildcards,
  `aps-environment=development`.
- Privacy: missing `*UsageDescription`, `NSUserTrackingUsageDescription`,
  `UIFileSharingEnabled`, `LSSupportsOpeningDocumentsInPlace`.
- Obfuscation: Swift mangling dominance, stripped symbols, few ObjC classes in a
  large binary → `ObfuscationInfo.Score` + indicators.

### 1.5 Rule packs

- New `rules/mastg-ios/rules.yaml`, same schema as `rules/mastg/rules.yaml`,
  `languages: [swift, objc, c]`.
- Migrate existing `masvs: MSTG-*` values to MASVS v2 (`MASVS-CRYPTO-1` etc.)
  and add `metadata.mastg: [MASTG-TEST-####]` / `metadata.maswe: [MASWE-####]`.
- `ConvertSemgrepFindings` must read `rule.Properties` (`masvs`, `category`,
  `reference`) into the new Finding fields and stop hardcoding
  `CategoryCodePattern` (currently only falls back to rule-id heuristics).
- Fix the dead rules in `rules/mastg/rules.yaml` while there:
  - `mastg-ecb-mode` uses `Cipher.getInstance("ECB", ...)` which never matches
    real code (`"AES/ECB/PKCS5Padding"` is one string literal) — use
    `pattern-regex`.
  - `mastg-hardcoded-api-key` matches **every** string constant — constrain to
    identifiers matching `(?i)(key|secret|token|pass)`.
  - `mastg-exported-activity` is `languages: [xml]` which OSS semgrep cannot
    parse — switch to `generic`+`pattern-regex` or drop (inventory covers it).

### 1.6 Wiring

- `cmd/mobiscope/analyze.go`: `platform.Detect` instead of bare `os.Stat`;
  `buildAnalyzers(stages, noRes, target)` dispatches per platform; help text
  mentions both `<apk>` and `<ipa>`.
- `internal/pipeline/pipeline.go`: rename `apkPath`→`targetPath`; inventory
  stage switches on platform; `convertFindings` should become a
  `FindingConverter` interface asserted at the call site (avoids the growing
  `switch a.Name()`).
- `gitleaks`/`semgrep` source dir: `JADXArtifactPath` (Android) vs
  `IPAExtractArtifactPath` (iOS) — needs a target-dir resolver.
- Report template: `**App ({{.Platform}}):**` instead of `**APK:**`.
- Dockerfile: add `unzip`, `libplist-utils`, `llvm`, static `ipsw` + `ldid`.

### 1.7 Test plan for iOS — DONE

All of the below is implemented (`platform` fixture ZIPs, ATS matrix incl.
`NSIncludesSubdomains`, entitlement severity table, category round-trip,
build-tagged synthetic IPA in `internal/pipeline/e2e_test.go`).

- `platform.Detect` unit tests with fixture ZIPs (APK, IPA, garbage, renamed).
- ATS fixtures: full `NSAppTransportSecurity` matrix.
- Entitlements fixtures: each entitlement above with expected severity.
- Round-trip: `findings.json` with new categories unmarshals (the enum switch).
- Integration (build-tagged) with a tiny hand-made IPA.

---

## 2. Android depth (high value)

### 2.1 Manifest via `encoding/xml` — `internal/analyzers/inventory.go`

Current regexes miss attribute order (`<uses-permission android:maxSdkVersion=…
android:name=…>`), `uses-permission-sdk-23`, and match XML comments.
Replace `analyzeManifest` with a real decode. Report:
- `android:allowBackup`, `android:usesCleartextTraffic`, `android:testOnly`,
  `android:sharedUserId`, `android:taskAffinity`, `grantUriPermissions`,
  `fullBackupContent`/`dataExtractionRules`, `extractNativeLibs`.
- Typed exported components (activity/service/receiver/provider) with
  `android:name` **and** whether an `<intent-filter>` exists (deeplink/IPC risk).
- Modern dangerous permissions: `READ_MEDIA_*`, `POST_NOTIFICATIONS`,
  `BLUETOOTH_CONNECT/SCAN`, `NEARBY_WIFI_DEVICES`, `BODY_SENSORS_BACKGROUND`,
  `READ_MEDIA_VISUAL_USER_SELECTED`. Match on the final segment after the last
  `.` so `com.foo.MANAGE_CAMERA` does not false-positive.

### 2.2 NSC resolved from the manifest

`analyzeNetworkSecurityConfig` hardcodes `res/xml/network_security_config.xml`.
Extract `android:networkSecurityConfig="@xml/…"` from the manifest and resolve
`res/xml/<name>.xml`.
Also fix `trustAnchorRe`: it flags stock `<trust-anchors><certificates
src="system"/>` (a false positive) — only flag `src="user"`/`src="@"`, and
detect `overridePins="true"` and pin `expiration`.

### 2.3 `apktool.yml` and `inventory.json`

apktool writes `versionInfo`/`sdkInfo`/`packageInfo` next to the manifest. Parse
it to populate `AnalysisSession.PackageName/VersionName` (currently dead schema
fields) and `minSdk`/`targetSdk`.
Emit a structured `inventory.json` artifact (not findings): full permission
list, native `.so` ABIs, assets, obfuscation (R8/ProGuard) presence, multidex,
WebView flags (`setAllowFileAccess`, `addJavascriptInterface`,
`setAllowUniversalAccessFromFileURLs`).

### 2.4 Signing / integrity

- New `internal/analyzers/apksigner.go` wrapping `apksigner verify
  --print-certs`: scheme v1/v2/v3, signer cert SHA-256 fingerprint, signer count,
  debug vs release. Record on `AnalysisSession` (`SigningCertFP`,
  `SignatureScheme`).
- `analyze --expect-sha256 <hex>` gate before any tool runs (already computed as
  `APKHash`, just not enforced).
- ZIP entry validation before/after extraction: reject `../` and absolute entry
  names (zip-slip), report symlink entries inside the APK.
- Report header: `app_sha256` + a `SHA256SUMS` file (chain of custody).

### 2.5 Scanner depth — DONE

All four bullets below are implemented (see the "Done in this pass" list).

- Size-cap already exists (`maxScanFileSize`); also precompute newline offsets
  per file — `countLines(content[:loc[0]])` is O(n) per match (O(n·m) overall).
- Demote the generic `https?://…` rule from one finding per URL to an aggregate
  in `inventory.json` (currently floods reports).
- Add patterns: Google OAuth client IDs, Slack/Azure/GitHub tokens, JWTs,
  `BEGIN RSA/EC PRIVATE KEY` blocks, hardcoded IV/`IvParameterSpec(null)`.
- Add code rules to `rules/mastg/rules.yaml`: TrustManager/HostnameVerifier
  bypass, `addJavascriptInterface`, `setAllowUniversalAccessFromFileURLs`,
  implicit `PendingIntent`, `Runtime.exec`, `DexClassLoader`, `Log.*` of
  sensitive data, DES/RC4/`Cipher.getInstance("AES")` ECB-default.

---

## 3. Test gaps (medium) — DONE except `go generate` mocks

The suite now covers the rows below (fuzzing incl. `platform.Detect`, fakebin
CLI e2e, `handleLLMTest`, failure scenarios, concurrent cache, signature
fixtures, direct `cmd/mobiscope` coverage; e2e runs in CI via
`make test-integration`). Deferred: replacing the hand-written
`internal/llm/mock` with `go generate` mocks — low value while the interface
is stable.

Historical list of what was missing (kept for context):

The suite is good but several classes of bug would slip through:

| Missing | Would catch |
|---------|-------------|
| Fuzzing on `ConvertGitleaksFindings`, `ConvertSemgrepFindings`, `config.Load`, `platform.Detect` | Malformed tool output, hostile ZIP entries |
| `go generate` mocks (currently `internal/llm/mock` is hand-written) | Interface drift |
| Integration for `analyze` end-to-end with mock binaries (a `testdata/fakebin/` dir on `PATH`) | Stage wiring, `--stages` trimming, fail-fast |
| API tests for `handleLLMTest` honoring provider/model + cloud refusal | The bug fixed in PR 3 |
| Failure scenarios: analyzer timeout, `ErrExit` per tool contract, cache corruption | Silent regressions |
| `e2e_test.go` is `//go:build integration` and **not run** by `make test` | Determinism/clustering regressions. Add a `make test-integration` target and call it in CI |
| Concurrent `Cache.Get/Set` | TOCTOU |
| APK/IPA signature fixtures for §2.4 | Integrity regressions |

Also: `cmd/mobiscope` coverage is 30% — `buildAnalyzers`, `runTriage`, `countTriaged`
have no direct tests.

---

## 4. Documentation (medium)

Standard is **English** (user decision) — DONE except tagging:

- [x] `README.md` fully English (+ batch example, non-goals section, docs links)
- [x] `CONTRIBUTING.md` English
- [x] `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1)
- [x] Issue templates + `PULL_REQUEST_TEMPLATE.md`
- [x] `CHANGELOG.md` (Keep a Changelog format)
- [x] Mermaid architecture diagram
- [x] Troubleshooting section incl. gitleaks exit codes
- [x] Full `findings.json`/`meta.json`/`session.json`/`inventory.json` examples (`docs/artifacts.md`)
- [x] Per-analyzer docs (`docs/analyzers.md`)
- [x] ADRs: 004 platform detection, 005 ErrExit contract, 006 binary
      allowlist, 007 retry policy, 008 parallel pipeline phases, 009 ASC
      deferral
- [ ] Tag `v0.1.0` from a green `test` state (goreleaser + `release.yml` are
      ready; tagging is a release decision, not code)

---

## 5. Architecture & extensibility (low, but planned)

- [x] **SARIF export** — `internal/report/sarif.go` (SARIF 2.1.0 runs).
- [ ] **CVSS** — `Finding.CVSSVector`/`CVSSScore`; compute base score from a
      small CVSS v3.1 library or an advisory mapping.
- [ ] **Vulnerability DBs** — OSV/NVD lookup for `NativeLib.Version` fingerprints.
- [ ] **SBOM** — CycloneDX via `syft` as an optional stage, or a minimal
      generator over `AppInventory.NativeLibs`.
- [ ] **Plugin system** — YAML-declared external analyzers first (command,
      output format, converter). The `FindingConverter` interface (done) is
      the intermediate step; `.so` plugins later if needed.
- [x] **Batch mode** — `analyze a.apk b.ipa …` with summary table and
      per-target session dirs.
- [ ] **Findings dedup across runs** and **version diff** (`mobiscope diff
      old.apk new.apk`) — enabled by deterministic IDs + `AppInventory`.
- [ ] **Obfuscation analysis** as its own stage (R8/ProGuard detection is §2.3;
      a score is §1.4).
- [x] **Network traffic analysis** — documented as a non-goal (README
      "Scope and non-goals").

---

## 6. Observability (low)

- [x] `/metrics` (Prometheus): per-analyzer duration/errors, findings by
      category/severity, LLM calls by provider/result + cumulative cost,
      cache hit/miss (`internal/metrics`, rendered from the API handler).
- [ ] OpenTelemetry tracing (optional, behind a flag).
- [x] `request_id` pass-through from chi's RequestID middleware into the API's
      LLM logs (pipeline/CLI logs correlate by `session_id` instead).
- [x] Executive summary section in `report.md` (severity rollup, top
      clusters/categories, triage count + cost).
- [ ] HTML report (`internal/report/html.go` + a template) and/or SARIF viewer link.
- [ ] Webhooks on completion (Slack/Discord generic incoming webhook).
- [ ] TUI mode (`bubbletea`) for `analyze --watch` — optional.

---

## 7. Smaller leftovers from the audit

**All items in this section are done** (kept for the record):

- [x] `AnalysisSession.ToolResult.Duration` custom marshaler (string) + `TimedOut bool`.
- [x] `Location.Line` `omitempty` dropped (line 0 distinguishable).
- [x] Lenient `UnmarshalJSON` for `Severity`/`Category`/… (unknown values preserved;
      caveat: no warning is logged — the models package has no logger).
- [x] Dead code wired-or-deleted: `llm.Registry` now backs the offline model
      listing fallback in `handleLLMProviderModels`; `ProbeCapabilities`,
      `NewFromLegacy` and `Preset.APIVersionHeader` were deleted (the flag was
      never read — Azure users must put `?api-version=…` in `base_url`);
      `ChatStream`/`StreamChunk` are kept deliberately — a tested interface
      capability reserved for streaming consumers (§6 TUI/webhooks).
- [x] `TriageConfig.ContextLines`/`ManifestContext` populated (`triagecontext.go`).
- [x] `CacheStats` deleted.
- [x] `mock.Provider.ChatStream` honors `chatFunc`.
- [x] Map-iteration determinism in `Router.autoDetect`/`Detector`.
- [x] Model-name drift unified (`claude-sonnet-4-20250514`).
- [x] `minInt` duplication removed (builtin `min`, Go ≥ 1.21).
- [x] golangci-lint pins match between Makefile and CI; gofumpt pinned in CI.
- [x] `Makefile` `test-integration` target (+ CI job).
- [x] goreleaser (`release.yml` + `.goreleaser.yaml`).
- [x] pre-commit hooks (`.pre-commit-config.yaml`, optional).
- [x] macOS CI job (soft-fail) exercising darwin-only iOS tools.

---

## 8. Known risks / decisions to make

1. **`GenerateID` hash encoding changed in `fix/core-correctness`** (that was the
   collision fix). IDs in `findings.json` files produced before that commit will
   not reproduce. Decide whether to document this in CHANGELOG as a breaking
   change for stored artifacts (recommended: yes, `0.1.0` treats the format as
   unstable).
2. **`ProvidersConfig` is now `map[string]*ProviderConfig`** — internal API
   break, TOML schema unchanged. Already merged; note in CHANGELOG.
3. **Docker image could not be built in the authoring environment** (WSL without
   Docker integration). `docker build` + `docker compose up` must be verified,
   and the CI `docker` job will catch it once pushed to GitHub.
4. **semgrep in the image is pinned to `1.127.1`** via pip on Ubuntu jammy.
   If that wheel disappears, fall back to `semgrep/semgrep` as an image stage and
   copy the binary + its venv.
5. **Prompt injection fencing is mitigation, not a fix.** A hostile binary can
   still try to steer triage. Consider: strip strings matching
   `(?i)ignore (all|previous) instructions` from evidence before templating, and
   always run `category=secret` locally (already enforced).

---

## 9. Suggested next order of work

Remaining open items only:

1. §5: CVSS scoring, OSV/NVD lookups, SBOM, YAML plugin system, cross-run
   dedup + `mobiscope diff`, obfuscation stage.
2. §6: HTML report, webhooks, OpenTelemetry, TUI.
3. Release: tag `v0.1.0` from green `test` (goreleaser workflow ready).
4. §1.6 tail: platform-aware source resolver for iOS gitleaks/semgrep
   (today they scan the whole session dir on iOS).
5. Revisit §8.5 (prompt-injection hardening) and the ASC deferral (ADR-009)
   only if a tree-free scan mode becomes a goal.
