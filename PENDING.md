# Pending Work — mobiscope

Handoff document. Everything below is **not implemented**. Each section states
the goal, the concrete design (file-level), the acceptance criteria and the
known pitfalls, so work can resume without re-reading the codebase.

State of `test`: Fases 1–6 of the improvement plan are done (config,
correctness, security, docker, CI, performance, LLM robustness) plus the
platform/iOS/Android-depth and report/docs items from sections 1, 2, 5 (SARIF)
and 8 below. `make check` green, `govulncheck` reports 0 reachable vulns.

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

Conventions used throughout: commits in English, atomic, **no Co-Authored-By**,
`make check` must pass before delivery. Docs are being standardized in English.

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

### 1.7 Test plan for iOS

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

### 2.5 Scanner depth

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

## 3. Test gaps (medium)

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

Standard is **English** going forward (user decision).

- [ ] `README.md` is still largely Portuguese (install/usage/privacy sections).
      Translate fully; keep `README.pt-BR.md` if a translation is wanted.
- [ ] `CONTRIBUTING.md` is Portuguese and says "Commits em inglês, docs/UX em
      pt-BR" — update to the English-docs standard.
- [ ] `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).
- [ ] Issue templates (bug report, analyzer request, false positive) and
      `PULL_REQUEST_TEMPLATE.md`.
- [ ] `CHANGELOG.md` (Keep a Changelog format) + semantic versioning tags.
      Start at `0.1.0` from the current `test` state.
- [ ] Mermaid architecture diagram in README (replace the ASCII one).
- [ ] Troubleshooting section: tool not in PATH, jadx OOM, gitleaks exit codes,
      semgrep rule pack fails to load, Ollama unreachable, exit code 4 meaning.
- [ ] Full `findings.json`/`meta.json`/`session.json` examples (README has a
      partial one; `session.json` is new).
- [ ] Per-analyzer docs: what each tool extracts, required version, known gaps.
- [ ] `docs/adr/` — add ADRs for: platform detection, `ErrExit` contract,
      binary allowlist, retry policy, parallel pipeline phases.

---

## 5. Architecture & extensibility (low, but planned)

- [ ] **SARIF export** — `Finding` now has `RuleID`/`CWE`/`MASVS` in mind (see
      §1.2); write `internal/report/sarif.go` mapping to SARIF 2.1.0 runs.
- [ ] **CVSS** — `Finding.CVSSVector`/`CVSSScore`; compute base score from a
      small CVSS v3.1 library or an advisory mapping.
- [ ] **Vulnerability DBs** — OSV/NVD lookup for `NativeLib.Version` fingerprints.
- [ ] **SBOM** — CycloneDX via `syft` as an optional stage, or a minimal
      generator over `AppInventory.NativeLibs`.
- [ ] **Plugin system** — YAML-declared external analyzers first (command,
      output format, converter); `.so` plugins later if needed. The
      `FindingConverter` interface from §1.6 is the intermediate step.
- [ ] **Batch mode** — `analyze a.apk b.ipa …` is trivial after `platform.Detect`;
      add a summary table and per-target session dirs.
- [ ] **Findings dedup across runs** and **version diff** (`mobiscope diff
      old.apk new.apk`) — enabled by deterministic IDs + `AppInventory`.
- [ ] **Obfuscation analysis** as its own stage (R8/ProGuard detection is §2.3;
      a score is §1.4).
- [ ] **Network traffic analysis** — out of scope for a static harness; document
      as a non-goal or integrate mitmproxy as an external stage later.

---

## 6. Observability (low)

- [ ] `/metrics` (Prometheus): per-analyzer duration, findings by
      category/severity, LLM call success/failure/cost, cache hit rate.
- [ ] OpenTelemetry tracing (optional, behind a flag).
- [ ] Structured JSON logs already exist (slog) — add a `request_id` attribute
      pass-through from chi's RequestID middleware into analyzer/LLM logs.
- [ ] Executive summary section in `report.md` (counts, top clusters, cost).
- [ ] HTML report (`internal/report/html.go` + a template) and/or SARIF viewer link.
- [ ] Webhooks on completion (Slack/Discord generic incoming webhook).
- [ ] TUI mode (`bubbletea`) for `analyze --watch` — optional.

---

## 7. Smaller leftovers from the audit

Worth a cleanup pass; each is small:

- [ ] `AnalysisSession.ToolResult.Duration` marshals as raw nanoseconds — add a
      custom marshaler emitting a string (`"1.2s"`), and `TimedOut bool`.
- [ ] `Location.Line` is `int` with `omitempty` — line 0 is indistinguishable
      from absent. Consider `*int` or drop `omitempty`.
- [ ] Strict `UnmarshalJSON` on `Severity`/`Category`/… hard-fails on unknown
      values — accept unknown strings with a warning for forward compatibility
      (required once iOS categories land).
- [ ] `llm.Registry`/`NewRegistry`, `openai_compatible.ProbeCapabilities`,
      `NewFromLegacy`, `Preset.APIVersionHeader`, `ChatStream`/`StreamChunk`
      have no production caller. Wire or delete.
- [ ] `TriageConfig.ContextLines` and `ManifestContext` are configured/templated
      but never populated (`runTriage` passes `codeContext=nil`). Build the map
      from the decompiled file around `Location.Line` and feed it in.
- [ ] `CacheStats` promises `Stats()` which does not exist.
- [ ] `mock.Provider.ChatStream` ignores `chatFunc`.
- [ ] Non-determinism: `Router.autoDetect` and `Detector` iterate maps — sort
      keys (partially fixed in `defaultModel` only).
- [ ] Model-name drift: `Registry` uses `claude-sonnet-4`, `PriceTable` and the
      Anthropic client use `claude-sonnet-4-20250514`. Unify (price table already
      has both).
- [ ] `minInt` duplicated in `inventory.go` and `triage.go`.
- [ ] `golangci-lint` `install-tools` target installs `@latest` while CI pins
      `v2.1.6` — pin both.
- [ ] `Makefile` `test` does not run `-tags integration`; add `test-integration`.
- [ ] goreleaser for multi-platform releases + a `release.yml` workflow.
- [ ] pre-commit hooks (optional).
- [ ] macOS CI job to exercise the darwin-only iOS tools (soft-fail).

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

1. §1.1–§1.2 (platform detection + model schema) — everything else depends on it.
2. §2.1–§2.2 (Android manifest depth) — highest false-positive/negative win per hour.
3. §1.3–§1.6 (iOS analyzers + wiring) — the big feature.
4. §2.3–§2.4 (inventory.json + signing/integrity).
5. §3 (tests) and §4 (docs/CHANGELOG) before tagging `v0.1.0`.
6. §5 SARIF export + §6 `/metrics` (small, high visibility).
7. The rest as needed.
