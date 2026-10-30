# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- In-process Android analyzers: `elf` (native-library hardening, JNI
  exports, anti-analysis strings), `anti-analysis` (obfuscation plus
  root/emulator/anti-debug/instrumentation markers), `repack` (unexpected
  certificate, executable/native payloads in assets) and `sdk` (third-party
  library inventory). They run directly on the APK, without a decompiler.
- Native AXML and `resources.arsc` parsers: `inventory` reads the binary
  manifest, resource references and the network security config straight
  from the APK, and only falls back to the decompiled tree when that fails.
- DEX string-pool scanner: secrets, URLs, IPs, e-mails, pinning and code
  patterns are found without `jadx`/`semgrep`, with duplicates against the
  tree removed.
- Full network security config parse (per-domain cleartext, debug overrides,
  pin-set expiration, trust anchors) feeding `inventory.network.exceptions`.
- `targetSdk`-aware manifest checks: exported/provider defaults, App Links
  without `autoVerify`, task hijacking, pre-API-28 cleartext and
  `<grant-uri-permission>`.
- `Finding.origin` (`app` / `sdk:<name>`) attributes each finding to the app
  or to a bundled third-party library.
- `--stages` validation: an unknown stage now fails with the list of valid
  names instead of silently running nothing.
- Android default now runs `jadx` only; `apktool` is opt-in via `--stages` or
  `--decompiler both`. `--reuse` skips a decompiler whose SHA-keyed session
  tree already exists.
- `report.md` gains an attack-surface section (package/version/targetSdk,
  permissions, SDKs, native ABIs, network policy, signing).
- LLM triage skips `info` findings, which are inventory/surface facts.
- `scanPatterns` scans files with a bounded worker pool, skips vendor SDK
  trees (the DEX scanner covers their strings) and keeps the `Needle`
  prefilter before the regex engine.
- Golden fixtures cover header-only PEM, complete/escaped PEM and client-side
  identifiers; complete PEM blocks escaped as Java/Kotlin `\n` are now
  detected and redacted.
- Optional `dexdc` backend (`dex-decompile`) selectable with
  `--decompiler dexdc` / `--decompiler jadx,dexdc`, fail-soft and with its own
  output tree; `SourceRoot` resolves it after jadx/apktool.
- `scripts/evaluate-decompiler.py` runs the ADR-009 differential evaluation
  (time, RSS, recall, fingerprint overlap, semgrep errors, acceptance checks).
- CI gate: `analyze --fail-on <severity>` exits with code 2 on matching
  findings; `--baseline <findings.json|session.json>` suppresses known ones
  before triage.
- `mobiscope diff <old> <new>` with `--json <path>`, matching findings by a
  line-independent fingerprint (new/resolved/unchanged).
- In-process APK signing-block parser and cryptographic verifier: v2/v3/v3.1
  signature and chunked content digest (SHA-256/SHA-512), scheme, signer
  certificate SHA-256 fingerprint, subject, validity and key size, plus v1
  presence, debug detection, rotation/source-stamp presence. New findings for
  a failed signature check, an expired signing certificate and a weak RSA key.
- Native depth: `.so` files under `assets/`, `DT_SONAME`, Shannon entropy,
  packer signatures and `RegisterNatives` detection.
- More SDK signatures: Huawei HMS, WeChat, Bugly, MMKV, Alipay, Umeng, JPush,
  Baidu, Play Billing, Flutter, Unity, Apache HttpClient, Bouncy Castle,
  SQLCipher, ZXing and the Kotlin stdlib. Versions are recovered from
  `META-INF/maven/*/pom.properties`, decoded string resources and decompiled
  `BuildConfig` classes; native-only SDKs are detected from `.so` names.
- Semgrep Android pack: Kotlin rules plus taint-mode coverage for
  intent/deeplink → WebView, SQL, file and exec, clipboard → log and intent
  redirection; `ContentProvider.openFile` traversal and a tightened mutable
  `PendingIntent` rule. 41 rules total, validated during the Docker build.
- `analyze --mapping mapping.txt` deobfuscates finding locations and class
  names through an R8/ProGuard mapping before baseline/triage.
- Reflection (`Class.forName`, reflective method lookup/invoke) and runtime
  Base64 string decoding are flagged by `anti-analysis` and by the new
  `mastg-reflection` / `mastg-string-encryption` semgrep rules.
- A built-in allowlist skips exported AndroidX/library infrastructure
  components that are not app-specific attack surface.
- `analyze --allowlist allowlist.yaml` suppresses documented exceptions by
  tool/category/rule/title/file/evidence, with a mandatory reason per rule.
- `analyze --expect-cert <hex>` flags a signing certificate that does not
  match the expected fingerprint.
- `analyze --osv` looks the detected libraries up in OSV.dev (opt-in; the
  only network egress during analysis) and `analyze --sbom` writes a
  CycloneDX 1.5 `sbom.cdx.json`.
- Semgrep rule packs are embedded in the binary (`internal/rules`), so an
  installed build no longer depends on the working directory; the Android
  pack now carries 29 rules.
- LLM prompts are redacted for credential-shaped values before leaving the
  machine; retries honour `Retry-After`; `llm.cache_ttl_hours` sets the cache
  TTL.
- Tests for `internal/osv`, `internal/sbom` and the embedded rule packs.
- Platform detection (`internal/platform`) for Android APK and iOS IPA from
  the ZIP central directory; the detected platform is recorded on the session
  and in the report.
- iOS analyzer set: `ipa-extract` (zip-slip-safe unpack), `plist` (ATS,
  file-sharing, URL schemes), `macho` (native libs, encryption, dylib
  linkage), `codesign` (entitlements, provisioning profile), `strings`
  (secret/pinning regexes), `inventory-ios` (obfuscation + combined signals).
- `internal/rules/mastg-ios/rules.yaml` semgrep pack for Swift/Objective-C/C.
- Android manifest decoded with `encoding/xml`: typed exported components,
  intent-filters, modern dangerous permissions, custom permission protection
  levels, `allowBackup`/`testOnly`/`usesCleartextTraffic`/`grantUriPermissions`.
- Network security config resolved from `android:networkSecurityConfig`;
  `overridePins=true` reported; `trust-anchors src="system"` no longer a
  false positive.
- `apksigner` analyzer (signing scheme, cert fingerprint, debug-signed,
  v1-only detection) and `inventory.json` with structured `AppInventory`.
- `analyze --expect-sha256` gate, `--fail-fast`, `--dry-run`,
  `--max-concurrency`; graceful shutdown on SIGINT/SIGTERM.
- Parallel analyzer execution (errgroup + `pipeline.max_concurrency`).
- Batch mode: `analyze a.apk b.ipa …` runs several targets in one command
  with per-target session dirs and a summary table.
- `FindingConverter` interface: analyzers convert their own output instead of
  a growing name switch in the pipeline.
- Scanner patterns: JWTs, Azure Storage connection strings, predictable IVs
  (`IvParameterSpec(null)` / `new byte[]` / hex literals).
- Six semgrep rules: HostnameVerifier bypass, `addJavascriptInterface`,
  `DexClassLoader`, sensitive `Log.*` calls, DES/RC4 ciphers, and
  `Cipher.getInstance("AES")` defaulting to ECB.
- Generic URLs are demoted from findings to an aggregate (`url_count`, `urls`)
  in `inventory.json`.
- Richer `/metrics`: analyzer runs/errors/duration per tool, findings by
  severity/category, LLM calls by provider/result, cumulative LLM cost and
  cache hit/miss counters (`internal/metrics`), plus `request_id` on API LLM
  logs and a model-registry fallback for offline provider listings.
- Executive summary in `report.md` (severity rollup, top clusters/categories,
  triage count + cost); the Markdown report template is now fully English.
- `docs/adr/004`–`009` (platform detection, ErrExit, binary allowlist, retry
  policy, pipeline phases, decompiler backends), `docs/artifacts.md`,
  `docs/analyzers.md`, `docs/roadmap.md` (with a Portuguese version),
  goreleaser + release workflow, optional pre-commit hooks, macOS CI
  soft-fail job for darwin-only tools.
- Tests: `platform.Detect` fuzzing, `handleLLMTest` routing/cloud refusal,
  concurrent + corrupt-cache tests, semgrep exit codes, direct
  `buildAnalyzers`/`runTriage`/`countTriaged` coverage, apksigner parse and
  mock-binary fixtures, synthetic IPA e2e, fakebin CLI integration tests,
  ATS matrix and entitlement severity coverage.
- `keychain-access-groups` wildcard entitlement finding.
- LLM retry with exponential backoff + jitter, `Retry-After` handling and a
  per-call timeout (`llm.max_retries`, `llm.retry_base_delay_ms`,
  `llm.timeout_seconds`).
- SARIF 2.1.0 export (`report.sarif`).
- Prometheus `/metrics` endpoint.
- `mobiscope serve` HTTP API bound to `127.0.0.1:8080` by default with
  optional `MOBISCOPE_API_TOKEN` bearer auth.
- Layered configuration: defaults < TOML file < environment variables < CLI
  flags. `MOBISCOPE_*` generic overrides plus well-known provider credentials.
- Free-form `[llm.providers.<name>]` map supporting any number of providers.
- Docker image shipping gitleaks, semgrep, apktool and jadx; hardened
  docker-compose with healthcheck and loopback port binding.
- GitHub Actions CI (lint, test, govulncheck, docker build) and Dependabot.

### Changed

- **Android signal quality:** pinning is reported once per app instead of once
  per occurrence; IPs and e-mails moved from findings to
  `inventory.json` (`ip_count`/`ips`, `email_count`/`emails`); GCP API keys,
  Google OAuth client IDs and Firebase URLs are informational client-side
  identifiers; private keys are redacted from evidence.
- `report.md` renders one row per cluster plus an “N more occurrences” count;
  `findings.json`/`report.sarif` still contain every occurrence.
- `repack` no longer flags multidex, a v2/v3-only signature or a normalized ZIP
  timestamp (normal for modern apps); it reports executable/native payloads
  in `assets/` instead.
- `inventory.json.network.kind` is only set when a network security config
  exists, and `obfuscation` is populated from the `anti-analysis` stage.
- `--stages` accepts hyphen/underscore spellings (`anti-analysis` and
  `anti_analysis`), so the documented name actually selects the analyzer.
- Semgrep rule packs moved from `rules/` to `internal/rules/` and are
  embedded in the binary, then materialized to a process-owned temp
  directory for semgrep.
- Independent in-process stages run concurrently with the decompilers, and a
  tool failure marks the session `partial` instead of dropping the run.
- **Finding ID encoding** now NUL-delimits fields (`GenerateID`). IDs produced
  by earlier builds will not reproduce; determinism holds from this release
  forward.
- `ProvidersConfig` is `map[string]*ProviderConfig` (internal API). TOML/JSON
  schema is unchanged.
- Secrets found by semgrep are classified as `category=secret` and routed to
  local providers only.
- Gitleaks exit code 1 (leaks found) is a success; codes >= 2 are failures.
- `jadx --no-res` is only passed when `--no-res` is set (previously always).
- Scanners, the manifest reader and triage context resolve one source root
  (`analyzers.SourceRoot`: `jadx/` → `apktool/` → session root) instead of
  each hardcoding the jadx path, so `--stages apktool,…` runs are scanned.
- LLM cache writes are atomic (temp file + rename) and reads reject corrupt
  entries as misses.

### Fixed

- `Repack` and `SDK` did not implement `ConvertFindings`, so the pipeline's
  `FindingConverter` assertion skipped them and repack never emitted findings.
- A header-only PEM constant (JSch/Netty) was reported as a critical private
  key; the rule now requires a complete, base64-valid block and redacts it.
- When `apksigner` was unavailable, a v2/v3-only APK was reported as
  “no signer”; the fallback now detects the APK Signing Block.
- `inventory` pattern findings had `platform: null`; every Android finding now
  sets `platform: android`.
- `--stages anti-analysis` was silently ignored because the analyzer is named
  `anti_analysis`; stage matching now normalizes `-`/`_`.
- The anti-analysis stage scanned every `assets/` blob for markers; generic
  words in Unity metadata produced Frida/Xposed/root false positives. It now
  scans only executable assets, and the bare `su`/`gadget` needles were
  removed.
- The Docker build failed on the jammy base because the bundled `pip3`
  segfaulted while resolving semgrep; pip is upgraded before the install.
- `make install-tools` used the pre-v2 golangci-lint module path.
- Android semgrep rules over-matched (`checkServerTrusted`, any
  `SecretKeySpec`, any file mode, any `proceed()`) and the pack contained an
  invalid `$PBEKeySpec(...)` pattern that made it unloadable. The pack now
  validates under `semgrep 1.127.1`.
- TOML config file and environment variables were never actually loaded.
- `--config` and `--provider` flags were documented but not wired.
- LLM triage results were written to disk before enrichment and lost.
- `LLMCostUSD` was always zero.
- `ErrCloudNotAllowed` never produced exit code 4 from triage.
- Cluster over-grouping (first title token) and missing verdict propagation.
- `f.ID[:8]` panic on short ids; report silently dropped unknown severities.
- Gemini API key leaked into URL query strings.
- `SafeRmtree` could delete arbitrary paths; symlinks in decompiled trees were
  followed into findings and LLM prompts.
- Prompt injection via untrusted evidence (now fenced).
- `--expect-sha256` was enforced but the flag was never registered, so the
  documented gate was unreachable from the CLI.
- apksigner: debug-signed detection was shadowed by a generic case (always
  empty) and signer counts over-counted; only `: true` scheme lines count.
- semgrep stdout fallback rewrapped a SARIF object into an array the converter
  could not read.
- ATS exceptions with a minimum TLS below 1.2 (`NSTemporaryExceptionMinimumTLSVersion`)
  were not flagged.
- **Semgrep packs did not load on the pinned 1.127.1**: both packs lacked the
  top-level `rules:` wrapper (`was not a mapping`), the iOS pack declared the
  unsupported `objc` language, every `pattern-regex: |` block scalar carried a
  trailing newline that killed all matches, and `mastg-ecb-mode` ANDed two
  mutually exclusive regexes. Packs validated end-to-end under
  `semgrep/semgrep:1.127.1` (all 29 Android rules fire) and guarded by
  `TestRulePacks_SemgrepSchema`.
- `rules.Cleanup` now removes the materialized pack directory and resets the
  one-shot state, so a later `Materialize` does not return a stale path.

### Security

- Bumped `github.com/go-chi/chi/v5` to 5.4.0, fixing client IP spoofing via
  `X-Forwarded-For` (Dependabot alert #1).

## [0.0.1] - 2026-09-22

### Added

- Initial release: APK analysis pipeline (apktool, jadx, gitleaks, semgrep,
  inventory), LLM triage with provider-agnostic router and local-first
  privacy policy, JSON/Markdown reports.
