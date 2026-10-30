# Roadmap

**Status:** living document · last updated 2026-10-30
**Português:** [roadmap.pt-BR.md](roadmap.pt-BR.md)

This file records what is done, what comes next, and the decisions behind
each step. Use it together with
[docs/analyzers.md](analyzers.md) (per-stage reference) and
[docs/artifacts.md](artifacts.md) (artifact schema).

## Principles

1. **Signal before volume.** A finding that fires on every third-party library
   is noise. Aggregate or remove it.
2. **Do not depend on a decompiler for core facts.** Manifest, resources,
   DEX strings and signature material can be read directly from the APK.
3. **Every new backend is optional and fail-soft.** A missing tool must never
   break a run; it must degrade the report, not the pipeline.
4. **Findings must stay deterministic.** IDs are derived from tool, category,
   file, line and snippet (ADR-002). Backend changes that alter locations need
   an explicit compatibility decision.
5. **Document the decision, not just the task.** Architectural choices get an
   ADR in [docs/adr/](adr/).

## Current state (Android)

The default run (`mobiscope analyze app.apk`) executes `apktool`, `jadx`,
`apksigner`, `elf`, `anti-analysis`, `repack`, `sdk` and `inventory`.
`gitleaks` and `semgrep` are opt-in via `--stages`.

Known strengths:

- In-process ELF hardening and anti-analysis from the APK itself.
- Manifest decoded with `encoding/xml` and NSC resolved from the manifest.
- Deterministic findings, dedup/clustering, SARIF and Markdown output.
- Provider-agnostic LLM triage with a local secret gate.

Known gaps are grouped below. P0, P1 and P2 are implemented; P3 is planned.

## P0 — signal quality (done)

These changes removed the noise that made a real report (TP-Link IoT, 47k ZIP
entries, 18 DEX files) unreadable: 1,597 findings, of which 1,080 were pinning
indicators, 424 IP addresses and 43 e-mails.

### Findings and aggregation

- **Pinning is app-level.** `inventory` now emits one informational
  `pinning_indicator` finding listing the markers found
  (`X509TrustManager`, `CertificatePinner`, `TrustKit`, `sha256/`,
  `pin-sha256`, `BEGIN CERTIFICATE`). The aggregate lives in
  `inventory.json` (`pinning_indicators`, `pinning_count`).
- **IPs and e-mails are inventory data, not findings.**
  `ip_count`/`ips` and `email_count`/`emails` are bounded, sorted samples.
- **Platform is always set.** Every `inventory` finding now carries
  `platform: android`.
- **Private keys require a full PEM block.** Header-only constants (JSch,
  Netty and similar parsers) no longer produce critical false positives. The
  matched PEM block must contain a valid base64 body, and the body is redacted
  from evidence, reports and LLM prompts.
- **Client-side keys are informational.** GCP API keys, Google OAuth client
  IDs and Firebase URLs are identifiers, not server secrets; they are reported
  as `info` with an explanation.
- **Repack was recalibrated.** Multidex, a v2/v3-only signature and a
  normalized ZIP timestamp are normal and no longer produce findings. The
  stage now reports executable payloads in `assets/` (high) and native
  libraries in `assets/` (low).
- **Repack and SDK findings are actually emitted.** `Repack` and `SDK` now
  implement `ConvertFindings`, so the pipeline's `FindingConverter` assertion
  reaches them.
- **Anti-analysis false positives removed.** The stage no longer scans data
  assets (Unity metadata and similar blobs); it scans DEX and executable
  assets only. Bare `su`/`gadget` needles were removed, so ordinary words no
  longer trigger root/Frida findings.
- **`--stages` spelling is normalized.** `anti-analysis` and `anti_analysis`
  now select the same analyzer; previously the documented hyphen form matched
  nothing.
- **Report shows cluster representatives.** `report.md` renders the
  representative of each cluster plus “N more occurrences”; `findings.json`
  and `report.sarif` keep every occurrence.

### Signing

- `apksigner` findings are wired into the pipeline (debug-signed, no signer,
  v1-only).
- When `apksigner` is unavailable (the Docker image does not ship it), the
  fallback now detects the **APK Signing Block** (v2/v3) instead of assuming
  that a missing `META-INF/*.RSA` means “unsigned”. This removes a false
  critical finding on modern v2/v3-only APKs.

### Semgrep pack

The Android pack now validates under `semgrep 1.127.1`
(`semgrep --validate --config internal/rules/mastg/rules.yaml`). Fixes:

- `mastg-trustmanager-bypass` only matches empty trust checks, not every
  `checkServerTrusted` implementation.
- `mastg-crypto-hardcoded-key` only matches literal keys.
- `mastg-storage-world-accessible` only matches `MODE_WORLD_*`.
- `mastg-crypto-no-padding` matches `".../NoPadding"` transformations.
- `mastg-webview-ssl-error` only inspects `onReceivedSslError` handlers.
- `mastg-webview-file-access` uses a valid semgrep severity.
- `mastg-exported-component` is scoped to `AndroidManifest.xml`.
- `mastg-crypto-pbe-weak` had an invalid pattern (`$PBEKeySpec(...)`) that
  made the whole pack unloadable; it now uses `new PBEKeySpec(...)`.

### Inventory

- `obfuscation` is populated from the `anti-analysis` stage (ratio, class
  count, toolchain).
- `network.kind` is only set when a network security config exists;
  `cleartext_permitted` and `pinned` are populated from it.

## P1 — Android-native analysis (done)

Goal: make the core checks independent of `apktool`/`jadx` and fast enough for
CI. The inventory stage now reads the APK in-process and only falls back to the
decoded tree when the native parse fails. See
[ADR-010](adr/010-native-apk-parsing.md).

1. **AXML and `resources.arsc` parser in Go.** (done)
   `axml.go` decodes compiled binary XML (string pool, resource map, typed
   values, namespaces, CDATA); `arsc.go` parses the resource table so
   `@xml/…` / `@string/…` references resolve without apktool. `inventory`
   reads `AndroidManifest.xml` and the network security config straight from
   the APK, so manifest/permission/NSC findings survive a decompiler OOM and
   `--stages inventory` works on a fresh session directory (`--quick` is
   meaningful).
2. **DEX string-table scanner.** (done)
   Every `classes*.dex` string pool is scanned for secrets, URLs, IPs, e-mails,
   pinning markers and the same code patterns as the tree. DEX hits are
   deduplicated against tree hits by category + evidence, and DEX aggregates
   are merged only when the tree produced none. This closes the gap where
   `semgrep` is opt-in and only sees `.java`.
3. **Full network security config parse.** (done)
   `nsc.go` parses base and per-domain `cleartextTrafficPermitted`,
   `debug-overrides`, `overridePins`, `pin-set`/`expiration` and trust anchors.
   Only genuine relaxations become findings; the structured result fills
   `inventory.network.exceptions`.
4. **targetSdk-aware manifest checks.** (done, assetlinks deferred)
   - `android:exported` / provider defaults depend on `targetSdk` and the
     component kind; a missing attribute on targetSdk ≥ 31 is not reported as
     exported (the platform rejects that manifest).
   - App Links: a browsable `https` VIEW filter without `autoVerify` is
     reported. Fetching `assetlinks.json` is intentionally left to a network
     stage (`--osv` is still the only egress).
   - Task hijacking combines `taskAffinity`, `launchMode` and
     `allowTaskReparenting`.
   - `usesCleartextTraffic` default by `targetSdk`; `<grant-uri-permission>`
     children; provider defaults.
   - `dataExtractionRules`/`fullBackupContent` are surfaced; flagging sensitive
     directories from the rules file is still a P2 refinement.
5. **Finding origin.** (done)
   `Finding.origin` is `app` or `sdk:<name>`, derived from the `sdk` class
   prefixes mapped onto decompiled paths. The pipeline fills it for
   semgrep/gitleaks findings, so “OkHttp mentions X509TrustManager” and “the
   app disables TLS validation” are distinguishable in the report.

## P2 — coverage (done)

- **Kotlin and taint.** (done) The pack has Kotlin-specific rules (hardcoded
  secrets, `addJavascriptInterface`, sensitive logging, weak ciphers, SQL
  concatenation) and taint-mode rules for intent/deeplink → WebView, SQL,
  file and exec, clipboard → log, and intent redirection. It also covers
  `ContentProvider.openFile` traversal and mutable PendingIntent (the generic
  PendingIntent rule was tightened to require a missing `FLAG_IMMUTABLE`).
  The Docker build now validates both packs with `semgrep --validate`.
- **Native depth.** (done) `RegisterNatives` is flagged; `.so` files under
  `assets/` are inspected; `DT_SONAME`, Shannon entropy and packer signatures
  (UPX, 360 Jiagu, Tencent Legu, Alibaba, Bangcle, …) land in
  `native_libs`, with `obfuscation` findings for high entropy and packing.
- **SDK detection.** (done) Signatures cover Huawei HMS, WeChat, Bugly,
  MMKV, Alipay, Umeng, JPush, Baidu, Play Billing, Flutter, Unity, Apache
  HttpClient, Bouncy Castle, SQLCipher, ZXing and the Kotlin stdlib, in
  addition to the Firebase/OkHttp/Gson set. Versions come from
  `META-INF/maven/*/pom.properties`, decoded string resources and decompiled
  `BuildConfig` classes; native-only SDKs are detected from `.so` names.
- **Signing in Go.** (done) The APK Signing Block v2/v3/v3.1 is parsed and
  cryptographically verified in-process: signature over the signed data,
  chunked content digest (SHA-256/SHA-512), scheme, signer count, certificate
  SHA-256 fingerprint, subject, validity and key algorithm/size, plus v1
  presence and debug detection. A tampered artifact is reported as
  `digest-mismatch`/`invalid-signature`. Rotation lineage and source-stamp
  presence are detected.
- **Obfuscation stage.** (done for the P2 scope) The anti-analysis stage
  detects R8/ProGuard/DexGuard artifacts, short class names and obfuscation
  tooling, and `analyze --mapping mapping.txt` rewrites obfuscated class paths
  and class names in findings before baseline/triage. Reflection and runtime
  Base64 string decoding are flagged by both `anti-analysis` and semgrep
  (`mastg-reflection`, `mastg-string-encryption`).
- **Diff, baseline and CI gate.** (done) `mobiscope diff old.apk new.apk`
  with `--json`, `analyze --baseline <findings.json|session.json>` and
  `analyze --fail-on <severity>` (exit code 2). Matching is fingerprint-based
  and line-number independent. A built-in allowlist skips AndroidX/library
  infrastructure components, and `--allowlist allowlist.yaml` accepts
  user-extensible rules (each with a mandatory reason) for known public
  identifiers.
- **Validate stage names.** (done) An unknown `--stages` entry now fails the
  run with the valid names for the detected platform.

## P3 — performance and reporting

- Stop running both decompilers in full by default. (done) The default is
  now `jadx` only; the native AXML/arsc parser covers manifest/resources/NSC,
  and `apktool` runs only when named or with `--decompiler`.
- Cache decompiler output by APK SHA and offer `--reuse`. (done) The session
  directory is already SHA-keyed; `--reuse` skips a decompiler whose tree
  exists.
- `scanPatterns`: (partial) rules carry a cheap `Needle` prefilter before the
  regex engine; vendor-directory skipping and a parallel walk are still open.
- Report: (done) representatives plus counts, top clusters/categories and an
  attack-surface section (package/version/targetSdk, permissions, SDKs, native
  ABIs, network policy, signing). Deep-link/component lists are still derived
  from findings rather than a dedicated surface table.
- Triage: (done) only representatives with severity ≥ `low` are sent; info
  findings are inventory/surface facts and skip the LLM.
- Golden fixtures with the false-positive traps (PEM in parser code, Firebase
  keys, multidex, zipalign timestamps) to lock the behavior.
- Obfuscation depth: scoring string encryption beyond Base64 detection,
  server-side deobfuscation beyond the class/file mapping, and validating the
  v3 rotation lineage and source-stamp chains.
- Native lib version recovery from SONAME/filename for OSV matching.

## Decompiler backends

The pipeline currently hardcodes `jadx` as the tree producer. That is the
slowest and most fragile part of a run: the timeout is 15 minutes and large
APKs can run out of memory.

### Candidate: `androguard/dex-decompiler`

[androguard/dex-decompiler](https://github.com/androguard/dex-decompiler) is a
pure-Rust DEX → Java decompiler from the Androguard project (Apache-2.0).
Relevant properties:

- full-tree export (`-d out/`), compatible with the current
  `SourceRoot`/gitleaks/semgrep/inventory contract;
- query fast path (`--getclass`, `--findrefs`) without a global index;
- built-in security analysis: `--scan-vulns`, `--scan-semgrep` (MASTG) and
  `--taint-solve` (Mariana Trench-style interprocedural taint);
- Rust library API and Python bindings;
- no JVM, low memory footprint.

It does **not** decode `res/` or `resources.arsc`, so it cannot replace
`apktool` for resources. The native AXML/arsc parser in P1 is the complement.

### Integration shape (proposed, not implemented)

- `--decompiler jadx|dexdc|both`, default `jadx`.
- Optional stage `dexdc`, fail-soft, pinned commit, `allowedBinaries` entry,
  output under `<session>/dexdc/`.
- `SourceRoot` resolves the selected backend explicitly; a session never mixes
  two trees silently.
- Converters for `--scan-vulns` and `--taint-output` feed `Finding` objects
  with `SourceTool=dexdc` and a category mapping; dedup by rule/MASVS against
  the semgrep/gitleaks findings.
- `jadx` remains the reference backend until the evaluation below passes.

See [ADR-009](adr/009-decompiler-backends.md).

### Evaluation harness (acceptance criteria)

Run both backends against the same APK (start with a large real target) and
compare:

| Metric | Target |
|--------|--------|
| Recall of known findings (secrets, pinning, manifest) | ≥ 95% of the jadx run |
| Semgrep parse-error rate on the emitted tree | < 5% |
| Full-tree export time (230 MB APK) | < 30 s |
| Peak RSS | < 1 GB |
| `findings.json` IDs | stable or explicitly documented as changed |
| `--findrefs` on 20 known sinks | correct class/method for all |

Do not promote the backend to default on benchmarks alone; the differential
result is the decision input.

### Risks

- Both the decompiler and its security scanners are young (0.1.x); output and
  rule semantics can change. Pin an exact commit and keep `jadx` available.
- Pseudocode that semgrep cannot parse produces silent false negatives.
- Taint engines can report false positives and, worse, false negatives; treat
  their output as an additional source with its own confidence.
- New backends can change file/line locations and therefore deterministic
  finding IDs. Decide between normalizing locations to class/method or
  accepting an ID migration.
- No published releases: build from a pinned commit, commit `Cargo.lock`, run
  `cargo audit`, and keep the toolchain in a separate Docker stage.

## Suggested order

1. P0 (done) — make the report readable.
2. P1 (done) — native manifest/DEX parsing, full NSC, targetSdk checks and
   finding origin.
3. P2 diff/baseline/CI gate (done).
4. P2 Kotlin/taint, signing verification, native depth and SDK detection
   (done).
5. Decompiler backend evaluation, then `--fast`.
6. P3 performance/reporting.
