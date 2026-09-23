# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Platform detection (`internal/platform`) for Android APK and iOS IPA from
  the ZIP central directory; the detected platform is recorded on the session
  and in the report.
- iOS analyzer set: `ipa-extract` (zip-slip-safe unpack), `plist` (ATS,
  file-sharing, URL schemes), `macho` (native libs, encryption, dylib
  linkage), `codesign` (entitlements, provisioning profile), `strings`
  (secret/pinning regexes), `inventory-ios` (obfuscation + combined signals).
- `rules/mastg-ios/rules.yaml` semgrep pack for Swift/Objective-C/C.
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

- **Finding ID encoding** now NUL-delimits fields (`GenerateID`). IDs produced
  by earlier builds will not reproduce; determinism holds from this release
  forward.
- `ProvidersConfig` is `map[string]*ProviderConfig` (internal API). TOML/JSON
  schema is unchanged.
- Secrets found by semgrep are classified as `category=secret` and routed to
  local providers only.
- Gitleaks exit code 1 (leaks found) is a success; codes >= 2 are failures.
- `jadx --no-res` is only passed when `--no-res` is set (previously always).

### Fixed

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

## [0.0.1] - 2026-09-22

### Added

- Initial release: APK analysis pipeline (apktool, jadx, gitleaks, semgrep,
  inventory), LLM triage with provider-agnostic router and local-first
  privacy policy, JSON/Markdown reports.
