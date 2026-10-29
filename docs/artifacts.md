# Artifact reference

Every `analyze` run writes its outputs into a single **session directory**.
This document lists each artifact, its exact JSON shape (derived from the
Go structs that marshal it), and which fields are Android-only or iOS-only.

Everything below is written by `internal/pipeline/pipeline.go`
(`PersistArtifacts`, `persistMeta`, phase 3b) unless noted otherwise.

## Session directory

```
<workdir>/<session-id>/
├── apktool/                     # apktool stage output      (Android)
│   ├── AndroidManifest.xml
│   └── apktool.yml
├── jadx/                        # jadx stage output         (Android)
│   ├── AndroidManifest.xml
│   ├── res/xml/network_security_config.xml
│   └── sources/com/...
├── extract/                     # ipa-extract stage output  (iOS)
│   └── Payload/<App>.app/...
├── gitleaks-report.json         # raw gitleaks report       (if stage ran)
├── semgrep.sarif                # raw semgrep SARIF         (if stage ran)
├── inventory.json               # AppInventory (pipeline)
├── sbom.cdx.json                # CycloneDX 1.5 bill of materials (--sbom)
├── findings.json                # []Finding
├── session.json                 # AnalysisSession
├── meta.json                    # run + per-tool metadata
├── report.md                    # human report (template)
└── report.sarif                 # SARIF 2.1.0 export
```

- `session-id` = first 16 hex chars of the SHA-256 of the analyzed file
  (`sha256[:16]`), so the same bytes always map to the same directory.
  Re-running overwrites in place; there is no per-run history.
- `workdir` defaults to `targets/` (`--workdir`). The session directory is
  also the `workdir` handed to every analyzer, which is why the trees above
  live inside it.
- Directories are created `0755`, artifacts written via `utils.WriteFile`
  are `0600` (the raw tool outputs `gitleaks-report.json` / `semgrep.sarif`
  keep whatever permissions the external tool used).
- `--dry-run` writes nothing (it only prints the stage list and
  `Available()` results to stderr).

| Artifact | Producer | Rewritten |
|----------|----------|-----------|
| `findings.json`, `session.json`, `report.md`, `report.sarif` | `PersistArtifacts` (phase 7) | again after `--triage`, so LLM enrichment is not lost |
| `meta.json` | `persistMeta` | once per run |
| `inventory.json` | pipeline phase 3b | once per run (always, even when `inventory` is not a selected stage) |
| `sbom.cdx.json` | `--sbom` flag, after the pipeline | once per run |
| `gitleaks-report.json`, `semgrep.sarif` | external tools | each time the stage runs |
| `SHA256SUMS` | **not implemented** | planned in PENDING.md §2.4 (chain of custody); today the SHA-256 only appears as `apk_hash` (session.json) / `apk_sha256` (meta.json) |

## findings.json

A JSON array of `Finding` objects (2-space indent), sorted by severity, then
file, then line (`report.SortFindingsBySeverity`). Empty runs produce `[]`.

### Fields

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | Deterministic 16-hex ID — see [Determinism](#determinism-of-finding-ids) |
| `session_id` | string | Equals the session directory name |
| `source_tool` | string | `gitleaks`, `semgrep`, `inventory`, `inventory-ios`, `ipa-extract`, `plist`, `macho`, `codesign`, `classdump`, `strings` |
| `category` | enum | `secret`, `code_pattern`, `manifest_issue`, `network_config`, `pinning_indicator`, `entitlement`, `binary_hardening`, `obfuscation`, `native_code`, `privacy` |
| `title`, `description`, `evidence` | string | last two are `omitempty` |
| `location` | object | `file` (relative to the scanned root), `line` (always present, `0` when unknown — no `omitempty`), `snippet` |
| `severity` | enum | `critical`, `high`, `medium`, `low`, `info` (unknown values are preserved on read for forward compatibility) |
| `sensitivity` | enum | `public`, `internal`, `confidential`, `secret` |
| `confidence` | float | 0..1, omitted when `0` |
| `platform` | enum | `android` / `ios` / `unknown`. **Set** by every iOS converter and by the Android manifest/NSC findings; **omitted** by scanner findings (gitleaks, semgrep, inventory pattern scan). `session.platform` is authoritative |
| `rule_id` | string | Semgrep rule ID only |
| `masvs`, `mastg` | []string | From semgrep rule metadata surfaced in SARIF `rule.properties` |
| `maswe`, `cwe` | []string | Schema-reserved: the converter can read `cwe` from rule metadata, but no shipped rule pack declares `cwe`/`maswe` today |
| `metadata` | map | Schema-reserved: no producer writes it yet |
| `needs_llm_triage` | bool | True for cluster representatives (clustering marks the first member of each cluster and clears the flag on the rest); gitleaks/semgrep converters also set it at creation time |
| `cluster_id` | string | `"cl-" + hex(sha256(tool\|category\|lower(title)\|file-ext))[:16]` |
| `representative` | bool | First cluster member by (file, line) |
| `llm_verdict` | enum | `confirmed`, `likely_fp`, `inconclusive` — only after `--triage` |
| `llm_confidence`, `llm_explanation`, `llm_remediation`, `llm_provider`, `llm_model`, `llm_cost_usd`, `llm_raw_response` | — | Triage enrichment, all `omitempty` |

Platform coverage: `entitlement`, `binary_hardening`, `native_code` are
effectively iOS-only (only the iOS converters emit them);
`manifest_issue`/`network_config`/`pinning_indicator`/`secret` occur on both.

### Example (Android)

A session is always one platform, so `findings.json` mixes categories and
severities but never platforms. Android run (`session_id` = session dir):

```json
[
  {
    "id": "5f2c9a11e03b47d8",
    "session_id": "8433fc853aabf932",
    "source_tool": "gitleaks",
    "category": "secret",
    "title": "Secret detected: aws-access-key",
    "description": "Identified a pattern that may contain credentials for AWS.",
    "evidence": "AKIAIOSFODNN7EXAMPLE",
    "location": {
      "file": "sources/com/example/smoke/Config.java",
      "line": 4,
      "snippet": "private static final String AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\";"
    },
    "severity": "critical",
    "sensitivity": "secret",
    "confidence": 0.95,
    "needs_llm_triage": true,
    "cluster_id": "cl-29d5736ef652d6e6",
    "representative": true,
    "llm_verdict": "confirmed",
    "llm_confidence": 0.9,
    "llm_explanation": "The literal matches the AWS access key ID pattern and is assigned to a static field, so it ships in the APK.",
    "llm_remediation": "Rotate the key, remove it from the binary and load credentials from a server-side store.",
    "llm_provider": "ollama",
    "llm_model": "qwen2.5-coder:7b",
    "llm_raw_response": "{\"verdict\":\"confirmed\",\"confidence\":0.9,\"explanation\":\"The literal matches the AWS access key ID pattern.\",\"remediation\":\"Rotate the key and remove it from the binary.\"}"
  },
  {
    "id": "b7e4f0a19c2d3e45",
    "session_id": "8433fc853aabf932",
    "source_tool": "semgrep",
    "category": "code_pattern",
    "title": "Use of MD5 hash algorithm which is cryptographically broken.",
    "description": "Rule mastg-weak-crypto-md5 matched MessageDigest.getInstance(\"MD5\").",
    "evidence": "MessageDigest.getInstance(\"MD5\")",
    "location": {
      "file": "sources/com/example/smoke/Crypto.java",
      "line": 18,
      "snippet": "MessageDigest digest = MessageDigest.getInstance(\"MD5\");"
    },
    "severity": "medium",
    "sensitivity": "internal",
    "confidence": 0.8,
    "rule_id": "mastg-weak-crypto-md5",
    "masvs": ["MASVS-CRYPTO-1"],
    "mastg": ["MASTG-TEST-0064"],
    "needs_llm_triage": true,
    "cluster_id": "cl-7d3c21f8aa09be14",
    "representative": true
  },
  {
    "id": "927f9cea5faa2b5c",
    "session_id": "8433fc853aabf932",
    "source_tool": "inventory",
    "category": "manifest_issue",
    "title": "Application is debuggable",
    "description": "android:debuggable=true allows debugging and inspection of the app.",
    "evidence": "android:debuggable=\"true\"",
    "location": {
      "file": "AndroidManifest.xml",
      "line": 1,
      "snippet": "android:debuggable=\"true\""
    },
    "severity": "high",
    "sensitivity": "confidential",
    "confidence": 1,
    "platform": "android",
    "needs_llm_triage": true,
    "cluster_id": "cl-bce0116ac903dbd6",
    "representative": true
  }
]
```

### Example (iOS)

```json
[
  {
    "id": "8851087da081df5f",
    "session_id": "5fe536c9f9deb99a",
    "source_tool": "codesign",
    "category": "entitlement",
    "title": "Debug entitlement: get-task-allow",
    "description": "get-task-allow=true marks a debug build; on a production device it allows any process to attach a debugger and read memory.",
    "evidence": "get-task-allow=true",
    "location": {
      "file": "entitlements.plist",
      "line": 1,
      "snippet": "get-task-allow=true"
    },
    "severity": "critical",
    "sensitivity": "confidential",
    "confidence": 1,
    "platform": "ios",
    "needs_llm_triage": true,
    "cluster_id": "cl-34634eca99d74696",
    "representative": true
  },
  {
    "id": "732bdfca0e6fc0b8",
    "session_id": "5fe536c9f9deb99a",
    "source_tool": "macho",
    "category": "binary_hardening",
    "title": "Encrypted binary (FairPlay)",
    "description": "SmokeApp is encrypted (LC_ENCRYPTION_INFO cryptid != 0); its body is not statically analyzable.",
    "evidence": "cryptid!=0",
    "location": {
      "file": "SmokeApp",
      "line": 1,
      "snippet": "cryptid!=0"
    },
    "severity": "info",
    "sensitivity": "internal",
    "confidence": 0.9,
    "platform": "ios",
    "cluster_id": "cl-9dd5857267101f71"
  }
]
```

The last object is a non-representative cluster member: no
`needs_llm_triage`/`representative` (both false are omitted) — it inherits
the representative's verdict after triage
(`PropagateClusterVerdicts`).

Reserved-field shape (`maswe`, `cwe`, `metadata`) that no current producer
emits, documented for schema completeness:

```json
{
  "rule_id": "mastg-weak-crypto-md5",
  "masvs": ["MASVS-CRYPTO-1"],
  "mastg": ["MASTG-TEST-0064"],
  "maswe": ["MASWE-0020"],
  "cwe": ["CWE-327"],
  "metadata": {
    "reference": "https://mas.owasp.org/MASWE/MASWE-0020/"
  }
}
```

### Determinism of finding IDs

`models.GenerateID(source_tool, category, file, line, snippet)` computes
`hex(sha256(join_NUL(source_tool, category, file, line, hex(sha256(snippet)))))[:16]`
— 16 hex chars (64 bits). Same inputs → same ID on every machine and every
run, which is what makes dedup, run-to-run diffing and the LLM cache work
(ADR-002). NUL separators prevent field-shifting collisions
(`file="a.java", line=12` vs `file="a.java1", line=2`). IDs changed once
(before `0.1.0`, see PENDING.md §8.1): `findings.json` produced by older
builds will not reproduce the same IDs. An ID changes whenever the snippet
changes — by design, that is a different finding.

## session.json

The `AnalysisSession` struct, marshalled with `started_at`/`completed_at` as
RFC 3339 strings (they are emitted **last**, after `findings`). Key order is
struct order.

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | Session directory name |
| `apk_path` | string | Original artifact path; the name is still APK-flavoured for IPAs (schema kept for compatibility) |
| `apk_hash` | string | Full SHA-256 of the artifact |
| `platform` | enum | `android` / `ios` |
| `package_name`, `version_name` | string | Always present (may be `""`); copied from `app` when non-empty (Android version from `apktool.yml`, iOS from `Info.plist`) |
| `app` | object | Same object as `inventory.json` (always emitted — struct `omitempty` does not apply) |
| `signing_cert_fp` | string | Android only, `omitempty` (empty when apksigner/META-INF gave nothing) |
| `signature_scheme` | string | Android only, `omitempty` — `v1`/`v2`/`v3`/`none` |
| `started_at`, `completed_at` | string | RFC 3339; `completed_at` omitted in dry-run |
| `status` | enum | `pending` (dry-run), `running`, `completed`, `failed` |
| `tool_results` | []ToolResult | Registration order; `null` if no stage ran |
| `findings` | []Finding | Identical objects to `findings.json` |
| `llm_cost_usd` | float | `omitempty`: cumulative triage cost, written after `--triage` |
| `summary` | string | Reserved: never written today |

`ToolResult` per entry:

| Field | Type | Notes |
|-------|------|-------|
| `tool_name`, `version` | string | In-process stages report `1.0.0`; external tools report `<binary> --version` (memoized) |
| `started_at` | string | RFC 3339 with nanoseconds |
| `duration` | **string** | Go duration, e.g. `"572.397942ms"` (custom marshaler) |
| `exit_code` | int | Per-tool exit code (ADR-005); `0` for in-process stages |
| `timed_out` | bool | Schema exists; nothing sets it today (timeouts surface via `error`) |
| `output` | raw JSON | Stage-specific; `null` when empty/invalid (guard `safeRaw`) |
| `error` | string | `omitempty`; set when the stage failed |

### Example (Android)

```json
{
  "id": "8433fc853aabf932",
  "apk_path": "/home/alien/mobiscope/.smoke-fixtures/smoke.apk",
  "apk_hash": "8433fc853aabf932bd87278f206b95af676086fe7b83dfd5c326d4681873ad0b",
  "platform": "android",
  "package_name": "com.example.smoke",
  "version_name": "2.1.0",
  "app": {
    "bundle_id": "com.example.smoke",
    "version_name": "2.1.0",
    "version_code": "12",
    "min_os": "24",
    "target_sdk": "34",
    "debuggable": true,
    "obfuscation": {},
    "network": {
      "kind": "network_security_config"
    },
    "permissions": [
      "android.permission.CAMERA",
      "android.permission.INTERNET"
    ]
  },
  "signing_cert_fp": "A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90",
  "signature_scheme": "v3",
  "tool_results": [
    {
      "tool_name": "apktool",
      "version": "apktool 2.11.1",
      "started_at": "2026-10-08T09:39:21.101002004-03:00",
      "exit_code": 0,
      "duration": "3.4821s",
      "output": {
        "stdout": "Using Apktool 2.11.1 to decode input file\n",
        "stderr": ""
      }
    },
    {
      "tool_name": "jadx",
      "version": "jadx version: 1.5.1",
      "started_at": "2026-10-08T09:39:24.590117338-03:00",
      "exit_code": 0,
      "duration": "8.927441s",
      "output": {
        "stdout": "",
        "stderr": "",
        "dex_warnings": null,
        "threads_used": 8
      }
    },
    {
      "tool_name": "gitleaks",
      "version": "gitleaks version 8.24.3",
      "started_at": "2026-10-08T09:39:33.520117001-03:00",
      "exit_code": 1,
      "duration": "572.397942ms",
      "output": [
        {
          "RuleID": "aws-access-key",
          "Description": "Identified a pattern that may contain credentials for AWS.",
          "StartLine": 4,
          "EndLine": 4,
          "StartColumn": 41,
          "EndColumn": 64,
          "Match": "private static final String AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\";",
          "Secret": "AKIAIOSFODNN7EXAMPLE",
          "File": "sources/com/example/smoke/Config.java",
          "Commit": "",
          "Author": "",
          "Email": "",
          "Date": "",
          "Message": "",
          "Tags": ["aws", "key"],
          "Fingerprint": "sources/com/example/smoke/Config.java:aws-access-key:4",
          "Entropy": 3.87
        }
      ]
    },
    {
      "tool_name": "inventory",
      "version": "1.0.0",
      "started_at": "2026-10-08T09:39:34.094561233-03:00",
      "exit_code": 0,
      "duration": "664.126µs",
      "output": null
    }
  ],
  "findings": [
    {
      "id": "927f9cea5faa2b5c",
      "session_id": "8433fc853aabf932",
      "source_tool": "inventory",
      "category": "manifest_issue",
      "title": "Application is debuggable",
      "description": "android:debuggable=true allows debugging and inspection of the app.",
      "evidence": "android:debuggable=\"true\"",
      "location": {
        "file": "AndroidManifest.xml",
        "line": 1,
        "snippet": "android:debuggable=\"true\""
      },
      "severity": "high",
      "sensitivity": "confidential",
      "confidence": 1,
      "platform": "android",
      "needs_llm_triage": true,
      "cluster_id": "cl-bce0116ac903dbd6",
      "representative": true
    }
  ],
  "started_at": "2026-10-08T09:39:21-03:00",
  "completed_at": "2026-10-08T09:39:34-03:00"
}
```

Notes:

- `gitleaks` exited `1` and is still a success (leaks found — ADR-005);
  `exit_code` records the real code.
- The signing identity comes from `apksigner verify --print-certs` (or the
  META-INF fallback) but the apksigner run itself is **not** listed in
  `tool_results` — it executes implicitly in phase 3b.
- iOS sessions look the same, minus `signing_*`, with `platform: "ios"` and
  stages `ipa-extract`, `plist`, `macho`, `codesign`, `classdump`,
  `strings` (+ `inventory-ios` when selected).

## meta.json

Run-level metadata written once. Same tools as `session.json` but:

- `started_at` on `tools[].started_at` uses Go's default RFC 3339
  **nanosecond** timestamps (top-level `started_at` likewise), and
- `tools[].duration` is a raw **integer of nanoseconds** (no custom
  marshaler on `ToolMeta`), unlike the duration string in `session.json`.

### Example

```json
{
  "apk_path": "/home/alien/mobiscope/.smoke-fixtures/smoke.apk",
  "apk_sha256": "8433fc853aabf932bd87278f206b95af676086fe7b83dfd5c326d4681873ad0b",
  "platform": "android",
  "started_at": "2026-10-08T09:39:21.22160333-03:00",
  "tools": [
    {
      "name": "apktool",
      "version": "apktool 2.11.1",
      "started_at": "2026-10-08T09:39:21.101002004-03:00",
      "duration": 3482100000,
      "exit_code": 0
    },
    {
      "name": "jadx",
      "version": "jadx version: 1.5.1",
      "started_at": "2026-10-08T09:39:24.590117338-03:00",
      "duration": 8927441000,
      "exit_code": 0
    },
    {
      "name": "gitleaks",
      "version": "gitleaks version 8.24.3",
      "started_at": "2026-10-08T09:39:33.520117001-03:00",
      "duration": 572397942,
      "exit_code": 1
    },
    {
      "name": "inventory",
      "version": "1.0.0",
      "started_at": "2026-10-08T09:39:34.094561233-03:00",
      "duration": 664126,
      "exit_code": 0
    }
  ]
}
```

`tools[].error` (`omitempty`) appears when a stage failed; the `inventory`
entry is only present when the inventory phase ran (it is a default stage).

## inventory.json

The `AppInventory` struct — observations, **not** findings (no severity, no
ID). Written unconditionally in phase 3b from the decoded manifest /
`apktool.yml` (Android) or `Info.plist` (iOS).

| Field | Type | Platform |
|-------|------|----------|
| `bundle_id` | string | both |
| `version_name`, `version_code` | string | both (Android from `apktool.yml`, iOS `CFBundleShortVersionString`/`CFBundleVersion`) |
| `min_os` | string | both (Android `minSdkVersion`, iOS `MinimumOSVersion`) |
| `target_sdk` | string | Android only (from `apktool.yml`) |
| `debuggable` | bool | Android only (`android:debuggable`) |
| `permissions` | []string | Android only (declared `<uses-permission>` entries) |
| `network` | object | both; only `kind` is populated today (`network_security_config` / `NSAppTransportSecurity`) |
| `obfuscation` | object | always emitted as `{}` today — obfuscation signals are reported as `anti_analysis`/`obfuscation` findings, not inventory |
| `native_libs` | []object | Android only, `omitempty`: populated by the `elf` stage (hardening flags, JNI exports, anti-analysis strings) |
| `sdks` | []object | Android only, `omitempty`: third-party libraries detected by the `sdk` stage (`name`, `group`, `artifact`, `version`, `package`, `evidence`, `confidence`) |
| `vulnerabilities` | []object | Android only, `omitempty`: OSV advisories for `sdks`, written only with `--osv` (`id`, `summary`, `severity`, `package`, `version`, `fixed_in`, `aliases`, `reference`) |
| `entitlements`, `url_schemes` | — | schema-reserved: never written by the current collectors |
| `url_count` | int | Android only, `omitempty`: total generic `http(s)://` matches in the scanned tree (the generic URL rule was demoted from findings to this aggregate) |
| `urls` | []string | Android only, `omitempty`: up to 100 unique normalized URLs, sorted — a sample, not the full set |

### Example (Android)

```json
{
  "bundle_id": "com.example.smoke",
  "version_name": "2.1.0",
  "version_code": "12",
  "min_os": "24",
  "target_sdk": "34",
  "debuggable": true,
  "obfuscation": {},
  "network": {
    "kind": "network_security_config"
  },
  "permissions": [
    "android.permission.CAMERA",
    "android.permission.INTERNET"
  ],
  "url_count": 7,
  "urls": [
    "https://api.example.com/v1",
    "https://firebase.example.com"
  ]
}
```

### Example (iOS)

```json
{
  "bundle_id": "com.example.smoke",
  "version_name": "1.0.0",
  "version_code": "1",
  "min_os": "14.0",
  "obfuscation": {},
  "network": {
    "kind": "NSAppTransportSecurity"
  }
}
```

`session.json.app` embeds exactly this object, and `package_name` /
`version_name` on the session are copied from it when non-empty.

## sbom.cdx.json

CycloneDX 1.5 bill of materials written by `analyze --sbom`
(`internal/sbom`). It is rendered from the session inventory, so it reflects
the `sdk` and `elf` stages even when the report itself is not regenerated.

- One `library` component per detected SDK, with a Maven PURL when the
  coordinates are known (`pkg:maven/<group>/<artifact>@<version>`).
- One `library` component per native library, with the ABIs in a
  `mobiscope:architectures` property.
- Metadata carries the app component and `mobiscope:package_name`,
  `mobiscope:apk_sha256` and `mobiscope:signing_cert` properties.
- Vulnerabilities are **not** embedded in the SBOM; they are findings in
  `findings.json` (and surface in the SARIF export) when `--osv` is used.

## report.sarif

SARIF 2.1.0 log (`internal/report/sarif.go`) for GitHub code scanning and
SARIF viewers: one run, driver `mobiscope`, one rule per distinct
`rule_id` (falling back to `source_tool/category/title`), one result per
finding with `level` mapped from severity (`critical|high -> error`,
`medium -> warning`, `low|info -> note`), and an `invocations` entry
carrying the session timestamps. `results` follow the sorted findings order;
the `rules` array is built from a map, so its order is not stable across
runs.

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "mobiscope",
          "informationUri": "https://github.com/dedek0/mobiscope",
          "semanticVersion": "dev",
          "rules": [
            {
              "id": "mastg-weak-crypto-md5",
              "name": "Use of MD5 hash algorithm which is cryptographically broken.",
              "shortDescription": {
                "text": "Use of MD5 hash algorithm which is cryptographically broken."
              },
              "properties": {
                "category": "code_pattern",
                "masvs": "MASVS-CRYPTO-1"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "mastg-weak-crypto-md5",
          "level": "warning",
          "message": {
            "text": "Rule mastg-weak-crypto-md5 matched MessageDigest.getInstance(\"MD5\"). Use of MD5 hash algorithm which is cryptographically broken."
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "sources/com/example/smoke/Crypto.java" },
                "region": {
                  "startLine": 18,
                  "snippet": { "text": "MessageDigest digest = MessageDigest.getInstance(\"MD5\");" }
                }
              }
            }
          ],
          "properties": {
            "platform": "",
            "sensitivity": "internal",
            "cluster_id": "cl-7d3c21f8aa09be14"
          }
        }
      ],
      "invocations": [
        {
          "executionSuccessful": true,
          "startTimeUtc": "2026-10-08T12:39:21Z",
          "endTimeUtc": "2026-10-08T12:39:34Z"
        }
      ]
    }
  ]
}
```

## report.md

Human-readable Markdown rendered from
`internal/report/templates/report.md.tmpl` (counts by severity/category and
a table per severity group). It is regenerated together with
`findings.json`, so it always reflects the latest triage state.

## SHA256SUMS

**Not written today.** PENDING.md §2.4 plans a `SHA256SUMS` chain-of-custody
file; until it exists, integrity references are `apk_hash` in
`session.json` and `apk_sha256` in `meta.json` (plus the `--expect-sha256`
gate before analysis starts).
