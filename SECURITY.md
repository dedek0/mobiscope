# Security Policy

## Scope

mobiscope is a **local analysis harness**. It decompiles and scans Android and
iOS application binaries you provide, and can send finding evidence to an LLM
for triage. Treat the tool and everything it produces as sensitive.

## Local-first threat model

The HTTP API is intended to run on `127.0.0.1` only. By default:

- The server binds `127.0.0.1:8080` (loopback).
- There is **no authentication**.
- Cloud LLM providers are **disabled** (`allow_cloud = false`).
- Findings categorized as `secret` are only routed to local providers.

### Do not expose the API

Anyone who can reach the API can:

- Trigger billable LLM calls (`POST /api/llm/test`).
- Download arbitrary models and fill the disk (`POST /api/llm/pull`).
- Read your LLM infrastructure layout (`GET /api/llm/config`).

If you must listen on a non-loopback address:

1. Set a strong `MOBISCOPE_API_TOKEN` (enables bearer-token auth on `/api/*`).
2. Put the service behind TLS (a reverse proxy such as Caddy or nginx).
3. Restrict network access with a firewall or private network.

```bash
export MOBISCOPE_API_TOKEN="$(openssl rand -hex 32)"
./bin/mobiscope serve --addr 0.0.0.0:8080   # only with the token set
```

Clients must send `Authorization: Bearer $MOBISCOPE_API_TOKEN`.

## Secrets handling

- API keys are read from environment variables. Do not put them in config files.
- Artifacts written under the workdir (`findings.json`, `report.md`,
  `session.json`) may contain extracted secrets and are written with mode `0600`.
- The LLM cache (`~/.cache/mobiscope/llm`) is created with mode `0700`.
- Prompt templates fence untrusted application content in `<untrusted_data>`
  tags and instruct the model to treat it as evidence only. This mitigates but
  does not eliminate prompt injection from hostile binaries.

## Untrusted input

Application binaries are hostile input. mobiscope takes these precautions:

- Symlinks in decompiled trees are never followed.
- External tool invocations use an allowlist of binaries and pass the target
  path after `--` so option-like filenames cannot inject arguments.
- File reads during scanning are size-capped.

Still, run mobiscope on a dedicated analysis host or container when processing
malware. Decompilers (jadx, apktool) parse complex, attacker-controlled formats.

## Reporting a vulnerability

Please report security issues privately via
[GitHub Security Advisories](https://github.com/dedek0/mobiscope/security/advisories/new)
or open a private report to the repository owner. Do not file public issues for
vulnerabilities.

## Supported versions

Security fixes are applied to the `main` branch.
