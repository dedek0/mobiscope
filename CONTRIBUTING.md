# Contributing to mobiscope

Thanks for your interest in contributing.

## Development setup

```bash
git clone https://github.com/dedek0/mobiscope.git
cd mobiscope
make install-tools
make build
make test
```

## Before opening a PR

1. `make check` — formats, vets, lints and tests.
2. Keep per-package test coverage at or above the existing level.
3. Commits and docs in English; no `Co-Authored-By` trailers.
4. No hardcoded secrets or API keys.

## Commit style

```
feat: add new analyzer for X
fix: handle nil pointer in Y
docs: update README setup section
test: add coverage for Z
refactor: extract helper from W
```

Atomic commits, one logical change each.

## Architecture

Design decisions live in `docs/adr/`. Remaining work is tracked in
[PENDING.md](PENDING.md) — check there before starting something new.

## Security issues

Do not file public issues for vulnerabilities. See
[SECURITY.md](SECURITY.md).
