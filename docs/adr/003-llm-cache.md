# ADR-003: File-based LLM cache with TTL

## Status

Accepted

## Context

Triagem LLM é cara (tempo + dinheiro). Muitos findings são idênticos entre runs
(mesmo APK, mesmas regras). Cachear respostas economiza >80% em re-análises.

## Decision

Cache em `~/.cache/mobiscope/llm/` com:
- Chave: SHA256(provider|model|prompt|temperature)
- Valor: resposta JSON crua
- TTL: configurável (default: 0 = sem expiração)
- Limpeza: manual via `cache.Clear()`

## Consequences

- Segunda execução do mesmo APK é instantânea
- Não há invalidação automática (se o modelo mudar, cache fica stale)
- Arquivos são legíveis para debug