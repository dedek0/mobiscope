# ADR-002: Deterministic finding IDs

## Status

Accepted

## Context

Findings precisam de IDs estáveis para: dedup, comparação entre runs, cache de
triagem, e referência em relatórios. UUIDs aleatórios quebram todos esses casos.

## Decision

ID = `hex(sha256(source_tool + category + file + line + sha256(snippet)))[:16]`

- Determinístico: mesma entrada → mesmo ID
- Curto: 16 hex chars = 64 bits
- Colisão aceitável para o domínio (não é primary key de DB)

## Consequences

- Cache funciona entre runs
- Dedup é O(1) por hash
- IDs mudam se o snippet mudar (esperado: finding diferente)