# Contribuindo

## Setup

```bash
git clone https://github.com/dedek0/mobiscope.git
cd mobiscope
make install-tools
make build
make test
```

## Antes de Enviar um PR

1. `make check` — formata, veta, linta e testa
2. Cobertura de testes ≥70% por pacote
3. Commits em inglês, docs/UX em pt-BR
4. Nenhum secret ou key hardcoded

## Estrutura de Commits

```
feat: add new analyzer for X
fix: handle nil pointer in Y
docs: update README setup section
test: add coverage for Z
refactor: extract helper from W
```

## Arquitetura

Veja `docs/adr/` para decisões de design.