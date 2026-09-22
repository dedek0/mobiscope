# ADR-001: Provider-agnostic LLM layer

## Status

Accepted

## Context

O mobiscope precisa de capacidade LLM para triagem, correlação e explicação
de achados de análise estática. O mercado de LLMs é fragmentado: dezenas de
providers com APIs diferentes, modelos que surgem e morrem a cada mês, e cenários
de uso que vão de laptops sem internet a servidores com GPU.

## Decision

Implementamos uma camada abstrata `Provider` com adapters específicos:

1. **Interface única** (`llmtypes.Provider`): Chat, ChatStream, IsAvailable, Models
2. **Adapter genérico** para OpenAI-compatible (cobre 15+ providers)
3. **Adapters dedicados** apenas para Ollama, Anthropic e Gemini
4. **Router** que seleciona provider por tarefa com fallback em cadeia
5. **Política de privacidade**: cloud bloqueado por default, secrets nunca vão para cloud

## Consequences

### Positivo

- Trocar provider = mudar uma linha no config
- Testes com MockProvider sem rede
- Fallback automático se provider primário falha
- Privacidade garantida por default

### Negativo

- Abstração pode esconder features específicas de um provider
- Adapters dedicados precisam de manutenção quando APIs mudam
- JSON mode disponível em todos os providers? Não — o Router precisa ser capability-aware