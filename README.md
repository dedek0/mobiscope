# mobiscope

Harness de análise estática de APKs Android que orquestra ferramentas externas (apktool, jadx, gitleaks, semgrep) e usa LLMs para triagem, correlação e explicação de achados de segurança.

> **Provider-agnostic**: funciona com Ollama, llama.cpp, LM Studio, vLLM, OpenAI, Anthropic, Gemini, Groq, OpenRouter e qualquer API compatível com OpenAI.

## Visão Geral

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────┐
│  APK Input  │────▶│  Decompilers │────▶│  Analyzers   │────▶│  Triage  │
│             │     │ apktool/jadx │     │ gitleaks/    │     │  (LLM)   │
│             │     │              │     │ semgrep/     │     │          │
│             │     │              │     │ inventory    │     │          │
└─────────────┘     └──────────────┘     └──────────────┘     └──────────┘
                                                                    │
                    ┌──────────────┐     ┌──────────────┐          │
                    │  Report.md   │◀────│  Dedup +     │◀─────────┘
                    │  findings    │     │  Cluster     │
                    │  meta.json   │     │              │
                    └──────────────┘     └──────────────┘
```

## Instalação

### Binário

```bash
# Clonar
git clone https://github.com/dedek0/mobiscope.git
cd mobiscope

# Build
make build

# Instalar tools externas (opcional, para análise completa)
# apktool: https://apktool.org
# jadx:    https://github.com/skylot/jadx
# gitleaks: https://github.com/gitleaks/gitleaks
# semgrep:  https://semgrep.dev
```

### Docker

```bash
# Build da imagem
docker build -t mobiscope .

# Com Ollama local (CPU)
docker compose --profile local-llm up -d

# Com Ollama + GPU NVIDIA
docker compose --profile local-llm-gpu up -d

# Apenas a aplicação (usar LLM cloud)
docker compose up mobiscope
```

## Uso

### Análise Básica

```bash
# Análise completa (apktool + jadx)
./bin/mobiscope analyze app.apk

# Com stages específicas
./bin/mobiscope analyze app.apk --stages apktool,jadx,gitleaks,semgrep

# Com triage LLM
./bin/mobiscope analyze app.apk --triage

# Triage com provider específico
./bin/mobiscope analyze app.apk --triage --triage-provider anthropic --allow-cloud
```

### Gestão de LLMs

```bash
# Detectar providers disponíveis
./bin/mobiscope llm detect

# Ver config efetiva
./bin/mobiscope llm config

# Checar saúde dos providers
./bin/mobiscope llm health
./bin/mobiscope llm health --provider ollama

# Listar modelos instalados
./bin/mobiscope llm list
./bin/mobiscope llm list --provider ollama

# Listar modelos conhecidos + preços
./bin/mobiscope llm models

# Testar conectividade
./bin/mobiscope llm test --task triage

# Baixar modelo (Ollama)
./bin/mobiscope llm pull qwen2.5-coder:7b
```

### Flags Globais

```
--provider <nome>    Override do provider LLM para todas as tarefas
--allow-cloud        Permite uso de providers cloud (por padrão só local)
```

## Configuração

### Arquivo de Config

```bash
# Localização padrão: ~/.config/mobiscope/config.toml
# Ou via flag: --config /path/to/config.toml

cp deploy/config.example.toml config.toml
```

### Config TOML Completa

```toml
[llm]
default_provider = "ollama"
allow_cloud = false
allow_cloud_secrets = false

# Providers por tarefa
[llm.tasks.triage]
provider = "ollama"
model = "qwen2.5-coder:7b"

[llm.tasks.remediation]
provider = "ollama"
model = "qwen2.5-coder:7b"

[llm.tasks.correlate]
provider = "ollama"
model = "qwen2.5-coder:7b"

[llm.tasks.chat]
provider = "ollama"
model = "qwen2.5-coder:7b"

# Provider: Ollama (local)
[llm.providers.ollama]
base_url = "http://localhost:11434"

# Provider: OpenAI (cloud)
# [llm.providers.openai]
# type = "openai_compatible"
# preset = "openai"
# api_key_env = "OPENAI_API_KEY"

# Provider: Anthropic (cloud)
# [llm.providers.anthropic]
# api_key_env = "ANTHROPIC_API_KEY"

# Provider: llama.cpp (local)
# [llm.providers.llamacpp]
# type = "openai_compatible"
# preset = "llamacpp"
# base_url = "http://localhost:8080/v1"
```

### Variáveis de Ambiente

| Variável | Provider | Obrigatória |
|----------|----------|-------------|
| `OPENAI_API_KEY` | OpenAI | Sim (se usar OpenAI) |
| `ANTHROPIC_API_KEY` | Anthropic | Sim (se usar Anthropic) |
| `GOOGLE_API_KEY` | Gemini | Sim (se usar Gemini) |
| `OPENROUTER_API_KEY` | OpenRouter | Sim (se usar OpenRouter) |
| `GROQ_API_KEY` | Groq | Sim (se usar Groq) |
| `TOGETHER_API_KEY` | Together | Sim (se usar Together) |
| `AZURE_OPENAI_API_KEY` | Azure | Sim (se usar Azure) |

## Providers Suportados

### Locais (grátis, sem limite)

| Provider | Porta Default | Preset | Setup |
|----------|--------------|--------|-------|
| **Ollama** | 11434 | `ollama` | `ollama serve` + `ollama pull qwen2.5-coder:7b` |
| **llama.cpp** | 8080 | `llamacpp` | `llama-server -m model.gguf` |
| **LM Studio** | 1234 | `lmstudio` | Abrir app → Start Server |
| **vLLM** | 8000 | `vllm` | `vllm serve model-name` |
| **LocalAI** | 8080 | `localai` | `local-ai run` |

### Cloud (pagam por uso)

| Provider | Preset | Modelos Recomendados |
|----------|--------|---------------------|
| **OpenAI** | `openai` | gpt-4o-mini, gpt-4o |
| **Anthropic** | - | claude-sonnet-4, claude-3-5-haiku |
| **Gemini** | - | gemini-2.0-flash |
| **OpenRouter** | `openrouter` | Diversos (proxy) |
| **Groq** | `groq` | llama-3.1-8b-instant |
| **Together** | `together` | Meta-Llama models |

## Arquitetura

```
cmd/mobiscope/         CLI (cobra)
├── main.go                 Root command, global flags, exit codes
├── analyze.go              Comando analyze com pipeline
├── llm.go                  Subcomandos llm (health, list, detect, etc.)
└── logger.go               Helper de logging

internal/
├── api/                    HTTP API (chi router)
│   ├── server.go           Endpoints REST
│   └── helpers.go          JSON response helpers
├── analyzers/              Wrappers de ferramentas externas
│   ├── analyzer.go         Interface Analyzer + CommandRunner
│   ├── apktool.go          Decompilação de resources
│   ├── jadx.go             Decompilação de bytecode
│   ├── gitleaks.go         Detecção de secrets
│   ├── semgrep.go          Análise de padrões (SARIF)
│   └── inventory.go        Análise customizada (manifest, nsc, regex)
├── config/                 Configuração (koanf + TOML)
├── llm/                    Camada LLM provider-agnostic
│   ├── llmtypes/           Tipos centrais (Provider interface, errors)
│   ├── providers/
│   │   ├── ollama/         Cliente Ollama via HTTP
│   │   ├── anthropic/      Cliente Anthropic Messages API
│   │   ├── gemini/         Cliente Gemini GenerateContent API
│   │   └── openai_compatible/  Cliente genérico OpenAI SDK
│   ├── router.go           Roteamento por tarefa + fallback
│   ├── detect.go           Detecção automática de providers
│   ├── triage.go           Engine de triagem LLM
│   ├── cache.go            Cache de respostas (SHA256, TTL)
│   ├── cost.go             Tabela de preços + acumulador
│   ├── prompts.go          Templates de prompt (go:embed)
│   └── factory.go          Cria providers a partir de config
├── models/                 Structs de domínio
├── pipeline/               Orquestração do pipeline
├── report/                 Geração de relatórios (JSON, Markdown)
└── utils/                  Utilitários de filesystem
```

## API HTTP

```bash
# Health check
GET /healthz

# Providers
GET  /api/llm/providers
GET  /api/llm/providers/{name}/models
GET  /api/llm/config
POST /api/llm/test        # {"provider":"ollama","task":"triage"}
POST /api/llm/pull        # {"provider":"ollama","model":"qwen2.5:7b"}

# Sessões
GET  /api/sessions/
GET  /api/sessions/{id}
```

## Privacidade e Segurança

- **Cloud bloqueado por padrão**: `allow_cloud = false` no config
- **Secrets nunca vão para cloud**: findings com `category=secret` só usam providers locais, a menos que `allow_cloud_secrets = true`
- **Exit code 4**: provider indisponível ou cloud bloqueado
- **API keys via env vars**: nunca em arquivos de config committed
- **Prompt truncado**: contexto de código limitado a 4000 chars por padrão

## Desenvolvimento

```bash
# Setup
make install-tools

# Build
make build

# Testes
make test

# Lint + formatação
make check

# Testes de integração (precisa de tools externas)
go test -tags integration ./internal/pipeline/
```

### Estrutura de Testes

Cada pacote tem cobertura ≥70%:

| Pacote | Cobertura |
|--------|-----------|
| `internal/pipeline` | ~93% |
| `internal/llm` | ~79% |
| `internal/analyzers` | ~87% |
| `internal/api` | ~85% |
| `internal/report` | ~88% |
| `internal/utils` | ~83% |

## Formato de Saída

### findings.json

```json
[
  {
    "id": "a1b2c3d4e5f67890",
    "session_id": "f1e2d3c4b5a69870",
    "source_tool": "gitleaks",
    "category": "secret",
    "title": "Secret detected: aws-access-key",
    "severity": "critical",
    "sensitivity": "secret",
    "location": {"file": "Config.java", "line": 42, "snippet": "AKIA..."},
    "needs_llm_triage": true,
    "representative": true,
    "cluster_id": "cl-abc123",
    "llm_verdict": "confirmed",
    "llm_confidence": 0.95,
    "llm_explanation": "Pattern matches AWS access key format.",
    "llm_provider": "ollama",
    "llm_model": "qwen2.5-coder:7b"
  }
]
```

### meta.json

```json
{
  "apk_path": "app.apk",
  "apk_sha256": "abc123...",
  "started_at": "2025-01-15T10:00:00Z",
  "tools": [
    {"name": "apktool", "version": "2.9.3", "exit_code": 0},
    {"name": "jadx", "version": "1.5.0", "exit_code": 0}
  ]
}
```

## Licença

MIT