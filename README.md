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
--config <path>      Arquivo de configuração (TOML)
--provider <nome>    Override do provider LLM para todas as tarefas
--allow-cloud        Permite uso de providers cloud (por padrão só local)
```

> Veja [Configuration](#configuration) para a precedência completa e as variáveis de ambiente suportadas.

## Configuration

### Precedence

Configuration is resolved in layers. Later layers override earlier ones:

```
built-in defaults  <  TOML file  <  environment variables  <  CLI flags
```

- **Defaults** only fill gaps — a value set in any higher layer is never overwritten.
- **CLI flags** are applied only when explicitly set on the command line (an unchanged flag never clobbers a file or env value).
- Cross-field rules are validated at load time: `llm.default_provider` and every `llm.tasks.*.provider` must reference a defined `[llm.providers.<name>]` section.

### Config file

TOML only. The file is looked up in this order (first match wins):

1. `--config /path/to/config.toml`
2. `$MOBISCOPE_CONFIG`
3. `./config.toml`
4. `./mobiscope.toml`
5. `~/.config/mobiscope/config.toml`
6. `~/.mobiscope/config.toml`

```bash
cp deploy/config.example.toml config.toml
```

An explicit path (`--config` or `$MOBISCOPE_CONFIG`) that does not exist is an error. When no path is given and no file is found, built-in defaults are used.

### Full TOML example

```toml
[llm]
default_provider = "ollama"
allow_cloud = false
allow_cloud_secrets = false

# Providers per task. Missing tasks fall back to the built-in defaults.
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
# type = "anthropic"
# api_key_env = "ANTHROPIC_API_KEY"

# Provider: llama.cpp (local)
# [llm.providers.llamacpp]
# type = "openai_compatible"
# preset = "llamacpp"
# base_url = "http://localhost:8080/v1"
```

`[llm.providers.<name>]` is a free-form map: add as many providers as you want. `type` is one of `ollama`, `openai`, `openai_compatible`, `anthropic`, `gemini` (or a known preset name, which implies `openai_compatible`). Optional fields: `preset`, `base_url` (must be a valid http(s) URL), `api_key_env`, `api_key`, `timeout` (seconds, > 0).

### Environment variables

#### Generic overrides

Any config key can be set with the `MOBISCOPE_` prefix, using `__` as the key separator:

| Variable | Config key |
|----------|------------|
| `MOBISCOPE_CONFIG` | (config file path, handled separately) |
| `MOBISCOPE_LLM__DEFAULT_PROVIDER` | `llm.default_provider` |
| `MOBISCOPE_LLM__ALLOW_CLOUD` | `llm.allow_cloud` |
| `MOBISCOPE_LLM__ALLOW_CLOUD_SECRETS` | `llm.allow_cloud_secrets` |
| `MOBISCOPE_LLM__PROVIDERS__OLLAMA__BASE_URL` | `llm.providers.ollama.base_url` |
| `MOBISCOPE_LLM__TASKS__TRIAGE__MODEL` | `llm.tasks.triage.model` |

#### Well-known provider credentials

| Variable | Config key | Provider |
|----------|------------|----------|
| `OLLAMA_HOST` | `llm.providers.ollama.base_url` | Ollama |
| `OPENAI_API_KEY` | `llm.providers.openai.api_key` | OpenAI |
| `ANTHROPIC_API_KEY` | `llm.providers.anthropic.api_key` | Anthropic |
| `GOOGLE_API_KEY` / `GEMINI_API_KEY` | `llm.providers.gemini.api_key` | Gemini |
| `OPENROUTER_API_KEY` | `llm.providers.openrouter.api_key` | OpenRouter |
| `GROQ_API_KEY` | `llm.providers.groq.api_key` | Groq |
| `TOGETHER_API_KEY` | `llm.providers.together.api_key` | Together |
| `AZURE_OPENAI_API_KEY` | `llm.providers.azure.api_key` | Azure OpenAI |

### CLI flags

| Flag | Config key | Notes |
|------|------------|-------|
| `--config <path>` | — | Config file path |
| `--provider <name>` | `llm.default_provider` | Overrides provider for all tasks |
| `--allow-cloud` | `llm.allow_cloud` | Permits cloud LLM providers |


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
# Start the server (loopback only by default)
./bin/mobiscope serve                 # 127.0.0.1:8080
./bin/mobiscope serve --addr 0.0.0.0:8080   # NEVER without MOBISCOPE_API_TOKEN

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

> **Warning — network exposure.** The API has no authentication by default and
> can trigger billable LLM calls and model downloads. It binds `127.0.0.1`
> only. Before binding to any other address, set `MOBISCOPE_API_TOKEN` and put
> the service behind TLS. See [SECURITY.md](SECURITY.md).

## Privacidade e Segurança

- **Cloud bloqueado por padrão**: `allow_cloud = false` no config
- **Secrets nunca vão para cloud**: findings com `category=secret` só usam providers locais, a menos que `allow_cloud_secrets = true`
- **Exit code 4**: provider indisponível ou cloud bloqueado
- **API keys via env vars**: nunca em arquivos de config committed
- **Prompt truncado**: contexto de código limitado a 4000 chars por padrão
- **Bind loopback por padrão**: `serve` escuta em `127.0.0.1`; autenticação opcional via `MOBISCOPE_API_TOKEN`
- **Dados não confiáveis cercados**: evidência e código vão para o LLM dentro de `<untrusted_data>`
- **Symlinks nunca seguidos** na árvore decompilada; binários externos com allowlist

Veja [SECURITY.md](SECURITY.md) para o modelo de ameaças completo.

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