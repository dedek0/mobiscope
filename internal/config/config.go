package config

import (
	"context"
	"fmt"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/knadh/koanf/v2"
)

// Config represents the complete application configuration.
type Config struct {
	LLM LLMConfig `koanf:"llm" validate:"required"`
}

// LLMConfig holds all LLM-related configuration.
type LLMConfig struct {
	DefaultProvider   string          `koanf:"default_provider" validate:"required"`
	AllowCloud        bool            `koanf:"allow_cloud"`
	AllowCloudSecrets bool            `koanf:"allow_cloud_secrets"`
	Tasks             map[string]Task `koanf:"tasks"`
	Providers         ProvidersConfig `koanf:"providers" validate:"required"`
}

// Task defines which provider/model to use for a specific task type.
type Task struct {
	Provider string `koanf:"provider" validate:"required"`
	Model    string `koanf:"model"    validate:"required"`
}

// ProvidersConfig holds configuration for all supported LLM providers.
type ProvidersConfig struct {
	Ollama           *ProviderConfig `koanf:"ollama"`
	OpenAICompatible *ProviderConfig `koanf:"openai_compatible"`
	OpenAI           *ProviderConfig `koanf:"openai"`
	Anthropic        *ProviderConfig `koanf:"anthropic"`
	Gemini           *ProviderConfig `koanf:"gemini"`
}

// ProviderConfig holds configuration for a single LLM provider.
type ProviderConfig struct {
	Type      string `koanf:"type"`
	Preset    string `koanf:"preset"`
	BaseURL   string `koanf:"base_url"`
	APIKeyEnv string `koanf:"api_key_env"`
	APIKey    string `koanf:"api_key"`
	Timeout   int    `koanf:"timeout"`
}

// Load reads configuration from file, environment variables, and flags.
func Load(ctx context.Context, cfgPath string) (*Config, error) {
	k := koanf.New(".")

	if cfgPath != "" {
		if err := loadFromFile(k, cfgPath); err != nil {
			return nil, fmt.Errorf("loading config file: %w", err)
		}
	}

	loadEnv(k)

	cfg := &Config{}
	if err := k.Unmarshal("", cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	applyDefaults(cfg)

	v := validator.New()
	if err := v.StructCtx(ctx, cfg); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

func loadFromFile(_ *koanf.Koanf, path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("config file not found: %s", path)
	}
	return nil
}

func loadEnv(_ *koanf.Koanf) {
	// TODO: implement env loading with koanf provider
}

func applyDefaults(cfg *Config) {
	if cfg.LLM.DefaultProvider == "" {
		cfg.LLM.DefaultProvider = "ollama"
	}

	if cfg.LLM.Providers.Ollama == nil {
		cfg.LLM.Providers.Ollama = &ProviderConfig{
			BaseURL: "http://localhost:11434",
		}
	}

	if cfg.LLM.Tasks == nil {
		cfg.LLM.Tasks = map[string]Task{
			"triage": {
				Provider: "ollama",
				Model:    "qwen2.5-coder:7b",
			},
			"remediation": {
				Provider: "ollama",
				Model:    "qwen2.5-coder:7b",
			},
			"chat": {
				Provider: "ollama",
				Model:    "qwen2.5-coder:7b",
			},
			"correlate": {
				Provider: "ollama",
				Model:    "qwen2.5-coder:7b",
			},
		}
	}
}
