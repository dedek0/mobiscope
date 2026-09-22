package llm

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/dedek0/mobiscope/internal/config"
	"github.com/dedek0/mobiscope/internal/llm/providers/anthropic"
	"github.com/dedek0/mobiscope/internal/llm/providers/gemini"
	"github.com/dedek0/mobiscope/internal/llm/providers/ollama"
	openaicompatible "github.com/dedek0/mobiscope/internal/llm/providers/openai_compatible"
)

// Factory creates Provider instances from configuration.
type Factory struct {
	logger *slog.Logger
}

// NewFactory creates a new provider factory.
func NewFactory(logger *slog.Logger) *Factory {
	return &Factory{logger: logger}
}

// Create creates a Provider instance from a name and config.
// For openai_compatible providers, it resolves presets and applies overrides.
func (f *Factory) Create(name string, cfg *config.ProviderConfig) (Provider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("provider config for %s is nil", name)
	}

	// Determine the effective type: explicit type field, or infer from name.
	effectiveType := cfg.Type
	if effectiveType == "" {
		effectiveType = name
	}

	switch effectiveType {
	case "ollama":
		return ollama.New(cfg.BaseURL, f.logger), nil

	case "openai", "openai_compatible":
		return f.createOpenAICompatible(name, cfg)

	case "anthropic":
		apiKey := resolveAPIKey(cfg)
		return anthropic.New(cfg.BaseURL, apiKey, f.logger), nil

	case "gemini":
		apiKey := resolveAPIKey(cfg)
		return gemini.New(apiKey, f.logger), nil

	default:
		// Check if it's a known preset name.
		if _, ok := openaicompatible.Presets[effectiveType]; ok {
			cfg.Type = "openai_compatible"
			cfg.Preset = effectiveType
			return f.createOpenAICompatible(name, cfg)
		}
		return nil, fmt.Errorf("unknown provider type %q (available presets: openai, llamacpp, lmstudio, vllm, localai, openrouter, groq, together, azure, fireworks, deepinfra, perplexity)", effectiveType)
	}
}

func (f *Factory) createOpenAICompatible(name string, cfg *config.ProviderConfig) (Provider, error) {
	apiKey := resolveAPIKey(cfg)

	// If a preset is specified, use it.
	if cfg.Preset != "" {
		overrides := &openaicompatible.Config{
			HTTPClient: nil,
		}
		if cfg.BaseURL != "" {
			overrides.BaseURL = cfg.BaseURL
		}
		p, err := openaicompatible.NewFromPreset(cfg.Preset, apiKey, overrides, f.logger)
		if err != nil {
			return nil, fmt.Errorf("creating provider %s from preset %s: %w", name, cfg.Preset, err)
		}
		return p, nil
	}

	// Otherwise, create from explicit config.
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("provider %s requires either preset or base_url", name)
	}

	return openaicompatible.New(openaicompatible.Config{
		Name:    name,
		BaseURL: cfg.BaseURL,
		APIKey:  apiKey,
		Logger:  f.logger,
	}), nil
}

// CreateAll creates all configured providers.
func (f *Factory) CreateAll(cfg config.ProvidersConfig) (map[string]Provider, error) {
	providers := make(map[string]Provider)

	if cfg.Ollama != nil {
		p, err := f.Create("ollama", cfg.Ollama)
		if err != nil {
			return nil, fmt.Errorf("creating ollama provider: %w", err)
		}
		providers["ollama"] = p
	}

	if cfg.OpenAI != nil {
		p, err := f.Create("openai", cfg.OpenAI)
		if err != nil {
			return nil, fmt.Errorf("creating openai provider: %w", err)
		}
		providers["openai"] = p
	}

	if cfg.OpenAICompatible != nil {
		p, err := f.Create("openai_compatible", cfg.OpenAICompatible)
		if err != nil {
			return nil, fmt.Errorf("creating openai_compatible provider: %w", err)
		}
		providers["openai_compatible"] = p
	}

	if cfg.Anthropic != nil {
		p, err := f.Create("anthropic", cfg.Anthropic)
		if err != nil {
			return nil, fmt.Errorf("creating anthropic provider: %w", err)
		}
		providers["anthropic"] = p
	}

	if cfg.Gemini != nil {
		p, err := f.Create("gemini", cfg.Gemini)
		if err != nil {
			return nil, fmt.Errorf("creating gemini provider: %w", err)
		}
		providers["gemini"] = p
	}

	return providers, nil
}

func resolveAPIKey(cfg *config.ProviderConfig) string {
	if cfg.APIKey != "" {
		return cfg.APIKey
	}
	if cfg.APIKeyEnv != "" {
		return os.Getenv(cfg.APIKeyEnv)
	}
	return ""
}
