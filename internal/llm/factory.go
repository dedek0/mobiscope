package llm

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

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

	// The config struct is shared with the caller (and reachable from the
	// API server), so it is copied before it is modified.
	local := *cfg
	cfg = &local

	// Determine the effective type: explicit type field, or infer from name.
	effectiveType := cfg.Type
	if effectiveType == "" {
		effectiveType = name
	}

	// The configured timeout is applied to every provider that has a
	// client, so the value is not silently ignored.
	var httpClient *http.Client
	if cfg.Timeout > 0 {
		httpClient = &http.Client{Timeout: time.Duration(cfg.Timeout) * time.Second}
	}

	switch effectiveType {
	case NameOllama:
		if httpClient != nil {
			return ollama.NewWithHTTPClient(cfg.BaseURL, httpClient, f.logger), nil
		}
		return ollama.New(cfg.BaseURL, f.logger), nil

	case NameOpenAI, "openai_compatible":
		return f.createOpenAICompatible(name, cfg, httpClient)

	case NameAnthropic:
		apiKey := resolveAPIKey(cfg)
		if httpClient != nil {
			return anthropic.NewWithHTTPClient(cfg.BaseURL, apiKey, httpClient, f.logger), nil
		}
		return anthropic.New(cfg.BaseURL, apiKey, f.logger), nil

	case NameGemini:
		apiKey := resolveAPIKey(cfg)
		if httpClient != nil {
			return gemini.NewWithHTTPClient(cfg.BaseURL, apiKey, httpClient, f.logger), nil
		}
		return gemini.New(apiKey, f.logger), nil

	default:
		// Check if it's a known preset name.
		if _, ok := openaicompatible.Presets[effectiveType]; ok {
			cfg.Type = "openai_compatible"
			cfg.Preset = effectiveType
			return f.createOpenAICompatible(name, cfg, httpClient)
		}
		return nil, fmt.Errorf("unknown provider type %q (available presets: openai, llamacpp, lmstudio, vllm, localai, openrouter, groq, together, azure, fireworks, deepinfra, perplexity)", effectiveType)
	}
}

func (f *Factory) createOpenAICompatible(name string, cfg *config.ProviderConfig, httpClient *http.Client) (Provider, error) {
	apiKey := resolveAPIKey(cfg)

	// If a preset is specified, use it.
	if cfg.Preset != "" {
		overrides := &openaicompatible.Config{
			HTTPClient: httpClient,
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
		Name:       name,
		BaseURL:    cfg.BaseURL,
		APIKey:     apiKey,
		HTTPClient: httpClient,
		Logger:     f.logger,
	}), nil
}

// CreateAll creates all configured providers, keyed by provider name.
func (f *Factory) CreateAll(cfg config.ProvidersConfig) (map[string]Provider, error) {
	providers := make(map[string]Provider, len(cfg))

	for name, pc := range cfg {
		if pc == nil {
			continue
		}
		p, err := f.Create(name, pc)
		if err != nil {
			return nil, fmt.Errorf("creating %s provider: %w", name, err)
		}
		providers[name] = p
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
