package llm

import (
	"log/slog"
	"testing"

	"github.com/dedek0/mobiscope/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFactory_CreateOllama(t *testing.T) {
	f := NewFactory(slog.Default())
	cfg := &config.ProviderConfig{BaseURL: "http://localhost:11434"}

	p, err := f.Create("ollama", cfg)
	require.NoError(t, err)
	assert.Equal(t, "ollama", p.Name())
	assert.True(t, p.IsLocal())
}

func TestFactory_CreateOpenAI(t *testing.T) {
	f := NewFactory(slog.Default())
	cfg := &config.ProviderConfig{
		BaseURL: "https://api.openai.com/v1",
		APIKey:  "test-key",
	}

	p, err := f.Create("openai", cfg)
	require.NoError(t, err)
	assert.Equal(t, "openai", p.Name())
}

func TestFactory_CreateAnthropic(t *testing.T) {
	f := NewFactory(slog.Default())
	cfg := &config.ProviderConfig{
		BaseURL: "https://api.anthropic.com",
		APIKey:  "test-key",
	}

	p, err := f.Create("anthropic", cfg)
	require.NoError(t, err)
	assert.Equal(t, "anthropic", p.Name())
}

func TestFactory_CreateGemini(t *testing.T) {
	f := NewFactory(slog.Default())
	cfg := &config.ProviderConfig{
		APIKey: "test-key",
	}

	p, err := f.Create("gemini", cfg)
	require.NoError(t, err)
	assert.Equal(t, "gemini", p.Name())
}

func TestFactory_CreateOpenAICompatible(t *testing.T) {
	f := NewFactory(slog.Default())
	cfg := &config.ProviderConfig{
		BaseURL: "http://localhost:8080",
	}

	p, err := f.Create("openai_compatible", cfg)
	require.NoError(t, err)
	assert.Equal(t, "openai_compatible", p.Name())
}

func TestFactory_CreateNilConfig(t *testing.T) {
	f := NewFactory(slog.Default())

	_, err := f.Create("ollama", nil)
	assert.Error(t, err)
}

func TestFactory_CreateUnknownProvider(t *testing.T) {
	f := NewFactory(slog.Default())
	cfg := &config.ProviderConfig{BaseURL: "http://localhost:11434"}

	_, err := f.Create("unknown", cfg)
	assert.Error(t, err)
}

func TestFactory_CreateAll(t *testing.T) {
	f := NewFactory(slog.Default())
	cfg := config.ProvidersConfig{
		"ollama": &config.ProviderConfig{BaseURL: "http://localhost:11434"},
		"openai": &config.ProviderConfig{BaseURL: "https://api.openai.com/v1", APIKey: "test"},
	}

	providers, err := f.CreateAll(cfg)
	require.NoError(t, err)
	assert.Len(t, providers, 2)
	assert.Contains(t, providers, "ollama")
	assert.Contains(t, providers, "openai")
}
