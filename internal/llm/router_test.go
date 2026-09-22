package llm

import (
	"context"
	"log/slog"
	"testing"

	"github.com/dedek0/mobiscope/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testRouterProviders() map[string]Provider {
	return map[string]Provider{
		"ollama": &MockProvider{name: "ollama", isLocal: true, available: true, caps: Capabilities{JSONMode: true}},
		"openai": &MockProvider{name: "openai", isLocal: false, available: true, caps: Capabilities{JSONMode: true}},
	}
}

func TestRouter_Route_ExplicitTask(t *testing.T) {
	providers := testRouterProviders()
	cfg := config.LLMConfig{
		DefaultProvider: "ollama",
		AllowCloud:      true,
		Tasks: map[string]config.Task{
			"triage": {Provider: "ollama", Model: "qwen2.5:7b"},
			"chat":   {Provider: "openai", Model: "gpt-4o"},
		},
	}

	r := NewRouter(providers, cfg, slog.Default())
	result, err := r.Route(context.Background(), TaskTriage, false)
	require.NoError(t, err)
	assert.Equal(t, "ollama", result.Provider.Name())
	assert.Equal(t, "qwen2.5:7b", result.Model)
}

func TestRouter_Route_DefaultProvider(t *testing.T) {
	providers := testRouterProviders()
	cfg := config.LLMConfig{
		DefaultProvider: "ollama",
		Tasks: map[string]config.Task{
			"triage": {Provider: "nonexistent", Model: "x"},
		},
	}

	r := NewRouter(providers, cfg, slog.Default())
	result, err := r.Route(context.Background(), TaskTriage, false)
	require.NoError(t, err)
	assert.Equal(t, "ollama", result.Provider.Name())
}

func TestRouter_Route_AutoDetectLocal(t *testing.T) {
	providers := map[string]Provider{
		"ollama": &MockProvider{name: "ollama", isLocal: true, available: true},
	}
	cfg := config.LLMConfig{
		DefaultProvider: "nonexistent",
		Tasks:           map[string]config.Task{},
	}

	r := NewRouter(providers, cfg, slog.Default())
	result, err := r.Route(context.Background(), TaskTriage, false)
	require.NoError(t, err)
	assert.Equal(t, "ollama", result.Provider.Name())
	assert.Equal(t, "auto-local", result.TaskName)
}

func TestRouter_Route_CloudBlocked(t *testing.T) {
	providers := map[string]Provider{
		"openai": &MockProvider{name: "openai", isLocal: false, available: true},
	}
	cfg := config.LLMConfig{
		DefaultProvider: "openai",
		AllowCloud:      false,
		Tasks: map[string]config.Task{
			"triage": {Provider: "openai", Model: "gpt-4o"},
		},
	}

	r := NewRouter(providers, cfg, slog.Default())
	_, err := r.Route(context.Background(), TaskTriage, false)
	assert.ErrorIs(t, err, ErrCloudNotAllowed)
}

func TestRouter_Route_CloudAllowed(t *testing.T) {
	providers := map[string]Provider{
		"openai": &MockProvider{name: "openai", isLocal: false, available: true},
	}
	cfg := config.LLMConfig{
		DefaultProvider: "openai",
		AllowCloud:      true,
		Tasks: map[string]config.Task{
			"chat": {Provider: "openai", Model: "gpt-4o"},
		},
	}

	r := NewRouter(providers, cfg, slog.Default())
	result, err := r.Route(context.Background(), TaskChat, false)
	require.NoError(t, err)
	assert.Equal(t, "openai", result.Provider.Name())
}

func TestRouter_Route_SecretBlocked(t *testing.T) {
	providers := map[string]Provider{
		"openai": &MockProvider{name: "openai", isLocal: false, available: true},
	}
	cfg := config.LLMConfig{
		DefaultProvider:   "openai",
		AllowCloud:        true,
		AllowCloudSecrets: false,
		Tasks: map[string]config.Task{
			"triage": {Provider: "openai", Model: "gpt-4o"},
		},
	}

	r := NewRouter(providers, cfg, slog.Default())
	_, err := r.Route(context.Background(), TaskTriage, true)
	assert.ErrorIs(t, err, ErrCloudNotAllowed)
	assert.Contains(t, err.Error(), "secrets")
}

func TestRouter_Route_SecretAllowedWithOverride(t *testing.T) {
	providers := map[string]Provider{
		"openai": &MockProvider{name: "openai", isLocal: false, available: true},
	}
	cfg := config.LLMConfig{
		DefaultProvider:   "openai",
		AllowCloud:        true,
		AllowCloudSecrets: true,
		Tasks: map[string]config.Task{
			"triage": {Provider: "openai", Model: "gpt-4o"},
		},
	}

	r := NewRouter(providers, cfg, slog.Default())
	result, err := r.Route(context.Background(), TaskTriage, true)
	require.NoError(t, err)
	assert.Equal(t, "openai", result.Provider.Name())
}

func TestRouter_Route_NoProviderAvailable(t *testing.T) {
	providers := map[string]Provider{
		"unavail": &MockProvider{name: "unavail", isLocal: true, available: false},
	}
	cfg := config.LLMConfig{
		DefaultProvider: "unavail",
		Tasks:           map[string]config.Task{},
	}

	r := NewRouter(providers, cfg, slog.Default())
	_, err := r.Route(context.Background(), TaskTriage, false)
	assert.ErrorIs(t, err, ErrProviderUnavailable)
}

func TestRouter_Route_FallbackChain(t *testing.T) {
	providers := map[string]Provider{
		"primary":   &MockProvider{name: "primary", isLocal: true, available: false},
		"secondary": &MockProvider{name: "secondary", isLocal: true, available: true},
	}
	cfg := config.LLMConfig{
		DefaultProvider: "primary",
		Tasks:           map[string]config.Task{},
	}

	r := NewRouter(providers, cfg, slog.Default())
	result, err := r.Route(context.Background(), TaskTriage, false)
	require.NoError(t, err)
	assert.Equal(t, "secondary", result.Provider.Name())
}

func TestRouter_Route_LocalPreferredOverCloud(t *testing.T) {
	providers := map[string]Provider{
		"ollama": &MockProvider{name: "ollama", isLocal: true, available: true},
		"openai": &MockProvider{name: "openai", isLocal: false, available: true},
	}
	cfg := config.LLMConfig{
		DefaultProvider: "nonexistent",
		AllowCloud:      true,
		Tasks:           map[string]config.Task{},
	}

	r := NewRouter(providers, cfg, slog.Default())
	result, err := r.Route(context.Background(), TaskTriage, false)
	require.NoError(t, err)
	assert.Equal(t, "ollama", result.Provider.Name())
	assert.Equal(t, "auto-local", result.TaskName)
}

func TestRouter_Providers(t *testing.T) {
	providers := testRouterProviders()
	cfg := config.LLMConfig{DefaultProvider: "ollama"}
	r := NewRouter(providers, cfg, slog.Default())
	assert.Len(t, r.Providers(), 2)
}
