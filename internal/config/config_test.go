package config

import (
	"context"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadDefaults(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)

	assert.Equal(t, "ollama", cfg.LLM.DefaultProvider)
	assert.NotNil(t, cfg.LLM.Providers.Ollama)
	assert.Equal(t, "http://localhost:11434", cfg.LLM.Providers.Ollama.BaseURL)
	assert.Len(t, cfg.LLM.Tasks, 4)
	assert.Contains(t, cfg.LLM.Tasks, "triage")
	assert.Contains(t, cfg.LLM.Tasks, "remediation")
	assert.Contains(t, cfg.LLM.Tasks, "chat")
	assert.Contains(t, cfg.LLM.Tasks, "correlate")
}

func TestLoadValidation(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)

	v := validator.New()
	err := v.StructCtx(context.Background(), cfg)
	require.NoError(t, err)
}

func TestProviderConfig(t *testing.T) {
	pc := &ProviderConfig{
		BaseURL:   "http://localhost:11434",
		APIKeyEnv: "TEST_API_KEY",
		Timeout:   30,
	}

	assert.Equal(t, "http://localhost:11434", pc.BaseURL)
	assert.Equal(t, "TEST_API_KEY", pc.APIKeyEnv)
	assert.Equal(t, 30, pc.Timeout)
}

func TestTaskConfig(t *testing.T) {
	task := Task{
		Provider: "ollama",
		Model:    "qwen2.5-coder:7b",
	}

	assert.Equal(t, "ollama", task.Provider)
	assert.Equal(t, "qwen2.5-coder:7b", task.Model)
}

func TestLLMConfig(t *testing.T) {
	llmCfg := LLMConfig{
		DefaultProvider: "ollama",
		AllowCloud:      false,
		Tasks: map[string]Task{
			"triage": {Provider: "ollama", Model: "test"},
		},
		Providers: ProvidersConfig{
			Ollama: &ProviderConfig{BaseURL: "http://localhost:11434"},
		},
	}

	assert.Equal(t, "ollama", llmCfg.DefaultProvider)
	assert.False(t, llmCfg.AllowCloud)
	assert.Len(t, llmCfg.Tasks, 1)
}
