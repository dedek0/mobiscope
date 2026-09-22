package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRegistry_Get(t *testing.T) {
	r := NewRegistry()

	m, ok := r.Get("qwen2.5-coder:7b")
	assert.True(t, ok)
	assert.Equal(t, "Qwen 2.5 Coder 7B", m.DisplayName)
	assert.True(t, m.IsLocal)
}

func TestRegistry_GetNotFound(t *testing.T) {
	r := NewRegistry()

	_, ok := r.Get("nonexistent-model")
	assert.False(t, ok)
}

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()

	custom := ModelInfo{
		ID:            "custom-model",
		Provider:      "custom",
		DisplayName:   "Custom Model",
		ContextWindow: 4096,
		IsLocal:       true,
	}
	r.Register(custom)

	m, ok := r.Get("custom-model")
	assert.True(t, ok)
	assert.Equal(t, "Custom Model", m.DisplayName)
}

func TestRegistry_List(t *testing.T) {
	r := NewRegistry()
	models := r.List()
	assert.NotEmpty(t, models)
}

func TestRegistry_ListByProvider(t *testing.T) {
	r := NewRegistry()

	ollamaModels := r.ListByProvider("ollama")
	assert.NotEmpty(t, ollamaModels)
	for _, m := range ollamaModels {
		assert.Equal(t, "ollama", m.Provider)
	}

	openaiModels := r.ListByProvider("openai")
	assert.NotEmpty(t, openaiModels)
	for _, m := range openaiModels {
		assert.Equal(t, "openai", m.Provider)
	}
}

func TestModelInfo_Fields(t *testing.T) {
	m := ModelInfo{
		ID:            "test",
		Provider:      "test-provider",
		DisplayName:   "Test Model",
		ContextWindow: 8192,
		CostPer1KIn:   0.001,
		CostPer1KOut:  0.002,
		IsLocal:       true,
		Capabilities:  Capabilities{JSONMode: true},
	}

	assert.Equal(t, "test", m.ID)
	assert.Equal(t, "test-provider", m.Provider)
	assert.Equal(t, 8192, m.ContextWindow)
	assert.True(t, m.IsLocal)
	assert.True(t, m.Capabilities.JSONMode)
}
