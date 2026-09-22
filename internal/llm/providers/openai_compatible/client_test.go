package openaicompatible

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// --- Preset tests ---

func TestPresets_AllDefined(t *testing.T) {
	expected := []string{
		"openai", "llamacpp", "lmstudio", "vllm", "localai",
		"openrouter", "groq", "together", "azure", "fireworks", "deepinfra", "perplexity",
	}
	for _, name := range expected {
		p, ok := Presets[name]
		assert.True(t, ok, "preset %q should exist", name)
		assert.NotEmpty(t, p.DisplayName, "preset %q should have DisplayName", name)
		// Azure requires user-set BaseURL; others should have defaults.
		if name != "azure" {
			assert.NotEmpty(t, p.BaseURL, "preset %q should have BaseURL", name)
		}
	}
}

func TestPresets_LocalProviders(t *testing.T) {
	locals := []string{"llamacpp", "lmstudio", "vllm", "localai"}
	for _, name := range locals {
		p := Presets[name]
		assert.True(t, p.IsLocal, "preset %q should be local", name)
		assert.False(t, p.NeedsKey, "preset %q should not need key", name)
	}
}

func TestPresets_CloudProviders(t *testing.T) {
	clouds := []string{"openai", "openrouter", "groq", "together", "azure"}
	for _, name := range clouds {
		p := Presets[name]
		assert.False(t, p.IsLocal, "preset %q should be cloud", name)
		assert.True(t, p.NeedsKey, "preset %q should need key", name)
	}
}

func TestResolvePreset_ByName(t *testing.T) {
	p := ResolvePreset("llamacpp", "")
	require.NotNil(t, p)
	assert.Equal(t, "llama.cpp", p.DisplayName)
}

func TestResolvePreset_ByURL(t *testing.T) {
	p := ResolvePreset("", "http://localhost:1234/v1")
	require.NotNil(t, p)
	assert.Equal(t, "LM Studio", p.DisplayName)
}

func TestResolvePreset_NotFound(t *testing.T) {
	assert.Nil(t, ResolvePreset("nonexistent", "https://nope.example.com/v1"))
}

func TestIsLocalURL(t *testing.T) {
	assert.True(t, IsLocalURL("http://localhost:8080/v1"))
	assert.True(t, IsLocalURL("http://127.0.0.1:8080/v1"))
	assert.False(t, IsLocalURL("https://api.openai.com/v1"))
}

func TestKindFromURL(t *testing.T) {
	assert.Equal(t, llmtypes.KindLocal, KindFromURL("http://localhost:8080/v1"))
	assert.Equal(t, llmtypes.KindCloud, KindFromURL("https://api.openai.com/v1"))
}

// --- Provider tests with httptest ---

func newTestServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

func TestProvider_Name(t *testing.T) {
	p := New(Config{Name: "test", BaseURL: "http://localhost:8080/v1", Logger: testLogger()})
	assert.Equal(t, "test", p.Name())
}

func TestProvider_Kind_Local(t *testing.T) {
	p := New(Config{Name: "test", BaseURL: "http://localhost:8080/v1", Logger: testLogger()})
	assert.Equal(t, llmtypes.KindLocal, p.Kind())
	assert.True(t, p.IsLocal())
}

func TestProvider_Kind_Cloud(t *testing.T) {
	p := New(Config{Name: "test", BaseURL: "https://api.openai.com/v1", Logger: testLogger()})
	assert.Equal(t, llmtypes.KindCloud, p.Kind())
	assert.False(t, p.IsLocal())
}

func TestProvider_Capabilities_Default(t *testing.T) {
	p := New(Config{Name: "test", BaseURL: "http://localhost:8080/v1", Logger: testLogger()})
	caps := p.Capabilities()
	assert.True(t, caps.JSONMode)
	assert.True(t, caps.Streaming)
	assert.True(t, caps.ToolCalling)
}

func TestProvider_Capabilities_Override(t *testing.T) {
	caps := llmtypes.Capabilities{Vision: true}
	p := New(Config{
		Name:         "test",
		BaseURL:      "http://localhost:8080/v1",
		Capabilities: &caps,
		Logger:       testLogger(),
	})
	assert.True(t, p.Capabilities().Vision)
}

func TestProvider_IsAvailable_OK(t *testing.T) {
	srv := newTestServer(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]string{{"id": "model-1"}},
		})
	})
	defer srv.Close()

	p := New(Config{Name: "test", BaseURL: srv.URL + "/v1", Logger: testLogger()})
	assert.True(t, p.IsAvailable(context.Background()))
}

func TestProvider_IsAvailable_Down(t *testing.T) {
	p := New(Config{Name: "test", BaseURL: "http://127.0.0.1:1/v1", Logger: testLogger()})
	assert.False(t, p.IsAvailable(context.Background()))
}

func TestProvider_Models(t *testing.T) {
	srv := newTestServer(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]string{
				{"id": "gpt-4o", "object": "model"},
				{"id": "gpt-4o-mini", "object": "model"},
			},
		})
	})
	defer srv.Close()

	p := New(Config{Name: "test", BaseURL: srv.URL + "/v1", Logger: testLogger()})
	models, err := p.Models(context.Background())
	require.NoError(t, err)
	assert.Len(t, models, 2)
	assert.Equal(t, "gpt-4o", models[0].Name)
}

func TestProvider_Models_Error(t *testing.T) {
	srv := newTestServer(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	p := New(Config{Name: "test", BaseURL: srv.URL + "/v1", Logger: testLogger()})
	_, err := p.Models(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hint")
}

func TestProvider_Chat(t *testing.T) {
	srv := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Contains(t, r.URL.Path, "/chat/completions")

		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "test-model", req["model"])

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":    "chatcmpl-test",
			"model": "test-model",
			"choices": []map[string]interface{}{
				{
					"message":       map[string]string{"role": "assistant", "content": "Hello!"},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]int{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
		})
	})
	defer srv.Close()

	p := New(Config{Name: "test", BaseURL: srv.URL + "/v1", Logger: testLogger()})
	resp, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model:    "test-model",
		Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})

	require.NoError(t, err)
	assert.Equal(t, "Hello!", resp.Content)
	assert.Equal(t, "test-model", resp.Model)
	assert.Equal(t, "test", resp.Provider)
	assert.Equal(t, 10, resp.Usage.PromptTokens)
	assert.Equal(t, 5, resp.Usage.CompletionTokens)
}

func TestProvider_Chat_JSONMode(t *testing.T) {
	srv := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)

		rf, ok := req["response_format"].(map[string]interface{})
		assert.True(t, ok, "should have response_format")
		assert.Equal(t, "json_object", rf["type"])

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "chatcmpl-test",
			"model":   "test-model",
			"choices": []map[string]interface{}{{"message": map[string]string{"role": "assistant", "content": `{"key":"value"}`}, "finish_reason": "stop"}},
			"usage":   map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
		})
	})
	defer srv.Close()

	p := New(Config{Name: "test", BaseURL: srv.URL + "/v1", Logger: testLogger()})
	resp, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model:    "test-model",
		Messages: []llmtypes.Message{{Role: "user", Content: "Give JSON"}},
		JSONMode: true,
	})

	require.NoError(t, err)
	assert.Contains(t, resp.Content, "key")
}

func TestProvider_Chat_WithOptions(t *testing.T) {
	srv := newTestServer(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, float64(0.7), req["temperature"])
		assert.Equal(t, float64(100), req["max_tokens"])

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "c", "model": "m",
			"choices": []map[string]interface{}{{"message": map[string]string{"role": "assistant", "content": "ok"}, "finish_reason": "stop"}},
			"usage":   map[string]int{},
		})
	})
	defer srv.Close()

	p := New(Config{Name: "test", BaseURL: srv.URL + "/v1", Logger: testLogger()})
	_, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model:       "test-model",
		Messages:    []llmtypes.Message{{Role: "user", Content: "Hi"}},
		Temperature: 0.7,
		MaxTokens:   100,
	})
	require.NoError(t, err)
}

func TestProvider_Chat_ServerError(t *testing.T) {
	srv := newTestServer(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"invalid request"}}`))
	})
	defer srv.Close()

	p := New(Config{Name: "test", BaseURL: srv.URL + "/v1", Logger: testLogger()})
	_, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model:    "test",
		Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
	assert.Error(t, err)
}

func TestProvider_Chat_EmptyChoices(t *testing.T) {
	srv := newTestServer(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "c", "model": "m", "choices": []interface{}{}, "usage": map[string]int{},
		})
	})
	defer srv.Close()

	p := New(Config{Name: "test", BaseURL: srv.URL + "/v1", Logger: testLogger()})
	_, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model:    "test",
		Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty choices")
}

func TestProvider_ChatStream(t *testing.T) {
	srv := newTestServer(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"Hello\"},\"index\":0}]}\n\n"))
		_, _ = w.Write([]byte("data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\" world\"},\"index\":0}]}\n\n"))
		_, _ = w.Write([]byte("data: {\"id\":\"c\",\"model\":\"m\",\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\",\"index\":0}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	})
	defer srv.Close()

	p := New(Config{Name: "test", BaseURL: srv.URL + "/v1", Logger: testLogger()})
	stream, err := p.ChatStream(context.Background(), llmtypes.ChatRequest{
		Model:    "test",
		Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
	require.NoError(t, err)
	defer stream.Close()

	chunks, err := ReadStreamChunks(stream)
	require.NoError(t, err)

	totalContent := ""
	for _, c := range chunks {
		totalContent += c.Content
	}
	assert.Contains(t, totalContent, "Hello")
	assert.Contains(t, totalContent, "world")
}

func TestNewFromPreset_OK(t *testing.T) {
	p, err := NewFromPreset("llamacpp", "", nil, testLogger())
	require.NoError(t, err)
	assert.Equal(t, "llamacpp", p.Name())
	assert.True(t, p.IsLocal())
}

func TestNewFromPreset_WithOverride(t *testing.T) {
	p, err := NewFromPreset("llamacpp", "", &Config{BaseURL: "http://custom:9999/v1"}, testLogger())
	require.NoError(t, err)
	assert.Contains(t, p.baseURL, "custom")
}

func TestNewFromPreset_NeedsKey(t *testing.T) {
	_, err := NewFromPreset("openai", "", nil, testLogger())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API key")
}

func TestNewFromPreset_Unknown(t *testing.T) {
	_, err := NewFromPreset("nonexistent", "key", nil, testLogger())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown preset")
}

func TestNewFromPreset_CloudWithKey(t *testing.T) {
	srv := newTestServer(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": []map[string]string{}})
	})
	defer srv.Close()

	// Override groq to point at our test server.
	p, err := NewFromPreset("groq", "test-key", &Config{BaseURL: srv.URL + "/v1"}, testLogger())
	require.NoError(t, err)
	assert.False(t, p.IsLocal())
}

func TestNewFromLegacy(t *testing.T) {
	p := NewFromLegacy("test", "http://localhost:8080/v1", "", testLogger())
	assert.Equal(t, "test", p.Name())
	assert.True(t, p.IsLocal())
}

func TestProvider_HintError_Local(t *testing.T) {
	p := New(Config{Name: "llamacpp", BaseURL: "http://localhost:8080/v1", Logger: testLogger()})
	err := p.hintError(assert.AnError)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hint")
}

func TestProvider_HintError_Cloud(t *testing.T) {
	p := New(Config{Name: "openai", BaseURL: "https://api.openai.com/v1", Logger: testLogger()})
	err := p.hintError(assert.AnError)
	assert.Error(t, err)
	assert.NotContains(t, err.Error(), "hint")
}

func TestProvider_DefaultModel(t *testing.T) {
	p := New(Config{Name: "llamacpp", BaseURL: "http://localhost:8080/v1", Logger: testLogger()})
	assert.Equal(t, "default", p.defaultModel())
}

func TestAvailablePresets(t *testing.T) {
	s := availablePresets()
	assert.Contains(t, s, "openai")
	assert.Contains(t, s, "llamacpp")
	assert.Contains(t, s, "groq")
}

func TestProvider_AllPresets_ChatRoundTrip(t *testing.T) {
	srv := newTestServer(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "c", "model": "m",
			"choices": []map[string]interface{}{{"message": map[string]string{"role": "assistant", "content": "ok"}, "finish_reason": "stop"}},
			"usage":   map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
		})
	})
	defer srv.Close()

	localPresets := []string{"llamacpp", "lmstudio", "vllm", "localai"}
	for _, name := range localPresets {
		t.Run(name, func(t *testing.T) {
			p, err := NewFromPreset(name, "", &Config{BaseURL: srv.URL + "/v1"}, testLogger())
			require.NoError(t, err)

			resp, err := p.Chat(context.Background(), llmtypes.ChatRequest{
				Model:    "test",
				Messages: []llmtypes.Message{{Role: "user", Content: "hi"}},
			})
			require.NoError(t, err)
			assert.Equal(t, "ok", resp.Content)
		})
	}
}
