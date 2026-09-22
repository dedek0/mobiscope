package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/dedek0/mobiscope/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func testConfig() *config.Config {
	cfg := &config.Config{
		LLM: config.LLMConfig{
			DefaultProvider: "ollama",
			Tasks: map[string]config.Task{
				"triage": {Provider: "ollama", Model: "qwen2.5-coder:7b"},
			},
			Providers: config.ProvidersConfig{
				"ollama": &config.ProviderConfig{BaseURL: "http://localhost:11434"},
			},
		},
	}
	return cfg
}

func TestNewServer(t *testing.T) {
	srv, err := NewServer(testConfig(), testLogger())
	require.NoError(t, err)
	assert.NotNil(t, srv)
	assert.NotNil(t, srv.Handler())
}

func TestHealthz(t *testing.T) {
	srv, err := NewServer(testConfig(), testLogger())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleLLMProviders(t *testing.T) {
	srv, err := NewServer(testConfig(), testLogger())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/llm/providers", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	// Should return at least the configured provider.
	assert.NotEmpty(t, resp)
}

func TestHandleLLMConfig(t *testing.T) {
	srv, err := NewServer(testConfig(), testLogger())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/llm/config", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "ollama", resp["default_provider"])
	assert.Equal(t, false, resp["allow_cloud"])
}

func TestHandleLLMProviderModels_NotFound(t *testing.T) {
	srv, err := NewServer(testConfig(), testLogger())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/llm/providers/nonexistent/models", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleLLMTest_InvalidBody(t *testing.T) {
	srv, err := NewServer(testConfig(), testLogger())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/llm/test", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleLLMPull_InvalidBody(t *testing.T) {
	srv, err := NewServer(testConfig(), testLogger())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/llm/pull", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleLLMPull_NotFound(t *testing.T) {
	srv, err := NewServer(testConfig(), testLogger())
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]string{"provider": "nonexistent", "model": "test"})
	req := httptest.NewRequest(http.MethodPost, "/api/llm/pull", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleSessions(t *testing.T) {
	srv, err := NewServer(testConfig(), testLogger())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleSessionGet_NotImplemented(t *testing.T) {
	srv, err := NewServer(testConfig(), testLogger())
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/test-id", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestJSONError(t *testing.T) {
	w := httptest.NewRecorder()
	JSONError(w, "test error", http.StatusBadRequest)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "test error", resp.Error)
	assert.Equal(t, 400, resp.Code)
}

func TestJSONOK(t *testing.T) {
	w := httptest.NewRecorder()
	JSONOK(w, map[string]string{"key": "value"})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "value", resp["key"])
}
