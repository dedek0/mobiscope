package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/dedek0/mobiscope/internal/config"
	"github.com/dedek0/mobiscope/internal/llm"
	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
	llmmock "github.com/dedek0/mobiscope/internal/llm/mock"
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

func newTestServer(t *testing.T) *Server {
	t.Helper()
	srv, err := NewServer(testConfig(), testLogger())
	require.NoError(t, err)
	return srv
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

func TestBearerAuth_EnforcedWhenTokenSet(t *testing.T) {
	t.Setenv("MOBISCOPE_API_TOKEN", "sekrit")
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/llm/config", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	req = httptest.NewRequest(http.MethodGet, "/api/llm/config", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	req = httptest.NewRequest(http.MethodGet, "/api/llm/config", nil)
	req.Header.Set("Authorization", "Bearer sekrit")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBearerAuth_DisabledWithoutToken(t *testing.T) {
	t.Setenv("MOBISCOPE_API_TOKEN", "")
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/llm/config", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBodyLimit_RejectsOversized(t *testing.T) {
	t.Setenv("MOBISCOPE_API_TOKEN", "")
	srv := newTestServer(t)

	huge := bytes.Repeat([]byte("a"), (1<<20)+10)
	req := httptest.NewRequest(http.MethodPost, "/api/llm/test", bytes.NewReader(huge))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestHandleMetrics(t *testing.T) {
	t.Setenv("MOBISCOPE_API_TOKEN", "")
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "mobiscope_build_info")
	assert.Contains(t, w.Body.String(), "mobiscope_providers")
	assert.Contains(t, w.Body.String(), "mobiscope_allow_cloud")
}

// postLLMTest posts a JSON body to /api/llm/test and returns the recorder.
func postLLMTest(t *testing.T, srv *Server, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/llm/test", bytes.NewReader(raw))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func TestHandleLLMTest_HonorsProviderAndModel(t *testing.T) {
	t.Setenv("MOBISCOPE_API_TOKEN", "")
	srv := newTestServer(t)
	m := llmmock.New(llmmock.WithName("custom"))
	srv.providers["custom"] = m

	w := postLLMTest(t, srv, map[string]string{
		"provider": "custom",
		"model":    "super-model",
		"task":     "triage",
	})
	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "custom", resp["provider"])
	assert.Equal(t, "super-model", resp["model"])
	assert.Equal(t, "triage", resp["task"])
	assert.Contains(t, fmt.Sprint(resp["response"]), "super-model")

	// The provider actually invoked must be the requested one, called with
	// the requested model — this is the regression from PR 3.
	calls := m.ChatCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "super-model", calls[0].Model)
	require.Len(t, calls[0].Messages, 1)
	assert.Equal(t, "user", calls[0].Messages[0].Role)
}

func TestHandleLLMTest_ExplicitProviderFallsBackToTaskModel(t *testing.T) {
	t.Setenv("MOBISCOPE_API_TOKEN", "")
	srv := newTestServer(t)
	m := llmmock.New(llmmock.WithName("custom"))
	srv.providers["custom"] = m

	// Model omitted: the configured triage task model must be used.
	w := postLLMTest(t, srv, map[string]string{"provider": "custom", "task": "triage"})
	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "qwen2.5-coder:7b", resp["model"])

	calls := m.ChatCalls()
	require.Len(t, calls, 1)
	assert.Equal(t, "qwen2.5-coder:7b", calls[0].Model)
}

func TestHandleLLMTest_CloudRefusedWhenNotAllowed(t *testing.T) {
	t.Setenv("MOBISCOPE_API_TOKEN", "")
	srv := newTestServer(t)
	require.False(t, srv.cfg.LLM.AllowCloud)

	cloud := llmmock.New(
		llmmock.WithName("cloudmock"),
		llmmock.WithKind(llmtypes.KindCloud),
	)
	srv.providers["cloudmock"] = cloud

	w := postLLMTest(t, srv, map[string]string{"provider": "cloudmock", "model": "gpt-x"})
	assert.Equal(t, http.StatusForbidden, w.Code)

	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "cloud providers are disabled")

	// Refusal must happen before any provider call.
	assert.Empty(t, cloud.ChatCalls())
}

func TestHandleLLMTest_CloudAllowedWhenEnabled(t *testing.T) {
	t.Setenv("MOBISCOPE_API_TOKEN", "")
	cfg := testConfig()
	cfg.LLM.AllowCloud = true
	srv, err := NewServer(cfg, testLogger())
	require.NoError(t, err)

	cloud := llmmock.New(
		llmmock.WithName("cloudmock"),
		llmmock.WithKind(llmtypes.KindCloud),
	)
	srv.providers["cloudmock"] = cloud

	w := postLLMTest(t, srv, map[string]string{"provider": "cloudmock", "model": "gpt-x"})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Len(t, cloud.ChatCalls(), 1)
}

func TestHandleLLMTest_UnknownProvider(t *testing.T) {
	t.Setenv("MOBISCOPE_API_TOKEN", "")
	srv := newTestServer(t)

	w := postLLMTest(t, srv, map[string]string{"provider": "nonexistent", "model": "m"})
	assert.Equal(t, http.StatusNotFound, w.Code)

	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "provider not found")
}

func TestHandleLLMTest_ProviderWithoutModel(t *testing.T) {
	t.Setenv("MOBISCOPE_API_TOKEN", "")
	srv := newTestServer(t)
	m := llmmock.New(llmmock.WithName("custom"))
	srv.providers["custom"] = m

	// Provider set explicitly but neither model nor a configured task model.
	w := postLLMTest(t, srv, map[string]string{"provider": "custom", "task": "no-such-task"})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Contains(t, resp.Error, "model is required")
	assert.Empty(t, m.ChatCalls())
}

func TestHandleLLMTest_NoProviderAvailable(t *testing.T) {
	t.Setenv("MOBISCOPE_API_TOKEN", "")
	srv := newTestServer(t)
	// Empty registry: routing must fail without touching the network.
	srv.providers = map[string]llm.Provider{}

	w := postLLMTest(t, srv, map[string]string{"task": "triage"})
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleLLMTest_EmptyBodyIsInvalidJSON(t *testing.T) {
	t.Setenv("MOBISCOPE_API_TOKEN", "")
	srv := newTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/llm/test", bytes.NewReader(nil))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleLLMTest_EmptyObjectRoutesViaConfig(t *testing.T) {
	t.Setenv("MOBISCOPE_API_TOKEN", "")
	srv := newTestServer(t)
	// A well-formed but empty body selects the default "triage" task and the
	// configured (unreachable) ollama provider — must be a routing failure,
	// not a decode failure.
	srv.providers = map[string]llm.Provider{}

	w := postLLMTest(t, srv, map[string]string{})
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}
