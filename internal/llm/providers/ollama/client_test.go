package ollama

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

func TestProvider_Name(t *testing.T) {
	p := New("", testLogger())
	assert.Equal(t, "ollama", p.Name())
}

func TestProvider_Kind(t *testing.T) {
	p := New("", testLogger())
	assert.Equal(t, llmtypes.KindLocal, p.Kind())
	assert.True(t, p.IsLocal())
}

func TestProvider_Capabilities(t *testing.T) {
	p := New("", testLogger())
	caps := p.Capabilities()
	assert.True(t, caps.JSONMode)
	assert.True(t, caps.Streaming)
	assert.True(t, caps.ToolCalling)
}

func TestProvider_IsAvailable_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := New(srv.URL, testLogger())
	assert.True(t, p.IsAvailable(context.Background()))
}

func TestProvider_IsAvailable_Down(t *testing.T) {
	p := New("http://127.0.0.1:1", testLogger())
	assert.False(t, p.IsAvailable(context.Background()))
}

func TestProvider_Models(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(tagsResponse{
			Models: []ollamaModel{
				{Name: "qwen2.5:7b", Size: 4500000000},
				{Name: "llama3.1:8b", Size: 4700000000},
			},
		})
	}))
	defer srv.Close()

	p := New(srv.URL, testLogger())
	models, err := p.Models(context.Background())
	require.NoError(t, err)
	assert.Len(t, models, 2)
	assert.Equal(t, "qwen2.5:7b", models[0].Name)
	assert.Equal(t, int64(4500000000), models[0].Size)
}

func TestProvider_Models_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := New(srv.URL, testLogger())
	_, err := p.Models(context.Background())
	assert.Error(t, err)
}

func TestProvider_Chat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/chat", r.URL.Path)

		var req ollamaChatRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "test-model", req.Model)
		assert.False(t, req.Stream)

		_ = json.NewEncoder(w).Encode(ollamaChatResponse{
			Model:           "test-model",
			Message:         llmtypes.Message{Role: "assistant", Content: "Hello!"},
			Done:            true,
			PromptEvalCount: 10,
			EvalCount:       5,
		})
	}))
	defer srv.Close()

	p := New(srv.URL, testLogger())
	resp, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model:    "test-model",
		Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})

	require.NoError(t, err)
	assert.Equal(t, "Hello!", resp.Content)
	assert.Equal(t, "test-model", resp.Model)
	assert.Equal(t, "ollama", resp.Provider)
	assert.Equal(t, 10, resp.Usage.PromptTokens)
	assert.Equal(t, 5, resp.Usage.CompletionTokens)
}

func TestProvider_Chat_WithJSONMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ollamaChatRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "json", req.Format)

		_ = json.NewEncoder(w).Encode(ollamaChatResponse{
			Model:   "test-model",
			Message: llmtypes.Message{Role: "assistant", Content: `{"key":"value"}`},
			Done:    true,
		})
	}))
	defer srv.Close()

	p := New(srv.URL, testLogger())
	resp, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model:    "test-model",
		Messages: []llmtypes.Message{{Role: "user", Content: "Give JSON"}},
		JSONMode: true,
	})

	require.NoError(t, err)
	assert.Contains(t, resp.Content, "key")
}

func TestProvider_Chat_WithOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ollamaChatRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.NotNil(t, req.Options)
		assert.NotNil(t, req.Options.Temperature)
		assert.NotNil(t, req.Options.NumPredict)

		_ = json.NewEncoder(w).Encode(ollamaChatResponse{
			Model:   "test-model",
			Message: llmtypes.Message{Role: "assistant", Content: "ok"},
			Done:    true,
		})
	}))
	defer srv.Close()

	p := New(srv.URL, testLogger())
	_, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model:       "test-model",
		Messages:    []llmtypes.Message{{Role: "user", Content: "Hi"}},
		Temperature: 0.7,
		MaxTokens:   100,
	})

	require.NoError(t, err)
}

func TestProvider_Chat_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("model not found"))
	}))
	defer srv.Close()

	p := New(srv.URL, testLogger())
	_, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model:    "nonexistent",
		Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestProvider_ChatStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ollamaChatRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.True(t, req.Stream)

		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = w.Write([]byte(`{"content":"Hello","done":false}` + "\n"))
		_, _ = w.Write([]byte(`{"content":" world","done":false}` + "\n"))
		_, _ = w.Write([]byte(`{"content":"","done":true}` + "\n"))
	}))
	defer srv.Close()

	p := New(srv.URL, testLogger())
	stream, err := p.ChatStream(context.Background(), llmtypes.ChatRequest{
		Model:    "test-model",
		Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})

	require.NoError(t, err)
	defer stream.Close()

	chunks, err := ReadStreamChunks(stream)
	require.NoError(t, err)
	assert.Len(t, chunks, 3)
	assert.Equal(t, "Hello", chunks[0].Content)
	assert.False(t, chunks[0].Done)
	assert.True(t, chunks[2].Done)
}

func TestProvider_Pull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		_, _ = w.Write([]byte(`{"status":"pulling manifest"}` + "\n"))
		_, _ = w.Write([]byte(`{"status":"downloading"}` + "\n"))
		_, _ = w.Write([]byte(`{"status":"success"}` + "\n"))
	}))
	defer srv.Close()

	p := New(srv.URL, testLogger())
	err := p.Pull(context.Background(), "test-model:latest")
	assert.NoError(t, err)
}

func TestProvider_Pull_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("model not found"))
	}))
	defer srv.Close()

	p := New(srv.URL, testLogger())
	err := p.Pull(context.Background(), "nonexistent:model")
	assert.Error(t, err)
}

func TestNew_DefaultURL(t *testing.T) {
	p := New("", testLogger())
	assert.Equal(t, "http://localhost:11434", p.baseURL)
}

func TestNewWithHTTPClient(t *testing.T) {
	client := &http.Client{}
	p := NewWithHTTPClient("http://custom:9999", client, testLogger())
	assert.Equal(t, "http://custom:9999", p.baseURL)
}

func TestReadStreamChunks_InvalidJSON(t *testing.T) {
	r := &simpleReader{data: []byte("not json\n")}
	_, err := ReadStreamChunks(r)
	assert.Error(t, err)
}

type simpleReader struct {
	data []byte
	pos  int
}

func (r *simpleReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, nil
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
