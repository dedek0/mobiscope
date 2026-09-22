package gemini

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
	"github.com/stretchr/testify/assert"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestProvider_Name(t *testing.T) {
	p := New("key", testLogger())
	assert.Equal(t, "gemini", p.Name())
}

func TestProvider_Kind(t *testing.T) {
	p := New("key", testLogger())
	assert.Equal(t, llmtypes.KindCloud, p.Kind())
	assert.False(t, p.IsLocal())
}

func TestProvider_Capabilities(t *testing.T) {
	p := New("key", testLogger())
	caps := p.Capabilities()
	assert.True(t, caps.JSONMode)
	assert.True(t, caps.Streaming)
	assert.True(t, caps.ToolCalling)
	assert.True(t, caps.Vision)
}

func TestProvider_Chat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.Path, "/models/gemini-2.0-flash:generateContent")
		assert.Equal(t, "test-key", r.URL.Query().Get("key"))

		var req generateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Len(t, req.Contents, 1)
		assert.Equal(t, "user", req.Contents[0].Role)

		_ = json.NewEncoder(w).Encode(generateResponse{
			Candidates: []candidate{{
				Content:      content{Parts: []part{{Text: "Hello from Gemini!"}}},
				FinishReason: "STOP",
			}},
			UsageMetadata: usageMeta{PromptTokenCount: 8, CandidatesTokenCount: 4, TotalTokenCount: 12},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "test-key", srv.Client(), testLogger())
	resp, _ := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "gemini-2.0-flash", Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})

	assert.Equal(t, "Hello from Gemini!", resp.Content)
	assert.Equal(t, "gemini", resp.Provider)
	assert.Equal(t, 8, resp.Usage.PromptTokens)
	assert.Equal(t, 4, resp.Usage.CompletionTokens)
	assert.Equal(t, 12, resp.Usage.TotalTokens)
}

func TestProvider_Chat_SystemMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req generateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.NotNil(t, req.SystemInstruction)
		assert.Equal(t, "Be helpful", req.SystemInstruction.Parts[0].Text)

		_ = json.NewEncoder(w).Encode(generateResponse{
			Candidates: []candidate{{Content: content{Parts: []part{{Text: "ok"}}}}},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	_, _ = p.Chat(context.Background(), llmtypes.ChatRequest{
		Model:    "gemini-2.0-flash",
		Messages: []llmtypes.Message{{Role: "system", Content: "Be helpful"}, {Role: "user", Content: "Hi"}},
	})
}

func TestProvider_Chat_JSONMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req generateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "application/json", req.GenerationConfig.ResponseMimeType)

		_ = json.NewEncoder(w).Encode(generateResponse{
			Candidates: []candidate{{Content: content{Parts: []part{{Text: `{"key":"value"}`}}}}},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	resp, _ := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "gemini-2.0-flash", JSONMode: true,
		Messages: []llmtypes.Message{{Role: "user", Content: "Give JSON"}},
	})
	assert.Contains(t, resp.Content, "key")
}

func TestProvider_Chat_WithOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req generateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, float64(0.8), req.GenerationConfig.Temperature)
		assert.Equal(t, 200, req.GenerationConfig.MaxOutputTokens)

		_ = json.NewEncoder(w).Encode(generateResponse{
			Candidates: []candidate{{Content: content{Parts: []part{{Text: "ok"}}}}},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	_, _ = p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "gemini-2.0-flash", Temperature: 0.8, MaxTokens: 200,
		Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
}

func TestProvider_Chat_EmptyCandidates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(generateResponse{Candidates: []candidate{}})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	_, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "gemini-2.0-flash", Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty candidates")
}

func TestProvider_Chat_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(apiError{
			Error: struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
				Status  string `json:"status"`
			}{Code: 401, Message: "Invalid API key", Status: "UNAUTHENTICATED"},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "bad-key", srv.Client(), testLogger())
	_, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "gemini-2.0-flash", Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
	assert.True(t, errors.Is(err, llmtypes.ErrAuthFailed))
}

func TestProvider_Chat_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(apiError{
			Error: struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
				Status  string `json:"status"`
			}{Code: 429, Message: "Quota exceeded", Status: "RESOURCE_EXHAUSTED"},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	_, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "gemini-2.0-flash", Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
	assert.True(t, errors.Is(err, llmtypes.ErrRateLimited))
	assert.Contains(t, err.Error(), "60")
}

func TestProvider_Chat_ModelNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(apiError{
			Error: struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
				Status  string `json:"status"`
			}{Code: 404, Message: "Model not found", Status: "NOT_FOUND"},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	_, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "nonexistent", Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
	assert.True(t, errors.Is(err, llmtypes.ErrModelNotFound))
}

func TestProvider_ChatStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Hello\"}]}}],\"usageMetadata\":{}}\n\n"))
		_, _ = w.Write([]byte("data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\" world\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{}}\n\n"))
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	stream, _ := p.ChatStream(context.Background(), llmtypes.ChatRequest{
		Model: "gemini-2.0-flash", Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
	defer stream.Close()

	chunks := readTestChunks(stream)
	total := ""
	foundDone := false
	for _, c := range chunks {
		total += c.Content
		if c.Done {
			foundDone = true
		}
	}
	assert.Contains(t, total, "Hello")
	assert.Contains(t, total, "world")
	assert.True(t, foundDone)
}

func TestProvider_IsAvailable_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	assert.True(t, p.IsAvailable(context.Background()))
}

func TestProvider_Models(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"models": []map[string]string{
				{"name": "models/gemini-2.0-flash"},
				{"name": "models/gemini-1.5-pro"},
			},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	models, _ := p.Models(context.Background())
	assert.Len(t, models, 2)
	assert.Equal(t, "gemini-2.0-flash", models[0].Name)
}

func TestProvider_Chat_RoleMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req generateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Len(t, req.Contents, 3)
		assert.Equal(t, "user", req.Contents[0].Role)
		assert.Equal(t, "model", req.Contents[1].Role)
		assert.Equal(t, "user", req.Contents[2].Role)

		_ = json.NewEncoder(w).Encode(generateResponse{
			Candidates: []candidate{{Content: content{Parts: []part{{Text: "ok"}}}}},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	_, _ = p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "gemini-2.0-flash",
		Messages: []llmtypes.Message{
			{Role: "user", Content: "Hi"},
			{Role: "assistant", Content: "Hello"},
			{Role: "user", Content: "How are you?"},
		},
	})
}

func readTestChunks(r interface{ Read([]byte) (int, error) }) []llmtypes.StreamChunk {
	var chunks []llmtypes.StreamChunk
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			start := 0
			for i, b := range buf[:n] {
				if b == '\n' {
					line := buf[start:i]
					if len(line) > 0 {
						var chunk llmtypes.StreamChunk
						if jsonErr := json.Unmarshal(line, &chunk); jsonErr == nil {
							chunks = append(chunks, chunk)
						}
					}
					start = i + 1
				}
			}
		}
		if err != nil {
			break
		}
	}
	return chunks
}
