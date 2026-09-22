package anthropic

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
	p := New("", "key", testLogger())
	assert.Equal(t, "anthropic", p.Name())
}

func TestProvider_Kind(t *testing.T) {
	p := New("", "key", testLogger())
	assert.Equal(t, llmtypes.KindCloud, p.Kind())
	assert.False(t, p.IsLocal())
}

func TestProvider_Capabilities(t *testing.T) {
	p := New("", "key", testLogger())
	caps := p.Capabilities()
	assert.True(t, caps.JSONMode)
	assert.True(t, caps.Streaming)
	assert.True(t, caps.ToolCalling)
	assert.True(t, caps.Vision)
}

func TestProvider_Chat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/messages", r.URL.Path)
		assert.Equal(t, "test-key", r.Header.Get("x-api-key"))
		assert.Equal(t, apiVersion, r.Header.Get("anthropic-version"))

		var req messagesRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "claude-sonnet-4-20250514", req.Model)
		assert.Equal(t, 100, req.MaxTokens)
		assert.False(t, req.Stream)
		assert.Equal(t, "Be helpful", req.System)

		_ = json.NewEncoder(w).Encode(messagesResponse{
			ID:    "msg-123",
			Model: "claude-sonnet-4-20250514",
			Content: []block{
				{Type: "text", Text: "Hello!"},
			},
			StopReason: "end_turn",
			Usage:      usage{InputTokens: 10, OutputTokens: 5},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "test-key", srv.Client(), testLogger())
	resp, _ := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "claude-sonnet-4-20250514", MaxTokens: 100,
		Messages: []llmtypes.Message{{Role: "system", Content: "Be helpful"}, {Role: "user", Content: "Hi"}},
	})

	assert.Equal(t, "Hello!", resp.Content)
	assert.Equal(t, "anthropic", resp.Provider)
	assert.Equal(t, 10, resp.Usage.PromptTokens)
	assert.Equal(t, 5, resp.Usage.CompletionTokens)
	assert.Equal(t, 15, resp.Usage.TotalTokens)
}

func TestProvider_Chat_SystemMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req messagesRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, "You are a security analyst", req.System)
		assert.Len(t, req.Messages, 1)

		_ = json.NewEncoder(w).Encode(messagesResponse{
			Content: []block{{Type: "text", Text: "ok"}},
			Usage:   usage{InputTokens: 1, OutputTokens: 1},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	_, _ = p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "claude-sonnet-4-20250514", MaxTokens: 100,
		Messages: []llmtypes.Message{{Role: "system", Content: "You are a security analyst"}, {Role: "user", Content: "Analyze"}},
	})
}

func TestProvider_Chat_DefaultMaxTokens(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req messagesRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.Equal(t, 4096, req.MaxTokens)

		_ = json.NewEncoder(w).Encode(messagesResponse{
			Content: []block{{Type: "text", Text: "ok"}}, Usage: usage{},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	_, _ = p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "claude-sonnet-4-20250514", Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
}

func TestProvider_Chat_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(errorResponse{
			Error: apiError{Type: "authentication_error", Message: "Invalid API key"},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "bad-key", srv.Client(), testLogger())
	_, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "claude-sonnet-4-20250514", MaxTokens: 100,
		Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
	assert.True(t, errors.Is(err, llmtypes.ErrAuthFailed))
}

func TestProvider_Chat_RateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(errorResponse{
			Error: apiError{Type: "rate_limit_error", Message: "Rate limit exceeded"},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	_, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "claude-sonnet-4-20250514", MaxTokens: 100,
		Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
	assert.True(t, errors.Is(err, llmtypes.ErrRateLimited))
	assert.Contains(t, err.Error(), "30")
}

func TestProvider_Chat_ModelNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(errorResponse{
			Error: apiError{Type: "not_found_error", Message: "Model not found"},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	_, err := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "nonexistent", MaxTokens: 100,
		Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
	assert.True(t, errors.Is(err, llmtypes.ErrModelNotFound))
}

func TestProvider_ChatStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req messagesRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		assert.True(t, req.Stream)

		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\"}\n\n"))
		_, _ = w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n"))
		_, _ = w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n\n"))
		_, _ = w.Write([]byte("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\n"))
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	stream, _ := p.ChatStream(context.Background(), llmtypes.ChatRequest{
		Model: "claude-sonnet-4-20250514", MaxTokens: 100,
		Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
	defer stream.Close()

	chunks := readTestChunks(stream)
	total := ""
	for _, c := range chunks {
		total += c.Content
	}
	assert.Contains(t, total, "Hello")
	assert.Contains(t, total, "world")
}

func TestProvider_Models(t *testing.T) {
	p := New("", "key", testLogger())
	models, _ := p.Models(context.Background())
	assert.NotEmpty(t, models)

	names := make(map[string]bool)
	for _, m := range models {
		names[m.Name] = true
	}
	assert.True(t, names["claude-sonnet-4-20250514"])
}

func TestProvider_Chat_CacheHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "prompt-caching-2024-07-31", r.Header.Get("anthropic-beta"))

		_ = json.NewEncoder(w).Encode(messagesResponse{
			Content: []block{{Type: "text", Text: "ok"}},
			Usage: usage{
				InputTokens: 100, OutputTokens: 50,
				CacheCreationInputTokens: 80, CacheReadInputTokens: 20,
			},
		})
	}))
	defer srv.Close()

	p := NewWithHTTPClient(srv.URL, "key", srv.Client(), testLogger())
	resp, _ := p.Chat(context.Background(), llmtypes.ChatRequest{
		Model: "claude-sonnet-4-20250514", MaxTokens: 100,
		Messages: []llmtypes.Message{{Role: "user", Content: "Hi"}},
	})
	assert.Equal(t, 100, resp.Usage.PromptTokens)
}

func TestProvider_DefaultURL(t *testing.T) {
	p := New("", "key", testLogger())
	assert.Equal(t, "https://api.anthropic.com", p.baseURL)
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
