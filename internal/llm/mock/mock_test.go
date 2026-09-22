package mock

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockProvider_Defaults(t *testing.T) {
	m := New()
	assert.Equal(t, "mock", m.Name())
	assert.Equal(t, llmtypes.KindLocal, m.Kind())
	assert.True(t, m.IsLocal())
	assert.True(t, m.Capabilities().JSONMode)
	assert.True(t, m.IsAvailable(context.Background()))
}

func TestMockProvider_WithOptions(t *testing.T) {
	m := New(
		WithName("test-provider"),
		WithKind(llmtypes.KindCloud),
		WithAvailable(false),
		WithCapabilities(llmtypes.Capabilities{Vision: true}),
	)

	assert.Equal(t, "test-provider", m.Name())
	assert.Equal(t, llmtypes.KindCloud, m.Kind())
	assert.False(t, m.IsLocal())
	assert.False(t, m.IsAvailable(context.Background()))
	assert.True(t, m.Capabilities().Vision)
}

func TestMockProvider_Models(t *testing.T) {
	m := New(WithModels([]llmtypes.ModelInfo{
		{Name: "custom:1b"},
	}))

	models, err := m.Models(context.Background())
	require.NoError(t, err)
	assert.Len(t, models, 1)
	assert.Equal(t, "custom:1b", models[0].Name)
}

func TestMockProvider_Chat_DefaultResponse(t *testing.T) {
	m := New()
	resp, err := m.Chat(context.Background(), llmtypes.ChatRequest{
		Model:    "test",
		Messages: []llmtypes.Message{{Role: "user", Content: "hi"}},
	})

	require.NoError(t, err)
	assert.Contains(t, resp.Content, "mock response")
	assert.Equal(t, "test", resp.Model)
	assert.Equal(t, "mock", resp.Provider)
}

func TestMockProvider_Chat_CustomFunc(t *testing.T) {
	m := New(WithChatFunc(func(_ context.Context, req llmtypes.ChatRequest) (*llmtypes.ChatResponse, error) {
		return &llmtypes.ChatResponse{
			Content:  "custom: " + req.Messages[0].Content,
			Model:    req.Model,
			Provider: "custom",
		}, nil
	}))

	resp, err := m.Chat(context.Background(), llmtypes.ChatRequest{
		Model:    "m",
		Messages: []llmtypes.Message{{Role: "user", Content: "hello"}},
	})

	require.NoError(t, err)
	assert.Equal(t, "custom: hello", resp.Content)
}

func TestMockProvider_ChatRecordsCalls(t *testing.T) {
	m := New()
	assert.Empty(t, m.ChatCalls())

	_, _ = m.Chat(context.Background(), llmtypes.ChatRequest{Model: "a"})
	_, _ = m.Chat(context.Background(), llmtypes.ChatRequest{Model: "b"})

	calls := m.ChatCalls()
	assert.Len(t, calls, 2)
	assert.Equal(t, "a", calls[0].Model)
	assert.Equal(t, "b", calls[1].Model)
}

func TestMockProvider_ChatStream(t *testing.T) {
	m := New()
	stream, err := m.ChatStream(context.Background(), llmtypes.ChatRequest{Model: "test"})
	require.NoError(t, err)
	defer stream.Close()

	data, err := io.ReadAll(stream)
	require.NoError(t, err)
	assert.Contains(t, string(data), "mock")
	assert.Contains(t, string(data), "done")
}

func TestMockProvider_Latency(t *testing.T) {
	m := New(WithLatency(50 * time.Millisecond))
	start := time.Now()
	m.IsAvailable(context.Background())
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed.Milliseconds(), int64(40))
}

func TestMockProvider_Pull(t *testing.T) {
	m := New()
	assert.NoError(t, m.Pull(context.Background(), "any-model"))
}

func TestMockProvider_PullError(t *testing.T) {
	m := New(WithPullError(assert.AnError))
	assert.Error(t, m.Pull(context.Background(), "model"))
}
