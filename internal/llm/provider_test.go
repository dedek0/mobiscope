package llm

import (
	"context"
	"io"
	"testing"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockProvider is a test implementation of the Provider interface.
type MockProvider struct {
	name      string
	isLocal   bool
	caps      Capabilities
	available bool
	chatFunc  func(ctx context.Context, req ChatRequest) (*ChatResponse, error)
}

func (m *MockProvider) Name() string { return m.name }
func (m *MockProvider) Kind() llmtypes.ProviderKind {
	if m.isLocal {
		return llmtypes.KindLocal
	}
	return llmtypes.KindCloud
}
func (m *MockProvider) IsLocal() bool                      { return m.isLocal }
func (m *MockProvider) Capabilities() Capabilities         { return m.caps }
func (m *MockProvider) IsAvailable(_ context.Context) bool { return m.available }

func (m *MockProvider) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	if m.chatFunc != nil {
		return m.chatFunc(ctx, req)
	}
	return &ChatResponse{
		Content:  "mock response",
		Model:    req.Model,
		Provider: m.name,
		Usage:    Usage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15},
	}, nil
}

func (m *MockProvider) ChatStream(_ context.Context, _ ChatRequest) (io.ReadCloser, error) {
	return nil, ErrCapabilityUnsupported
}

func (m *MockProvider) Models(_ context.Context) ([]llmtypes.ModelInfo, error) {
	return []llmtypes.ModelInfo{
		{Name: "mock-model-1"},
		{Name: "mock-model-2"},
	}, nil
}

func TestCapabilities_Has(t *testing.T) {
	caps := Capabilities{
		JSONMode:    true,
		Streaming:   true,
		ToolCalling: false,
		Vision:      false,
	}

	assert.True(t, caps.Has(CapJSONMode))
	assert.True(t, caps.Has(CapStreaming))
	assert.False(t, caps.Has(CapToolCalling))
	assert.False(t, caps.Has(CapVision))
}

func TestCapabilities_HasUnknown(t *testing.T) {
	caps := Capabilities{}
	assert.False(t, caps.Has(Capability("unknown")))
}

func TestMockProvider_Interface(t *testing.T) {
	var _ Provider = &MockProvider{}
}

func TestMockProvider_BasicMethods(t *testing.T) {
	p := &MockProvider{
		name:      "test",
		isLocal:   true,
		available: true,
		caps:      Capabilities{JSONMode: true, Streaming: true},
	}

	assert.Equal(t, "test", p.Name())
	assert.Equal(t, llmtypes.KindLocal, p.Kind())
	assert.True(t, p.IsLocal())
	assert.True(t, p.IsAvailable(context.Background()))
	assert.True(t, p.Capabilities().Has(CapJSONMode))
}

func TestMockProvider_Chat(t *testing.T) {
	p := &MockProvider{name: "test", available: true}
	resp, err := p.Chat(context.Background(), ChatRequest{
		Model:    "test-model",
		Messages: []Message{{Role: "user", Content: "hello"}},
	})

	require.NoError(t, err)
	assert.Equal(t, "mock response", resp.Content)
	assert.Equal(t, "test", resp.Provider)
}

func TestMockProvider_Models(t *testing.T) {
	p := &MockProvider{}
	models, err := p.Models(context.Background())
	require.NoError(t, err)
	assert.Len(t, models, 2)
	assert.Equal(t, "mock-model-1", models[0].Name)
}

func TestErrorVariables(t *testing.T) {
	assert.Error(t, ErrProviderUnavailable)
	assert.Error(t, ErrModelNotFound)
	assert.Error(t, ErrCloudNotAllowed)
	assert.Error(t, ErrCapabilityUnsupported)
}

func TestTaskType_Constants(t *testing.T) {
	assert.Equal(t, TaskType("triage"), TaskTriage)
	assert.Equal(t, TaskType("remediation"), TaskRemediation)
	assert.Equal(t, TaskType("chat"), TaskChat)
	assert.Equal(t, TaskType("correlate"), TaskCorrelate)
}

func TestProviderKind_String(t *testing.T) {
	assert.Equal(t, "local", KindLocal.String())
	assert.Equal(t, "cloud", KindCloud.String())
}
