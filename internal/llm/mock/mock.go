// Package mock provides a test double for llmtypes.Provider.
//
// Provider returns canned responses and supports configurable latency
// for deterministic testing without network access.
package mock

import (
	"context"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
)

// Provider is a configurable test double for llmtypes.Provider.
type Provider struct {
	mu        sync.Mutex
	name      string
	kind      llmtypes.ProviderKind
	caps      llmtypes.Capabilities
	available bool
	models    []llmtypes.ModelInfo
	chatFunc  func(ctx context.Context, req llmtypes.ChatRequest) (*llmtypes.ChatResponse, error)
	latency   time.Duration
	chatCalls []llmtypes.ChatRequest
	pullErr   error
}

// Option configures a Provider.
type Option func(*Provider)

// WithName sets the provider name.
func WithName(n string) Option { return func(m *Provider) { m.name = n } }

// WithKind sets the provider kind.
func WithKind(k llmtypes.ProviderKind) Option { return func(m *Provider) { m.kind = k } }

// WithCapabilities sets the capabilities.
func WithCapabilities(c llmtypes.Capabilities) Option { return func(m *Provider) { m.caps = c } }

// WithAvailable sets the health check result.
func WithAvailable(a bool) Option { return func(m *Provider) { m.available = a } }

// WithModels sets the list of models returned by Models().
func WithModels(models []llmtypes.ModelInfo) Option {
	return func(m *Provider) { m.models = models }
}

// WithChatFunc overrides the Chat implementation.
func WithChatFunc(fn func(ctx context.Context, req llmtypes.ChatRequest) (*llmtypes.ChatResponse, error)) Option {
	return func(m *Provider) { m.chatFunc = fn }
}

// WithLatency adds artificial latency to all calls.
func WithLatency(d time.Duration) Option { return func(m *Provider) { m.latency = d } }

// WithPullError sets the error returned by Pull.
func WithPullError(err error) Option { return func(m *Provider) { m.pullErr = err } }

// New creates a Provider with sensible defaults.
func New(opts ...Option) *Provider {
	m := &Provider{
		name:      "mock",
		kind:      llmtypes.KindLocal,
		caps:      llmtypes.Capabilities{JSONMode: true, Streaming: true},
		available: true,
		models: []llmtypes.ModelInfo{
			{Name: "mock-model:1b"},
			{Name: "mock-model:7b"},
		},
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (m *Provider) Name() string                        { return m.name }
func (m *Provider) Kind() llmtypes.ProviderKind         { return m.kind }
func (m *Provider) IsLocal() bool                       { return m.kind == llmtypes.KindLocal }
func (m *Provider) Capabilities() llmtypes.Capabilities { return m.caps }

func (m *Provider) IsAvailable(_ context.Context) bool {
	m.sleep()
	return m.available
}

func (m *Provider) Models(_ context.Context) ([]llmtypes.ModelInfo, error) {
	m.sleep()
	out := make([]llmtypes.ModelInfo, len(m.models))
	copy(out, m.models)
	return out, nil
}

func (m *Provider) Chat(ctx context.Context, req llmtypes.ChatRequest) (*llmtypes.ChatResponse, error) {
	m.sleep()
	m.mu.Lock()
	m.chatCalls = append(m.chatCalls, req)
	m.mu.Unlock()

	if m.chatFunc != nil {
		return m.chatFunc(ctx, req)
	}
	return &llmtypes.ChatResponse{
		Content:  "mock response for: " + req.Model,
		Model:    req.Model,
		Provider: m.name,
		Usage:    llmtypes.Usage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15},
	}, nil
}

func (m *Provider) ChatStream(_ context.Context, req llmtypes.ChatRequest) (io.ReadCloser, error) {
	m.sleep()
	chunks := []byte(`{"content":"mock ","done":false}` + "\n" +
		`{"content":"stream","done":false}` + "\n" +
		`{"content":"","done":true}` + "\n")
	return io.NopCloser(strings.NewReader(string(chunks))), nil
}

// ChatCalls returns all Chat requests made to this mock.
func (m *Provider) ChatCalls() []llmtypes.ChatRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]llmtypes.ChatRequest, len(m.chatCalls))
	copy(out, m.chatCalls)
	return out
}

// Pull simulates pulling a model.
func (m *Provider) Pull(_ context.Context, _ string) error {
	m.sleep()
	return m.pullErr
}

func (m *Provider) sleep() {
	if m.latency > 0 {
		time.Sleep(m.latency)
	}
}
