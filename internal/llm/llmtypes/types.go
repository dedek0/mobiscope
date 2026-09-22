// Package llmtypes defines the core types for the provider-agnostic LLM layer.
//
// All LLM providers implement the [Provider] interface. The [ChatRequest] and
// [ChatResponse] types carry messages and metadata between callers and providers.
// [Capabilities] advertises what a provider supports (JSON mode, streaming, etc.).
package llmtypes

import (
	"context"
	"errors"
	"io"
)

// ProviderKind classifies a provider as local or cloud.
type ProviderKind int

const (
	// KindLocal indicates a provider running on the user's machine (e.g., Ollama).
	KindLocal ProviderKind = iota
	// KindCloud indicates a remote provider (e.g., OpenAI, Anthropic).
	KindCloud
)

func (k ProviderKind) String() string {
	switch k {
	case KindLocal:
		return "local"
	case KindCloud:
		return "cloud"
	default:
		return "unknown"
	}
}

// Sentinel errors returned by providers.
var (
	// ErrProviderUnavailable indicates the provider endpoint is unreachable.
	ErrProviderUnavailable = errors.New("provider unavailable")
	// ErrModelNotFound indicates the requested model does not exist on the provider.
	ErrModelNotFound = errors.New("model not found")
	// ErrCapabilityUnsupported indicates the provider lacks a required capability.
	ErrCapabilityUnsupported = errors.New("capability unsupported")
	// ErrCloudNotAllowed indicates cloud providers are blocked by policy.
	ErrCloudNotAllowed = errors.New("cloud providers not allowed")
	// ErrRateLimited indicates the provider throttled the request.
	// Callers should check for RetryAfter on the wrapped error.
	ErrRateLimited = errors.New("rate limited")
	// ErrAuthFailed indicates invalid or missing credentials.
	ErrAuthFailed = errors.New("authentication failed")
)

// Backwards-compatible aliases (deprecated: use the Err* variants).
var (
	ErrProviderNotAvailable   = ErrProviderUnavailable
	ErrModelNotSupported      = ErrModelNotFound
	ErrCapabilityNotSupported = ErrCapabilityUnsupported
)

// TaskType identifies the purpose of an LLM call.
type TaskType string

const (
	TaskTriage      TaskType = "triage"
	TaskRemediation TaskType = "remediation"
	TaskChat        TaskType = "chat"
	TaskCorrelate   TaskType = "correlate"
)

// Capability identifies a single provider capability.
type Capability string

const (
	CapJSONMode    Capability = "json_mode"
	CapStreaming   Capability = "streaming"
	CapToolCalling Capability = "tool_calling"
	CapVision      Capability = "vision"
)

// Capabilities advertises what a provider supports.
type Capabilities struct {
	JSONMode    bool `json:"json_mode"`
	Streaming   bool `json:"streaming"`
	ToolCalling bool `json:"tool_calling"`
	Vision      bool `json:"vision"`
}

// Has returns true if cap is supported.
func (c Capabilities) Has(cap Capability) bool {
	switch cap {
	case CapJSONMode:
		return c.JSONMode
	case CapStreaming:
		return c.Streaming
	case CapToolCalling:
		return c.ToolCalling
	case CapVision:
		return c.Vision
	default:
		return false
	}
}

// Message is a single turn in a conversation.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest is sent to a provider.
type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	JSONMode    bool      `json:"json_mode,omitempty"`
	Stream      bool      `json:"stream,omitempty"`
}

// ChatResponse is returned by a provider after a non-streaming call.
type ChatResponse struct {
	Content      string `json:"content"`
	Model        string `json:"model"`
	Provider     string `json:"provider"`
	FinishReason string `json:"finish_reason,omitempty"`
	Usage        Usage  `json:"usage"`
}

// Usage tracks token consumption.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// StreamChunk is a single piece of a streaming response.
type StreamChunk struct {
	Content      string `json:"content"`
	Done         bool   `json:"done"`
	FinishReason string `json:"finish_reason,omitempty"`
}

// ModelInfo describes a model available on a provider.
type ModelInfo struct {
	Name     string `json:"name"`
	Size     int64  `json:"size,omitempty"`
	Modified string `json:"modified,omitempty"`
}

// Provider is the interface all LLM providers must implement.
//
// Implementations must be safe for concurrent use. Methods accept a context
// for cancellation and deadline propagation.
type Provider interface {
	// Name returns the provider identifier (e.g., "ollama", "openai").
	Name() string

	// Kind returns whether the provider is local or cloud.
	Kind() ProviderKind

	// IsLocal is a convenience accessor; returns true for KindLocal.
	IsLocal() bool

	// Capabilities reports what the provider supports.
	Capabilities() Capabilities

	// Chat sends a non-streaming request and returns the complete response.
	Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error)

	// ChatStream sends a streaming request. The returned ReadCloser yields
	// newline-delimited JSON [StreamChunk] objects. Caller must close it.
	ChatStream(ctx context.Context, req ChatRequest) (io.ReadCloser, error)

	// IsAvailable performs a health check against the provider endpoint.
	IsAvailable(ctx context.Context) bool

	// Models lists the models available on this provider.
	Models(ctx context.Context) ([]ModelInfo, error)
}
