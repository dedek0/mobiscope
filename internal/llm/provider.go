package llm

import "github.com/dedek0/mobiscope/internal/llm/llmtypes"

// Re-export types for convenience.
type (
	Provider     = llmtypes.Provider
	Capabilities = llmtypes.Capabilities
	ChatRequest  = llmtypes.ChatRequest
	ChatResponse = llmtypes.ChatResponse
	Message      = llmtypes.Message
	Usage        = llmtypes.Usage
	StreamChunk  = llmtypes.StreamChunk
	TaskType     = llmtypes.TaskType
	Capability   = llmtypes.Capability
	ProviderKind = llmtypes.ProviderKind
)

var (
	ErrProviderUnavailable   = llmtypes.ErrProviderUnavailable
	ErrModelNotFound         = llmtypes.ErrModelNotFound
	ErrCloudNotAllowed       = llmtypes.ErrCloudNotAllowed
	ErrCapabilityUnsupported = llmtypes.ErrCapabilityUnsupported
	ErrRateLimited           = llmtypes.ErrRateLimited
	ErrAuthFailed            = llmtypes.ErrAuthFailed
)

const (
	CapJSONMode    = llmtypes.CapJSONMode
	CapStreaming   = llmtypes.CapStreaming
	CapToolCalling = llmtypes.CapToolCalling
	CapVision      = llmtypes.CapVision
)

const (
	TaskTriage      = llmtypes.TaskTriage
	TaskRemediation = llmtypes.TaskRemediation
	TaskChat        = llmtypes.TaskChat
	TaskCorrelate   = llmtypes.TaskCorrelate
)

const (
	KindLocal = llmtypes.KindLocal
	KindCloud = llmtypes.KindCloud
)
