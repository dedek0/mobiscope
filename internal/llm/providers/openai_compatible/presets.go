package openaicompatible

import (
	"strings"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
)

// Preset defines connection defaults for an OpenAI-compatible provider.
type Preset struct {
	// DisplayName is the human-readable name.
	DisplayName string
	// BaseURL is the default API endpoint.
	BaseURL string
	// NeedsKey indicates whether an API key is required.
	NeedsKey bool
	// IsLocal indicates whether the provider runs locally.
	IsLocal bool
	// APIVersionHeader is set for Azure-style APIs that require api-version.
	APIVersionHeader bool
	// DefaultModel is the model to use if none is specified.
	DefaultModel string
}

// Presets maps provider names to their default configurations.
var Presets = map[string]Preset{
	"openai": {
		DisplayName:  "OpenAI",
		BaseURL:      "https://api.openai.com/v1",
		NeedsKey:     true,
		IsLocal:      false,
		DefaultModel: "gpt-4o-mini",
	},
	"llamacpp": {
		DisplayName:  "llama.cpp",
		BaseURL:      "http://localhost:8080/v1",
		NeedsKey:     false,
		IsLocal:      true,
		DefaultModel: "default",
	},
	"lmstudio": {
		DisplayName:  "LM Studio",
		BaseURL:      "http://localhost:1234/v1",
		NeedsKey:     false,
		IsLocal:      true,
		DefaultModel: "default",
	},
	"vllm": {
		DisplayName:  "vLLM",
		BaseURL:      "http://localhost:8000/v1",
		NeedsKey:     false,
		IsLocal:      true,
		DefaultModel: "default",
	},
	"localai": {
		DisplayName:  "LocalAI",
		BaseURL:      "http://localhost:8080/v1",
		NeedsKey:     false,
		IsLocal:      true,
		DefaultModel: "default",
	},
	"openrouter": {
		DisplayName:  "OpenRouter",
		BaseURL:      "https://openrouter.ai/api/v1",
		NeedsKey:     true,
		IsLocal:      false,
		DefaultModel: "openai/gpt-4o-mini",
	},
	"groq": {
		DisplayName:  "Groq",
		BaseURL:      "https://api.groq.com/openai/v1",
		NeedsKey:     true,
		IsLocal:      false,
		DefaultModel: "llama-3.1-8b-instant",
	},
	"together": {
		DisplayName:  "Together AI",
		BaseURL:      "https://api.together.xyz/v1",
		NeedsKey:     true,
		IsLocal:      false,
		DefaultModel: "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",
	},
	"azure": {
		DisplayName:      "Azure OpenAI",
		BaseURL:          "", // Must be set by user.
		NeedsKey:         true,
		IsLocal:          false,
		APIVersionHeader: true,
		DefaultModel:     "gpt-4o",
	},
	"fireworks": {
		DisplayName:  "Fireworks AI",
		BaseURL:      "https://api.fireworks.ai/inference/v1",
		NeedsKey:     true,
		IsLocal:      false,
		DefaultModel: "accounts/fireworks/models/llama-v3p1-8b-instruct",
	},
	"deepinfra": {
		DisplayName:  "DeepInfra",
		BaseURL:      "https://api.deepinfra.com/v1/openai",
		NeedsKey:     true,
		IsLocal:      false,
		DefaultModel: "meta-llama/Meta-Llama-3.1-8B-Instruct",
	},
	"perplexity": {
		DisplayName:  "Perplexity",
		BaseURL:      "https://api.perplexity.ai",
		NeedsKey:     true,
		IsLocal:      false,
		DefaultModel: "llama-3.1-sonar-small-128k-online",
	},
}

// ResolvePreset looks up a preset by name. If name is empty, it tries to
// match baseURL against known presets. Returns nil if no match.
func ResolvePreset(name, baseURL string) *Preset {
	if name != "" {
		if p, ok := Presets[name]; ok {
			return &p
		}
	}
	if baseURL != "" {
		for _, p := range Presets {
			if p.BaseURL == "" {
				continue
			}
			if strings.HasPrefix(baseURL, strings.TrimRight(p.BaseURL, "/")) {
				return &p
			}
		}
	}
	return nil
}

// IsLocalURL returns true if the URL points to localhost.
func IsLocalURL(url string) bool {
	return strings.Contains(url, "localhost") ||
		strings.Contains(url, "127.0.0.1") ||
		strings.Contains(url, "0.0.0.0")
}

// KindFromURL returns KindLocal or KindCloud based on the URL.
func KindFromURL(url string) llmtypes.ProviderKind {
	if IsLocalURL(url) {
		return llmtypes.KindLocal
	}
	return llmtypes.KindCloud
}
