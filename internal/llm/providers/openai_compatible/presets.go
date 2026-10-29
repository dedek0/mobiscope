package openaicompatible

import (
	"net/url"
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
	// DefaultModel is the model to use if none is specified.
	DefaultModel string
}

const (
	defaultLocalBaseURL = "http://localhost:8080/v1"
	defaultModelName    = "default"
)

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
		BaseURL:      defaultLocalBaseURL,
		NeedsKey:     false,
		IsLocal:      true,
		DefaultModel: defaultModelName,
	},
	"lmstudio": {
		DisplayName:  "LM Studio",
		BaseURL:      "http://localhost:1234/v1",
		NeedsKey:     false,
		IsLocal:      true,
		DefaultModel: defaultModelName,
	},
	"vllm": {
		DisplayName:  "vLLM",
		BaseURL:      "http://localhost:8000/v1",
		NeedsKey:     false,
		IsLocal:      true,
		DefaultModel: defaultModelName,
	},
	"localai": {
		DisplayName:  "LocalAI",
		BaseURL:      defaultLocalBaseURL,
		NeedsKey:     false,
		IsLocal:      true,
		DefaultModel: defaultModelName,
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
		DisplayName:  "Azure OpenAI",
		BaseURL:      "", // Must be set by user (include ?api-version=... if required).
		NeedsKey:     true,
		IsLocal:      false,
		DefaultModel: "gpt-4o",
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

// IsLocalURL reports whether the URL points at the local machine.
//
// The hostname is compared exactly: a substring test classified
// "https://localhost.evil.example" and "https://evil.example/?x=127.0.0.1"
// as local, which let a crafted base_url bypass the cloud policy and ship
// secrets to a remote host.
func IsLocalURL(rawURL string) bool {
	host := URLHost(rawURL)
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0", "[::1]":
		return true
	}
	// 127.0.0.0/8 is entirely loopback.
	if strings.HasPrefix(host, "127.") {
		return true
	}
	return false
}

// URLHost returns the hostname of a URL, or "" when it cannot be parsed.
func URLHost(rawURL string) string {
	raw := strings.TrimSpace(rawURL)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// KindFromURL returns KindLocal or KindCloud based on the URL.
func KindFromURL(url string) llmtypes.ProviderKind {
	if IsLocalURL(url) {
		return llmtypes.KindLocal
	}
	return llmtypes.KindCloud
}
