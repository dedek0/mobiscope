package llm

import (
	"context"
	"log/slog"
	"os"
	"sort"
	"time"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
)

// DetectedProvider describes a discovered provider.
type DetectedProvider struct {
	Name      string                `json:"name"`
	Kind      llmtypes.ProviderKind `json:"kind"`
	Available bool                  `json:"available"`
	Latency   int64                 `json:"latency_ms"`
	Models    []string              `json:"models,omitempty"`
	Error     string                `json:"error,omitempty"`
	Source    string                `json:"source"` // "probe" or "env"
}

// Detector probes local endpoints and checks env vars to discover providers.
type Detector struct {
	logger *slog.Logger
}

// NewDetector creates a Detector.
func NewDetector(logger *slog.Logger) *Detector {
	return &Detector{logger: logger}
}

// ProbeTarget describes a local endpoint to probe.
type ProbeTarget struct {
	Name    string
	BaseURL string
}

// DefaultProbes returns the standard local endpoints to check.
func DefaultProbes() []ProbeTarget {
	return []ProbeTarget{
		{Name: "ollama", BaseURL: "http://localhost:11434"},
		{Name: "llamacpp", BaseURL: "http://localhost:8080"},
		{Name: "lmstudio", BaseURL: "http://localhost:1234"},
		{Name: "vllm", BaseURL: "http://localhost:8000"},
		{Name: "localai", BaseURL: "http://localhost:8080"},
	}
}

// EnvCheck describes an environment variable check for a cloud provider.
type EnvCheck struct {
	Name   string
	EnvVar string
}

// DefaultEnvChecks returns the standard env var checks.
func DefaultEnvChecks() []EnvCheck {
	return []EnvCheck{
		{Name: "openai", EnvVar: "OPENAI_API_KEY"},
		{Name: "anthropic", EnvVar: "ANTHROPIC_API_KEY"},
		{Name: "gemini", EnvVar: "GOOGLE_API_KEY"},
		{Name: "openrouter", EnvVar: "OPENROUTER_API_KEY"},
		{Name: "groq", EnvVar: "GROQ_API_KEY"},
		{Name: "together", EnvVar: "TOGETHER_API_KEY"},
		{Name: "azure", EnvVar: "AZURE_OPENAI_API_KEY"},
	}
}

// DetectAvailable probes local endpoints and checks env vars.
// Results are sorted: local available first, then cloud available, then unavailable.
func (d *Detector) DetectAvailable(ctx context.Context, providers map[string]Provider) []DetectedProvider {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	probeTargets := DefaultProbes()
	envChecks := DefaultEnvChecks()

	results := make([]DetectedProvider, 0, len(providers)+len(probeTargets)+len(envChecks))

	// Check configured providers.
	for name, p := range providers {
		dp := DetectedProvider{
			Name:   name,
			Kind:   p.Kind(),
			Source: "config",
		}

		start := time.Now()
		dp.Available = p.IsAvailable(ctx)
		dp.Latency = time.Since(start).Milliseconds()

		if dp.Available {
			if models, err := p.Models(ctx); err == nil {
				dp.Models = make([]string, len(models))
				for i, m := range models {
					dp.Models[i] = m.Name
				}
			}
			d.logger.Info("provider available", "provider", name, "kind", dp.Kind, "latency_ms", dp.Latency)
		}

		results = append(results, dp)
	}

	// Probe local endpoints not already configured.
	for _, target := range probeTargets {
		if _, exists := providers[target.Name]; exists {
			continue
		}
		dp := d.probeLocal(ctx, target)
		results = append(results, dp)
	}

	// Check env vars for cloud providers not already configured.
	for _, check := range envChecks {
		if _, exists := providers[check.Name]; exists {
			continue
		}
		dp := DetectedProvider{
			Name:   check.Name,
			Kind:   llmtypes.KindCloud,
			Source: "env",
		}
		if key := os.Getenv(check.EnvVar); key != "" {
			dp.Available = true
			d.logger.Info("cloud provider detected via env", "provider", check.Name, "env", check.EnvVar)
		}
		results = append(results, dp)
	}

	// Sort: local available first, then cloud available, then unavailable.
	sort.Slice(results, func(i, j int) bool {
		if results[i].Available != results[j].Available {
			return results[i].Available
		}
		if results[i].Kind != results[j].Kind {
			return results[i].Kind == llmtypes.KindLocal
		}
		return results[i].Name < results[j].Name
	})

	return results
}

func (d *Detector) probeLocal(ctx context.Context, target ProbeTarget) DetectedProvider {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	dp := DetectedProvider{
		Name:   target.Name,
		Kind:   llmtypes.KindLocal,
		Source: "probe",
	}

	// Use a lightweight HTTP GET to check if the endpoint is alive.
	start := time.Now()
	available := probeHTTPEndpoint(ctx, target.BaseURL)
	dp.Latency = time.Since(start).Milliseconds()
	dp.Available = available

	if available {
		d.logger.Info("local endpoint detected", "provider", target.Name, "url", target.BaseURL)
	}

	return dp
}

// FilterAvailable returns only available providers from the map.
func (d *Detector) FilterAvailable(ctx context.Context, providers map[string]Provider) map[string]Provider {
	available := make(map[string]Provider)
	for name, p := range providers {
		if p.IsAvailable(ctx) {
			available[name] = p
		}
	}
	return available
}

// DetectLocal is a convenience method that returns only local DetectionResults
// (backwards-compatible with the old API).
func (d *Detector) DetectLocal(ctx context.Context, providers map[string]Provider) []DetectedProvider {
	all := d.DetectAvailable(ctx, providers)
	var local []DetectedProvider
	for _, dp := range all {
		if dp.Kind == llmtypes.KindLocal {
			local = append(local, dp)
		}
	}
	return local
}
