package llm

import (
	"context"
	"log/slog"
	"testing"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
	"github.com/stretchr/testify/assert"
)

func TestDetector_DetectLocal(t *testing.T) {
	logger := slog.Default()
	detector := NewDetector(logger)

	mock := &MockProvider{name: "ollama", isLocal: true, available: true}

	providers := map[string]Provider{"ollama": mock}
	results := detector.DetectLocal(context.Background(), providers)

	// Should contain the configured ollama plus probe results.
	found := false
	for _, r := range results {
		if r.Name == "ollama" && r.Source == "config" {
			found = true
			assert.True(t, r.Available)
			assert.Equal(t, llmtypes.KindLocal, r.Kind)
		}
	}
	assert.True(t, found, "should contain configured ollama provider")
}

func TestDetector_DetectLocal_SkipsCloud(t *testing.T) {
	logger := slog.Default()
	detector := NewDetector(logger)

	local := &MockProvider{name: "local", isLocal: true, available: true}
	cloud := &MockProvider{name: "cloud", isLocal: false, available: true}

	providers := map[string]Provider{"local": local, "cloud": cloud}
	results := detector.DetectLocal(context.Background(), providers)

	for _, r := range results {
		assert.Equal(t, llmtypes.KindLocal, r.Kind, "should only include local providers")
	}
}

func TestDetector_FilterAvailable(t *testing.T) {
	logger := slog.Default()
	detector := NewDetector(logger)

	avail := &MockProvider{name: "avail", isLocal: true, available: true}
	unavail := &MockProvider{name: "unavail", isLocal: true, available: false}

	providers := map[string]Provider{"avail": avail, "unavail": unavail}
	filtered := detector.FilterAvailable(context.Background(), providers)

	assert.Len(t, filtered, 1)
	assert.Contains(t, filtered, "avail")
	assert.NotContains(t, filtered, "unavail")
}

func TestDetector_DetectAvailable_SortsLocalFirst(t *testing.T) {
	logger := slog.Default()
	detector := NewDetector(logger)

	local := &MockProvider{name: "local-p", isLocal: true, available: true}
	cloud := &MockProvider{name: "cloud-p", isLocal: false, available: true}

	providers := map[string]Provider{"cloud-p": cloud, "local-p": local}
	results := detector.DetectAvailable(context.Background(), providers)

	// Local should come before cloud.
	localIdx := -1
	cloudIdx := -1
	for i, r := range results {
		if r.Name == "local-p" {
			localIdx = i
		}
		if r.Name == "cloud-p" {
			cloudIdx = i
		}
	}
	assert.True(t, localIdx < cloudIdx, "local should come before cloud")
}

func TestDetector_DetectAvailable_IncludesProbes(t *testing.T) {
	logger := slog.Default()
	detector := NewDetector(logger)

	providers := map[string]Provider{}
	results := detector.DetectAvailable(context.Background(), providers)

	// Should have probe results for ollama, llamacpp, lmstudio, vllm, localai.
	names := make(map[string]bool)
	for _, r := range results {
		names[r.Name] = true
	}
	assert.True(t, names["ollama"])
	assert.True(t, names["llamacpp"])
	assert.True(t, names["lmstudio"])
}

func TestDetector_DetectAvailable_IncludesEnvChecks(t *testing.T) {
	logger := slog.Default()
	detector := NewDetector(logger)

	providers := map[string]Provider{}
	results := detector.DetectAvailable(context.Background(), providers)

	// Should have env check results.
	names := make(map[string]bool)
	for _, r := range results {
		names[r.Name] = true
	}
	assert.True(t, names["openai"])
	assert.True(t, names["anthropic"])
	assert.True(t, names["gemini"])
}

func TestDefaultProbes(t *testing.T) {
	probes := DefaultProbes()
	assert.NotEmpty(t, probes)

	names := make(map[string]bool)
	for _, p := range probes {
		names[p.Name] = true
	}
	assert.True(t, names["ollama"])
	assert.True(t, names["llamacpp"])
	assert.True(t, names["lmstudio"])
}

func TestDefaultEnvChecks(t *testing.T) {
	checks := DefaultEnvChecks()
	assert.NotEmpty(t, checks)

	names := make(map[string]bool)
	for _, c := range checks {
		names[c.Name] = true
	}
	assert.True(t, names["openai"])
	assert.True(t, names["anthropic"])
	assert.True(t, names["gemini"])
}

func TestDetectedProvider_Fields(t *testing.T) {
	dp := DetectedProvider{
		Name:      "test",
		Kind:      llmtypes.KindLocal,
		Available: true,
		Latency:   50,
		Models:    []string{"model1"},
		Source:    "probe",
	}
	assert.Equal(t, "test", dp.Name)
	assert.Equal(t, llmtypes.KindLocal, dp.Kind)
	assert.True(t, dp.Available)
	assert.Equal(t, int64(50), dp.Latency)
	assert.Equal(t, "probe", dp.Source)
}
