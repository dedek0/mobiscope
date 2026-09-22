package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/dedek0/mobiscope/internal/config"
	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func triageTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newTriageMockProvider(verdict string) *MockProvider {
	resp := TriageResponse{
		Verdict:     verdict,
		Confidence:  0.9,
		Explanation: "test explanation",
		Remediation: "test remediation",
	}
	raw, _ := json.Marshal(resp)

	return &MockProvider{
		name:      "mock-triage",
		isLocal:   true,
		available: true,
		caps:      Capabilities{JSONMode: true},
		chatFunc: func(_ context.Context, _ llmtypes.ChatRequest) (*llmtypes.ChatResponse, error) {
			return &llmtypes.ChatResponse{
				Content:  string(raw),
				Model:    "mock-model",
				Provider: "mock-triage",
				Usage:    llmtypes.Usage{PromptTokens: 100, CompletionTokens: 50},
			}, nil
		},
	}
}

func newFailingMockProvider() *MockProvider {
	return &MockProvider{
		name:      "failing",
		isLocal:   true,
		available: true,
		caps:      Capabilities{JSONMode: true},
		chatFunc: func(_ context.Context, _ llmtypes.ChatRequest) (*llmtypes.ChatResponse, error) {
			return nil, fmt.Errorf("provider failed")
		},
	}
}

func TestTriageEngine_TriageConfirmed(t *testing.T) {
	mock := newTriageMockProvider("confirmed")
	providers := map[string]Provider{"mock": mock}
	cfg := config.LLMConfig{
		DefaultProvider: "mock",
		Tasks: map[string]config.Task{
			"triage": {Provider: "mock", Model: "mock-model"},
		},
	}

	router := NewRouter(providers, cfg, triageTestLogger())
	dir := t.TempDir()
	cache := NewCacheInDir(dir, time.Hour)
	cost := NewCostAccumulator(triageTestLogger())
	engine := NewTriageEngine(router, cache, cost, DefaultTriageConfig(), triageTestLogger())

	findings := []models.Finding{
		{
			ID:             "f1",
			NeedsLLMTriage: true,
			Category:       models.CategorySecret,
			Severity:       models.SeverityCritical,
			Location:       models.Location{File: "a.java", Line: 10},
		},
		{
			ID:             "f2",
			NeedsLLMTriage: false,
			Category:       models.CategoryCodePattern,
			Severity:       models.SeverityInfo,
		},
	}

	processed, err := engine.Triage(context.Background(), findings, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	assert.Equal(t, models.VerdictConfirmed, findings[0].LLMVerdict)
	assert.Equal(t, "mock-triage", findings[0].LLMProvider)
	assert.Equal(t, "mock-model", findings[0].LLMModel)
	assert.Equal(t, 0.9, findings[0].LLMConfidence)
	assert.Equal(t, "test explanation", findings[0].LLMExplanation)
	assert.Equal(t, "test remediation", findings[0].LLMRemediation)
	assert.NotEmpty(t, findings[0].LLMRawResponse)
	// Second finding should not be triaged.
	assert.Empty(t, findings[1].LLMVerdict)
}

func TestTriageEngine_TriageLikelyFP(t *testing.T) {
	mock := newTriageMockProvider("likely_fp")
	providers := map[string]Provider{"mock": mock}
	cfg := config.LLMConfig{
		DefaultProvider: "mock",
		Tasks:           map[string]config.Task{"triage": {Provider: "mock", Model: "m"}},
	}

	router := NewRouter(providers, cfg, triageTestLogger())
	cache := NewCacheInDir(t.TempDir(), time.Hour)
	cost := NewCostAccumulator(triageTestLogger())
	engine := NewTriageEngine(router, cache, cost, DefaultTriageConfig(), triageTestLogger())

	findings := []models.Finding{
		{ID: "f1", NeedsLLMTriage: true, Category: models.CategoryCodePattern, Severity: models.SeverityLow},
	}

	_, err := engine.Triage(context.Background(), findings, nil)
	require.NoError(t, err)
	assert.Equal(t, models.VerdictLikelyFP, findings[0].LLMVerdict)
}

func TestTriageEngine_TriageInconclusiveOnError(t *testing.T) {
	mock := newFailingMockProvider()
	providers := map[string]Provider{"mock": mock}
	cfg := config.LLMConfig{
		DefaultProvider: "mock",
		Tasks:           map[string]config.Task{"triage": {Provider: "mock", Model: "m"}},
	}

	router := NewRouter(providers, cfg, triageTestLogger())
	cache := NewCacheInDir(t.TempDir(), time.Hour)
	cost := NewCostAccumulator(triageTestLogger())
	engine := NewTriageEngine(router, cache, cost, DefaultTriageConfig(), triageTestLogger())

	findings := []models.Finding{
		{ID: "f1", NeedsLLMTriage: true, Category: models.CategorySecret, Severity: models.SeverityCritical},
	}

	_, err := engine.Triage(context.Background(), findings, nil)
	require.NoError(t, err) // Error is absorbed, not returned.
	assert.Equal(t, models.VerdictInconclusive, findings[0].LLMVerdict)
	assert.Contains(t, findings[0].LLMExplanation, "triage error")
}

func TestTriageEngine_TriageWithCodeContext(t *testing.T) {
	mock := newTriageMockProvider("confirmed")
	providers := map[string]Provider{"mock": mock}
	cfg := config.LLMConfig{
		DefaultProvider: "mock",
		Tasks:           map[string]config.Task{"triage": {Provider: "mock", Model: "m"}},
	}

	router := NewRouter(providers, cfg, triageTestLogger())
	cache := NewCacheInDir(t.TempDir(), time.Hour)
	cost := NewCostAccumulator(triageTestLogger())
	engine := NewTriageEngine(router, cache, cost, DefaultTriageConfig(), triageTestLogger())

	findings := []models.Finding{
		{
			ID: "f1", NeedsLLMTriage: true, Category: models.CategorySecret, Severity: models.SeverityCritical,
			Location: models.Location{File: "a.java", Line: 10},
		},
	}

	codeCtx := map[string]string{
		"a.java": "public class A {\n    String key = \"AKIA...\";\n}",
	}

	_, err := engine.Triage(context.Background(), findings, codeCtx)
	require.NoError(t, err)
	assert.Equal(t, models.VerdictConfirmed, findings[0].LLMVerdict)
}

func TestTriageEngine_CacheHit(t *testing.T) {
	mock := newTriageMockProvider("confirmed")
	providers := map[string]Provider{"mock": mock}
	cfg := config.LLMConfig{
		DefaultProvider: "mock",
		Tasks:           map[string]config.Task{"triage": {Provider: "mock", Model: "m"}},
	}

	router := NewRouter(providers, cfg, triageTestLogger())
	dir := t.TempDir()
	cache := NewCacheInDir(dir, time.Hour)
	cost := NewCostAccumulator(triageTestLogger())
	engine := NewTriageEngine(router, cache, cost, DefaultTriageConfig(), triageTestLogger())

	findings := []models.Finding{
		{ID: "f1", NeedsLLMTriage: true, Category: models.CategorySecret, Severity: models.SeverityCritical},
	}

	// First run - cache miss.
	_, err := engine.Triage(context.Background(), findings, nil)
	require.NoError(t, err)
	assert.Equal(t, models.VerdictConfirmed, findings[0].LLMVerdict)

	// Second run with same findings - should hit cache.
	findings2 := []models.Finding{
		{ID: "f1", NeedsLLMTriage: true, Category: models.CategorySecret, Severity: models.SeverityCritical},
	}
	cost2 := NewCostAccumulator(triageTestLogger())
	engine2 := NewTriageEngine(router, cache, cost2, DefaultTriageConfig(), triageTestLogger())
	_, err = engine2.Triage(context.Background(), findings2, nil)
	require.NoError(t, err)
	assert.Equal(t, models.VerdictConfirmed, findings2[0].LLMVerdict)
	// Cost should be 0 because cache hit.
	assert.Equal(t, 0.0, cost2.Total())
}

func TestTriageEngine_CostAccumulation(t *testing.T) {
	mock := newTriageMockProvider("confirmed")
	providers := map[string]Provider{"mock": mock}
	cfg := config.LLMConfig{
		DefaultProvider: "mock",
		Tasks:           map[string]config.Task{"triage": {Provider: "mock", Model: "gpt-4o"}},
	}

	router := NewRouter(providers, cfg, triageTestLogger())
	cache := NewCacheInDir(t.TempDir(), time.Hour)
	cost := NewCostAccumulator(triageTestLogger())
	engine := NewTriageEngine(router, cache, cost, DefaultTriageConfig(), triageTestLogger())

	findings := []models.Finding{
		{ID: "f1", NeedsLLMTriage: true},
		{ID: "f2", NeedsLLMTriage: true},
	}

	_, err := engine.Triage(context.Background(), findings, nil)
	require.NoError(t, err)
	// gpt-4o: 100/1000 * 0.0025 + 50/1000 * 0.01 = 0.00025 + 0.0005 = 0.00075 per call
	assert.Greater(t, cost.Total(), 0.0)
	assert.Len(t, cost.Entries(), 2)
}

func TestTriageEngine_SecretRouting(t *testing.T) {
	// Test that findings with secrets route to local providers only.
	localMock := &MockProvider{
		name: "local", isLocal: true, available: true,
		caps: Capabilities{JSONMode: true},
		chatFunc: func(_ context.Context, _ llmtypes.ChatRequest) (*llmtypes.ChatResponse, error) {
			resp := TriageResponse{Verdict: "confirmed", Confidence: 0.9}
			raw, _ := json.Marshal(resp)
			return &llmtypes.ChatResponse{Content: string(raw), Provider: "local", Usage: llmtypes.Usage{PromptTokens: 10, CompletionTokens: 5}}, nil
		},
	}
	cloudMock := &MockProvider{
		name: "cloud", isLocal: false, available: true,
		caps: Capabilities{JSONMode: true},
	}

	providers := map[string]Provider{"local": localMock, "cloud": cloudMock}
	cfg := config.LLMConfig{
		DefaultProvider:   "local",
		AllowCloud:        true,
		AllowCloudSecrets: false,
		Tasks:             map[string]config.Task{"triage": {Provider: "local", Model: "m"}},
	}

	router := NewRouter(providers, cfg, triageTestLogger())
	cache := NewCacheInDir(t.TempDir(), time.Hour)
	cost := NewCostAccumulator(triageTestLogger())
	engine := NewTriageEngine(router, cache, cost, DefaultTriageConfig(), triageTestLogger())

	findings := []models.Finding{
		{ID: "f1", NeedsLLMTriage: true, Category: models.CategorySecret, Severity: models.SeverityCritical},
	}

	_, err := engine.Triage(context.Background(), findings, nil)
	require.NoError(t, err)
	assert.Equal(t, "local", findings[0].LLMProvider)
}

func TestTriageEngine_CancelledContext(t *testing.T) {
	mock := newTriageMockProvider("confirmed")
	providers := map[string]Provider{"mock": mock}
	cfg := config.LLMConfig{
		DefaultProvider: "mock",
		Tasks:           map[string]config.Task{"triage": {Provider: "mock", Model: "m"}},
	}

	router := NewRouter(providers, cfg, triageTestLogger())
	cache := NewCacheInDir(t.TempDir(), time.Hour)
	cost := NewCostAccumulator(triageTestLogger())
	engine := NewTriageEngine(router, cache, cost, DefaultTriageConfig(), triageTestLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings := []models.Finding{
		{ID: "f1", NeedsLLMTriage: true},
		{ID: "f2", NeedsLLMTriage: true},
	}

	_, err := engine.Triage(ctx, findings, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cancelled")
}
