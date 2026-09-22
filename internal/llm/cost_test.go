package llm

import (
	"log/slog"
	"os"
	"testing"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
	"github.com/stretchr/testify/assert"
)

func testCostLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestEstimateCost_KnownModel(t *testing.T) {
	usage := llmtypes.Usage{PromptTokens: 1000, CompletionTokens: 500}
	cost := EstimateCost("gpt-4o", usage)
	// 1000/1000 * 0.0025 + 500/1000 * 0.01 = 0.0025 + 0.005 = 0.0075
	assert.InDelta(t, 0.0075, cost, 0.0001)
}

func TestEstimateCost_LocalModel(t *testing.T) {
	usage := llmtypes.Usage{PromptTokens: 1000, CompletionTokens: 500}
	cost := EstimateCost("qwen2.5-coder:7b", usage)
	assert.Equal(t, 0.0, cost)
}

func TestEstimateCost_UnknownModel(t *testing.T) {
	usage := llmtypes.Usage{PromptTokens: 1000, CompletionTokens: 500}
	cost := EstimateCost("unknown-model", usage)
	assert.Equal(t, 0.0, cost)
}

func TestEstimateCost_AnthropicModel(t *testing.T) {
	usage := llmtypes.Usage{PromptTokens: 2000, CompletionTokens: 1000}
	cost := EstimateCost("claude-sonnet-4-20250514", usage)
	// 2000/1000 * 0.003 + 1000/1000 * 0.015 = 0.006 + 0.015 = 0.021
	assert.InDelta(t, 0.021, cost, 0.0001)
}

func TestCostAccumulator_Add(t *testing.T) {
	ca := NewCostAccumulator(testCostLogger())

	cost := ca.Add("openai", "gpt-4o", llmtypes.Usage{PromptTokens: 1000, CompletionTokens: 500})
	assert.InDelta(t, 0.0075, cost, 0.0001)
	assert.InDelta(t, 0.0075, ca.Total(), 0.0001)
}

func TestCostAccumulator_Multiple(t *testing.T) {
	ca := NewCostAccumulator(testCostLogger())

	ca.Add("openai", "gpt-4o", llmtypes.Usage{PromptTokens: 1000, CompletionTokens: 500})
	ca.Add("openai", "gpt-4o", llmtypes.Usage{PromptTokens: 1000, CompletionTokens: 500})

	assert.InDelta(t, 0.015, ca.Total(), 0.001)
	assert.Len(t, ca.Entries(), 2)
}

func TestCostAccumulator_LocalModel(t *testing.T) {
	ca := NewCostAccumulator(testCostLogger())

	cost := ca.Add("ollama", "qwen2.5-coder:7b", llmtypes.Usage{PromptTokens: 1000, CompletionTokens: 500})
	assert.Equal(t, 0.0, cost)
	assert.Equal(t, 0.0, ca.Total())
}

func TestCostAccumulator_Entries(t *testing.T) {
	ca := NewCostAccumulator(testCostLogger())

	ca.Add("openai", "gpt-4o", llmtypes.Usage{PromptTokens: 100, CompletionTokens: 50})
	entries := ca.Entries()
	assert.Len(t, entries, 1)
	assert.Equal(t, "openai", entries[0].Provider)
	assert.Equal(t, "gpt-4o", entries[0].Model)
	assert.Equal(t, 100, entries[0].Input)
	assert.Equal(t, 50, entries[0].Output)
}

func TestPriceTable_ContainsExpectedModels(t *testing.T) {
	expected := []string{"gpt-4o", "gpt-4o-mini", "claude-sonnet-4-20250514", "gemini-2.0-flash", "qwen2.5-coder:7b"}
	for _, m := range expected {
		_, ok := PriceTable[m]
		assert.True(t, ok, "PriceTable should contain %s", m)
	}
}
