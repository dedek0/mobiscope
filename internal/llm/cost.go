package llm

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
)

// PriceEntry defines the cost per 1000 tokens for a model.
type PriceEntry struct {
	Per1KInput  float64 `json:"per_1k_input"`
	Per1KOutput float64 `json:"per_1k_output"`
}

// PriceTable maps model names to their pricing.
var PriceTable = map[string]PriceEntry{
	// OpenAI
	"gpt-4o":        {Per1KInput: 0.0025, Per1KOutput: 0.01},
	"gpt-4o-mini":   {Per1KInput: 0.00015, Per1KOutput: 0.0006},
	"gpt-4-turbo":   {Per1KInput: 0.01, Per1KOutput: 0.03},
	"gpt-3.5-turbo": {Per1KInput: 0.0005, Per1KOutput: 0.0015},
	// Anthropic
	"claude-sonnet-4-20250514":   {Per1KInput: 0.003, Per1KOutput: 0.015},
	"claude-3-5-sonnet-20241022": {Per1KInput: 0.003, Per1KOutput: 0.015},
	"claude-3-5-haiku-20241022":  {Per1KInput: 0.001, Per1KOutput: 0.005},
	"claude-3-opus-20240229":     {Per1KInput: 0.015, Per1KOutput: 0.075},
	// Google
	"gemini-2.0-flash": {Per1KInput: 0.0001, Per1KOutput: 0.0004},
	"gemini-1.5-pro":   {Per1KInput: 0.00125, Per1KOutput: 0.005},
	// Groq
	"llama-3.1-8b-instant": {Per1KInput: 0.00005, Per1KOutput: 0.00008},
	// Local models: $0
	"qwen2.5-coder:7b": {Per1KInput: 0, Per1KOutput: 0},
	"llama3.1:8b":      {Per1KInput: 0, Per1KOutput: 0},
}

// EstimateCost calculates the USD cost for a given usage and model.
func EstimateCost(model string, usage llmtypes.Usage) float64 {
	price, ok := PriceTable[model]
	if !ok {
		return 0
	}
	inputCost := float64(usage.PromptTokens) / 1000 * price.Per1KInput
	outputCost := float64(usage.CompletionTokens) / 1000 * price.Per1KOutput
	return inputCost + outputCost
}

// CostAccumulator tracks cumulative LLM costs across a session.
type CostAccumulator struct {
	mu      sync.Mutex
	total   float64
	entries []CostEntry
	logger  *slog.Logger
}

// CostEntry records a single LLM call's cost.
type CostEntry struct {
	Provider string  `json:"provider"`
	Model    string  `json:"model"`
	Input    int     `json:"input_tokens"`
	Output   int     `json:"output_tokens"`
	CostUSD  float64 `json:"cost_usd"`
}

// NewCostAccumulator creates a CostAccumulator.
func NewCostAccumulator(logger *slog.Logger) *CostAccumulator {
	return &CostAccumulator{logger: logger}
}

// Add records a cost entry.
func (ca *CostAccumulator) Add(provider, model string, usage llmtypes.Usage) float64 {
	cost := EstimateCost(model, usage)

	ca.mu.Lock()
	defer ca.mu.Unlock()

	ca.total += cost
	ca.entries = append(ca.entries, CostEntry{
		Provider: provider,
		Model:    model,
		Input:    usage.PromptTokens,
		Output:   usage.CompletionTokens,
		CostUSD:  cost,
	})

	if cost > 0 {
		ca.logger.Info("llm cost",
			"provider", provider,
			"model", model,
			"input_tokens", usage.PromptTokens,
			"output_tokens", usage.CompletionTokens,
			"cost_usd", fmt.Sprintf("%.6f", cost),
			"total_usd", fmt.Sprintf("%.6f", ca.total),
		)
	}

	return cost
}

// Total returns the accumulated cost in USD.
func (ca *CostAccumulator) Total() float64 {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.total
}

// Entries returns a copy of all cost entries.
func (ca *CostAccumulator) Entries() []CostEntry {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	out := make([]CostEntry, len(ca.entries))
	copy(out, ca.entries)
	return out
}
