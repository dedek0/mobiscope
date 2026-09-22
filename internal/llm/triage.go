package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
	"github.com/dedek0/mobiscope/internal/models"
)

// TriageConfig holds configuration for the triage engine.
type TriageConfig struct {
	// MaxContextChars limits the code context sent to the LLM.
	MaxContextChars int
	// ContextLines is the number of lines before/after the finding line.
	ContextLines int
}

// DefaultTriageConfig returns sensible defaults.
func DefaultTriageConfig() TriageConfig {
	return TriageConfig{
		MaxContextChars: 4000,
		ContextLines:    10,
	}
}

// TriageEngine performs LLM-based triage on findings.
type TriageEngine struct {
	router  *Router
	cache   *Cache
	cost    *CostAccumulator
	cfg     TriageConfig
	retry   RetryConfig
	timeout time.Duration
	logger  *slog.Logger
}

// NewTriageEngine creates a TriageEngine with default retry and timeout settings.
func NewTriageEngine(router *Router, cache *Cache, cost *CostAccumulator, cfg TriageConfig, logger *slog.Logger) *TriageEngine {
	return NewTriageEngineWithRetry(router, cache, cost, cfg, DefaultRetryConfig(), 60*time.Second, logger)
}

// NewTriageEngineWithRetry creates a TriageEngine with explicit retry/timeout settings.
func NewTriageEngineWithRetry(router *Router, cache *Cache, cost *CostAccumulator, cfg TriageConfig, retry RetryConfig, timeout time.Duration, logger *slog.Logger) *TriageEngine {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &TriageEngine{
		router:  router,
		cache:   cache,
		cost:    cost,
		cfg:     cfg,
		retry:   retry,
		timeout: timeout,
		logger:  logger,
	}
}

// TriageResponse is the structured output from the LLM triage.
type TriageResponse struct {
	Verdict     string  `json:"verdict"`
	Confidence  float64 `json:"confidence"`
	Explanation string  `json:"explanation"`
	Remediation string  `json:"remediation"`
}

// extractJSONRe matches a fenced ```json block.
var extractJSONRe = regexp.MustCompile("(?s)```(?:json)?\\s*\\n?(\\{.*?\\})\\s*```")

// extractJSONLooseRe matches a raw JSON object containing a verdict key.
var extractJSONLooseRe = regexp.MustCompile(`(?s)\{[^{}]*"verdict"[^{}]*\}`)

// Triage processes a batch of findings, enriching each with LLM verdicts.
// Only findings with NeedsLLMTriage=true are processed.
//
// Per-finding failures mark the finding inconclusive but do not abort the
// batch. Policy violations (cloud blocked, provider unavailable) are
// accumulated and returned so callers can map them to exit code 4.
func (te *TriageEngine) Triage(ctx context.Context, findings []models.Finding, codeContext map[string]string) (int, error) {
	processed := 0
	var policyErr error

	for i := range findings {
		if !findings[i].NeedsLLMTriage {
			continue
		}

		if err := ctx.Err(); err != nil {
			return processed, fmt.Errorf("triage cancelled: %w", err)
		}

		containsSecret := findings[i].Category == models.CategorySecret
		route, err := te.router.Route(ctx, llmtypes.TaskTriage, containsSecret)
		if err != nil {
			te.logger.Error("routing failed for finding", "id", findings[i].ID, "error", err)
			if errors.Is(err, ErrCloudNotAllowed) || errors.Is(err, ErrProviderUnavailable) {
				if policyErr == nil {
					policyErr = err
				}
			}
			findings[i].LLMVerdict = models.VerdictInconclusive
			findings[i].LLMExplanation = fmt.Sprintf("routing failed: %s", err)
			continue
		}

		if err := te.triageOne(ctx, &findings[i], route, codeContext); err != nil {
			te.logger.Error("triage failed for finding", "id", findings[i].ID, "error", err)
			if errors.Is(err, ErrCloudNotAllowed) || errors.Is(err, ErrProviderUnavailable) {
				if policyErr == nil {
					policyErr = err
				}
			}
			findings[i].LLMVerdict = models.VerdictInconclusive
			findings[i].LLMExplanation = fmt.Sprintf("triage error: %s", err)
		}
		processed++
	}

	if processed > 0 && te.cost != nil {
		te.logger.Info("triage batch complete",
			"processed", processed,
			"total_cost_usd", fmt.Sprintf("%.6f", te.cost.Total()),
		)
	}

	return processed, policyErr
}

func (te *TriageEngine) triageOne(ctx context.Context, f *models.Finding, route *RouteResult, codeContext map[string]string) error {
	code := codeContext[f.Location.File]
	if code == "" {
		code = f.Location.Snippet
	}

	truncated, wasTruncated := TruncateContext(code, te.cfg.MaxContextChars)
	if wasTruncated {
		te.logger.Warn("code context truncated", "file", f.Location.File, "max_chars", te.cfg.MaxContextChars)
	}

	promptCtx := TriageContext{
		ID:          f.ID,
		Category:    string(f.Category),
		Title:       f.Title,
		Severity:    string(f.Severity),
		SourceTool:  f.SourceTool,
		File:        f.Location.File,
		Line:        f.Location.Line,
		Evidence:    f.Evidence,
		CodeContext: truncated,
	}

	caps := route.Provider.Capabilities()
	jsonMode := caps.JSONMode

	prompt, err := RenderTriagePrompt(promptCtx, jsonMode)
	if err != nil {
		return fmt.Errorf("rendering prompt: %w", err)
	}

	// Check cache.
	cacheKey := CacheKey(route.Provider.Name(), route.Model, prompt, 0)
	if te.cache != nil {
		if cached := te.cache.Get(cacheKey); cached != nil {
			te.logger.Debug("cache hit", "finding", f.ID)
			return te.applyResponse(f, route, *cached, llmtypes.Usage{})
		}
	}

	// Call LLM with retry + per-call timeout.
	req := llmtypes.ChatRequest{
		Model: route.Model,
		Messages: []llmtypes.Message{
			{Role: "user", Content: prompt},
		},
		JSONMode: jsonMode,
	}

	var resp *llmtypes.ChatResponse
	callCtx, cancel := context.WithTimeout(ctx, te.timeout)
	err = withRetry(callCtx, te.retry, te.logger, "triage", func() error {
		var callErr error
		resp, callErr = route.Provider.Chat(callCtx, req)
		return callErr
	})
	cancel()
	if err != nil {
		return fmt.Errorf("chat failed: %w", err)
	}
	if te.cost != nil {
		te.cost.Add(route.Provider.Name(), route.Model, resp.Usage)
	}

	raw := json.RawMessage([]byte(resp.Content))

	// Cache the raw JSON response.
	if te.cache != nil {
		if err := te.cache.Set(cacheKey, raw); err != nil {
			te.logger.Warn("cache write failed", "error", err)
		}
	}

	return te.applyResponse(f, route, raw, resp.Usage)
}

func (te *TriageEngine) applyResponse(f *models.Finding, route *RouteResult, raw json.RawMessage, usage llmtypes.Usage) error {
	var triageResp TriageResponse
	if err := json.Unmarshal(raw, &triageResp); err != nil {
		// Tolerant parse: try to extract JSON from text.
		triageResp, err = extractJSONFromText(string(raw))
		if err != nil {
			te.logger.Warn("failed to parse triage response, marking inconclusive",
				"finding", f.ID, "raw", string(raw)[:minInt(len(string(raw)), 200)])
			f.LLMVerdict = models.VerdictInconclusive
			f.LLMExplanation = "failed to parse LLM response"
			f.LLMRawResponse = string(raw)
			f.LLMProvider = route.Provider.Name()
			f.LLMModel = route.Model
			return nil
		}
	}

	f.LLMProvider = route.Provider.Name()
	f.LLMModel = route.Model
	f.LLMRawResponse = string(raw)

	switch triageResp.Verdict {
	case "confirmed":
		f.LLMVerdict = models.VerdictConfirmed
	case "likely_fp":
		f.LLMVerdict = models.VerdictLikelyFP
	default:
		f.LLMVerdict = models.VerdictInconclusive
	}

	f.LLMConfidence = triageResp.Confidence
	f.LLMExplanation = triageResp.Explanation
	f.LLMRemediation = triageResp.Remediation

	f.LLMCostUSD = EstimateCost(route.Model, usage)

	return nil
}

// extractJSONFromText tries to find and parse a JSON object in text.
func extractJSONFromText(text string) (TriageResponse, error) {
	if matches := extractJSONRe.FindStringSubmatch(text); len(matches) > 1 {
		var resp TriageResponse
		if err := json.Unmarshal([]byte(matches[1]), &resp); err == nil {
			return resp, nil
		}
	}

	if match := extractJSONLooseRe.FindString(text); match != "" {
		var resp TriageResponse
		if err := json.Unmarshal([]byte(match), &resp); err == nil {
			return resp, nil
		}
	}

	return TriageResponse{}, fmt.Errorf("no valid JSON found in response")
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ExtractCodeContext extracts a window of lines around the finding location.
// Returns an empty string when line is out of range (never the entire source).
func ExtractCodeContext(source string, line, contextLines int) string {
	lines := strings.Split(source, "\n")
	if line <= 0 || line > len(lines) {
		return ""
	}

	start := line - contextLines - 1
	if start < 0 {
		start = 0
	}
	end := line + contextLines
	if end > len(lines) {
		end = len(lines)
	}

	return strings.Join(lines[start:end], "\n")
}
