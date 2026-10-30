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
	"github.com/dedek0/mobiscope/internal/metrics"
	"github.com/dedek0/mobiscope/internal/models"
)

// TriageConfig holds configuration for the triage engine.
type TriageConfig struct {
	// MaxContextChars limits the code context sent to the LLM.
	MaxContextChars int
	// ManifestContext is the session-level platform config excerpt
	// (AndroidManifest.xml or Info.plist/entitlements) shown to the model
	// so it can reason about app configuration, not just the finding line.
	ManifestContext string
}

// DefaultTriageConfig returns sensible defaults.
func DefaultTriageConfig() TriageConfig {
	return TriageConfig{
		MaxContextChars: 4000,
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
// The route is resolved once per batch instead of once per finding: the
// provider availability check is a real request for some providers, and
// calling it per finding turned a batch into N extra billable calls.
//
// Per-finding failures mark the finding inconclusive but do not abort the
// batch. Policy violations (cloud blocked, provider unavailable) are
// accumulated and returned so callers can map them to exit code 4.
func (te *TriageEngine) Triage(ctx context.Context, findings []models.Finding, codeContext map[string]string) (int, error) {
	processed := 0
	var policyErr error

	// At most two routes: one for findings without secrets and one for
	// findings that carry them, because the privacy policy differs. Each
	// is resolved lazily, so a batch without secrets never pays for the
	// secret route.
	var plainRoute, secretRoute *RouteResult
	var plainErr, secretErr error
	plainDone, secretDone := false, false

	routeFor := func(containsSecret bool) (*RouteResult, error) {
		if containsSecret {
			if !secretDone {
				secretDone = true
				secretRoute, secretErr = te.router.Route(ctx, llmtypes.TaskTriage, true)
			}
			return secretRoute, secretErr
		}
		if !plainDone {
			plainDone = true
			plainRoute, plainErr = te.router.Route(ctx, llmtypes.TaskTriage, false)
		}
		return plainRoute, plainErr
	}

	for i := range findings {
		if !findings[i].NeedsLLMTriage {
			continue
		}
		// Info-level findings are inventory/surface facts (pinning markers,
		// library detection, client-side identifiers). Sending them to the
		// LLM adds cost without a security decision.
		if findings[i].Severity == models.SeverityInfo {
			continue
		}

		if err := ctx.Err(); err != nil {
			return processed, fmt.Errorf("triage cancelled: %w", err)
		}

		containsSecret := findingCarriesSecret(findings[i])
		route, err := routeFor(containsSecret)
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

// findingCarriesSecret reports whether a finding must be kept away from a
// cloud provider. The category is not enough: an analyzer can mark a
// finding as sensitive without putting it in the secret category.
func findingCarriesSecret(f models.Finding) bool {
	return f.Category == models.CategorySecret || f.Sensitivity == models.SensitivitySecret
}

func (te *TriageEngine) triageOne(ctx context.Context, f *models.Finding, route *RouteResult, codeContext map[string]string) error {
	// The code context is looked up with the same key the pipeline used to
	// build it, and the excerpt is centred on the offending line so the
	// model actually sees the finding.
	code := codeContext[f.Location.File]
	if code == "" {
		code = f.Location.Snippet
	} else if excerpt := ExtractCodeContext(code, f.Location.Line, triageContextLines); excerpt != "" {
		code = excerpt
	}

	// Anything that looks like a credential is redacted before the
	// context leaves the machine: the excerpt can contain a second
	// secret that has nothing to do with the finding.
	code = RedactSecrets(code)

	truncated, wasTruncated := TruncateContext(code, te.cfg.MaxContextChars)
	if wasTruncated {
		te.logger.Warn("code context truncated", "file", f.Location.File, "max_chars", te.cfg.MaxContextChars)
	}

	promptCtx := TriageContext{
		ID:              f.ID,
		Category:        string(f.Category),
		Title:           f.Title,
		Severity:        string(f.Severity),
		SourceTool:      f.SourceTool,
		File:            f.Location.File,
		Line:            f.Location.Line,
		Evidence:        f.Evidence,
		CodeContext:     truncated,
		ManifestContext: te.cfg.ManifestContext,
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

	// Call LLM with retry + a per-attempt timeout.
	req := llmtypes.ChatRequest{
		Model: route.Model,
		Messages: []llmtypes.Message{
			{Role: "user", Content: prompt},
		},
		JSONMode: jsonMode,
	}

	var resp *llmtypes.ChatResponse
	// The deadline is applied per attempt, not to the whole retry
	// sequence: otherwise the first slow attempt consumes the entire
	// budget and the retries never happen.
	err = withRetry(ctx, te.retry, te.logger, "triage", func() error {
		attemptCtx, cancel := context.WithTimeout(ctx, te.timeout)
		defer cancel()
		var callErr error
		resp, callErr = route.Provider.Chat(attemptCtx, req)
		return callErr
	})
	if err != nil {
		metrics.RecordLLMCall(route.Provider.Name(), false, 0)
		return fmt.Errorf("chat failed: %w", err)
	}
	if te.cost != nil {
		te.cost.Add(route.Provider.Name(), route.Model, resp.Usage)
	}

	raw := json.RawMessage([]byte(resp.Content))

	// Cache the raw response. Providers without JSON mode answer with a
	// fenced block, so the payload is stored as text and parsed on read.
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
				"finding", f.ID, "raw", truncateForLog(string(raw)))
			f.LLMVerdict = models.VerdictInconclusive
			f.LLMExplanation = "failed to parse LLM response"
			f.LLMRawResponse = RedactSecrets(string(raw))
			f.LLMProvider = route.Provider.Name()
			f.LLMModel = route.Model
			return nil
		}
	}

	f.LLMProvider = route.Provider.Name()
	f.LLMModel = route.Model
	// The raw answer often echoes the evidence, and the evidence can hold
	// a credential. The stored copy is redacted.
	f.LLMRawResponse = RedactSecrets(string(raw))

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

// truncateForLog trims a value so it can be written to a log line.
func truncateForLog(s string) string {
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
