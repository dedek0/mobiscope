// Package ollama implements the LLM provider interface for Ollama.
//
// It communicates with the Ollama REST API (default http://localhost:11434)
// using standard net/http. No external SDK dependency is required.
package ollama

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
)

const (
	defaultBaseURL = "http://localhost:11434"
	healthPath     = "/"
	tagsPath       = "/api/tags"
	chatPath       = "/api/chat"
	pullPath       = "/api/pull"
	defaultTimeout = 30 * time.Second
)

// Provider implements [llmtypes.Provider] for Ollama.
type Provider struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

// New creates an Ollama provider pointing at baseURL.
func New(baseURL string, logger *slog.Logger) *Provider {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Provider{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: defaultTimeout},
		logger:     logger,
	}
}

// NewWithHTTPClient creates an Ollama provider with a custom http.Client (for tests).
func NewWithHTTPClient(baseURL string, client *http.Client, logger *slog.Logger) *Provider {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Provider{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: client,
		logger:     logger,
	}
}

func (p *Provider) Name() string                { return "ollama" }
func (p *Provider) Kind() llmtypes.ProviderKind { return llmtypes.KindLocal }
func (p *Provider) IsLocal() bool               { return true }
func (p *Provider) Capabilities() llmtypes.Capabilities {
	return llmtypes.Capabilities{
		JSONMode:    true,
		Streaming:   true,
		ToolCalling: true,
	}
}

// IsAvailable checks if the Ollama server is reachable.
func (p *Provider) IsAvailable(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+healthPath, nil)
	if err != nil {
		return false
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// ModelInfo represents a model from Ollama's /api/tags.
type ollamaModel struct {
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	ModifiedAt string `json:"modified_at"`
}

type tagsResponse struct {
	Models []ollamaModel `json:"models"`
}

// Models lists installed models.
func (p *Provider) Models(ctx context.Context) ([]llmtypes.ModelInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+tagsPath, nil)
	if err != nil {
		return nil, fmt.Errorf("creating tags request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing models: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tags returned status %d", resp.StatusCode)
	}

	var tags tagsResponse
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return nil, fmt.Errorf("decoding tags: %w", err)
	}

	models := make([]llmtypes.ModelInfo, len(tags.Models))
	for i, m := range tags.Models {
		models[i] = llmtypes.ModelInfo{
			Name:     m.Name,
			Size:     m.Size,
			Modified: m.ModifiedAt,
		}
	}
	return models, nil
}

// ollamaChatRequest is the JSON body for /api/chat.
type ollamaChatRequest struct {
	Model    string             `json:"model"`
	Messages []llmtypes.Message `json:"messages"`
	Stream   bool               `json:"stream"`
	Options  *ollamaOptions     `json:"options,omitempty"`
	Format   string             `json:"format,omitempty"`
}

type ollamaOptions struct {
	Temperature *float64 `json:"temperature,omitempty"`
	NumPredict  *int     `json:"num_predict,omitempty"`
}

// ollamaChatResponse is the JSON response from /api/chat (non-streaming).
type ollamaChatResponse struct {
	Model           string           `json:"model"`
	Message         llmtypes.Message `json:"message"`
	Done            bool             `json:"done"`
	TotalDuration   int64            `json:"total_duration"`
	PromptEvalCount int              `json:"prompt_eval_count"`
	EvalCount       int              `json:"eval_count"`
}

// Chat sends a non-streaming chat request.
func (p *Provider) Chat(ctx context.Context, req llmtypes.ChatRequest) (*llmtypes.ChatResponse, error) {
	body := ollamaChatRequest{
		Model:    req.Model,
		Messages: req.Messages,
		Stream:   false,
	}

	if req.Temperature > 0 || req.MaxTokens > 0 {
		opts := &ollamaOptions{}
		if req.Temperature > 0 {
			opts.Temperature = &req.Temperature
		}
		if req.MaxTokens > 0 {
			opts.NumPredict = &req.MaxTokens
		}
		body.Options = opts
	}

	if req.JSONMode {
		body.Format = "json"
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling chat request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+chatPath, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating chat request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("chat request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("chat returned status %d: %s", resp.StatusCode, string(errBody))
	}

	var ollamaResp ollamaChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return nil, fmt.Errorf("decoding chat response: %w", err)
	}

	return &llmtypes.ChatResponse{
		Content:  ollamaResp.Message.Content,
		Model:    ollamaResp.Model,
		Provider: "ollama",
		Usage: llmtypes.Usage{
			PromptTokens:     ollamaResp.PromptEvalCount,
			CompletionTokens: ollamaResp.EvalCount,
			TotalTokens:      ollamaResp.PromptEvalCount + ollamaResp.EvalCount,
		},
	}, nil
}

// ChatStream sends a streaming chat request. Caller must close the returned ReadCloser.
func (p *Provider) ChatStream(ctx context.Context, req llmtypes.ChatRequest) (io.ReadCloser, error) {
	body := ollamaChatRequest{
		Model:    req.Model,
		Messages: req.Messages,
		Stream:   true,
	}

	if req.Temperature > 0 {
		body.Options = &ollamaOptions{Temperature: &req.Temperature}
	}
	if req.JSONMode {
		body.Format = "json"
	}

	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling stream request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+chatPath, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating stream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("stream request failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("stream returned status %d: %s", resp.StatusCode, string(errBody))
	}

	return resp.Body, nil
}

// ReadStreamChunks reads newline-delimited JSON StreamChunks from a reader.
func ReadStreamChunks(r io.Reader) ([]llmtypes.StreamChunk, error) {
	var chunks []llmtypes.StreamChunk
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var chunk llmtypes.StreamChunk
		if err := json.Unmarshal(line, &chunk); err != nil {
			return chunks, fmt.Errorf("decoding stream chunk: %w", err)
		}
		chunks = append(chunks, chunk)
	}
	return chunks, scanner.Err()
}

// PullRequest is the JSON body for /api/pull.
type pullRequest struct {
	Name string `json:"name"`
}

// Pull downloads a model. It blocks until the pull completes.
func (p *Provider) Pull(ctx context.Context, model string) error {
	body := pullRequest{Name: model}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling pull request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+pullPath, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("creating pull request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("pull request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pull returned status %d: %s", resp.StatusCode, string(errBody))
	}

	// Ollama streams progress; drain it until done.
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var status struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(line, &status); err == nil {
			p.logger.Debug("pull progress", "model", model, "status", status.Status)
		}
	}
	return scanner.Err()
}
