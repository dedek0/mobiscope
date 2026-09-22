// Package gemini implements the LLM provider interface for Google Gemini.
//
// It communicates with the Gemini GenerateContent API using standard net/http.
package gemini

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
	defaultBaseURL = "https://generativelanguage.googleapis.com/v1beta"
	defaultTimeout = 60 * time.Second
)

// Provider implements [llmtypes.Provider] for Google Gemini.
type Provider struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	logger     *slog.Logger
}

// New creates a Gemini provider. If baseURL is empty, the official API is used.
func New(apiKey string, logger *slog.Logger) *Provider {
	return &Provider{
		baseURL:    defaultBaseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: defaultTimeout},
		logger:     logger,
	}
}

// NewWithHTTPClient creates a Gemini provider with a custom http.Client.
func NewWithHTTPClient(baseURL, apiKey string, client *http.Client, logger *slog.Logger) *Provider {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Provider{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		httpClient: client,
		logger:     logger,
	}
}

func (p *Provider) Name() string                { return "gemini" }
func (p *Provider) Kind() llmtypes.ProviderKind { return llmtypes.KindCloud }
func (p *Provider) IsLocal() bool               { return false }

func (p *Provider) Capabilities() llmtypes.Capabilities {
	return llmtypes.Capabilities{
		JSONMode:    true,
		Streaming:   true,
		ToolCalling: true,
		Vision:      true,
	}
}

// IsAvailable performs a lightweight health check.
func (p *Provider) IsAvailable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	httpReq, err := p.newRequest(ctx, http.MethodGet, p.baseURL+"/models", nil)
	if err != nil {
		return false
	}

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// newRequest builds a request with the API key in a header. The key is never
// placed in the URL query string where it would leak into proxy and error logs.
func (p *Provider) newRequest(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	httpReq, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("x-goog-api-key", p.apiKey)
	return httpReq, nil
}

// Models lists available models via the ListModels API.
func (p *Provider) Models(ctx context.Context) ([]llmtypes.ModelInfo, error) {
	httpReq, err := p.newRequest(ctx, http.MethodGet, p.baseURL+"/models", nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("listing models: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, p.mapError(resp)
	}

	var listResp struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	models := make([]llmtypes.ModelInfo, len(listResp.Models))
	for i, m := range listResp.Models {
		name := strings.TrimPrefix(m.Name, "models/")
		models[i] = llmtypes.ModelInfo{Name: name}
	}
	return models, nil
}

// Chat sends a non-streaming GenerateContent request.
func (p *Provider) Chat(ctx context.Context, req llmtypes.ChatRequest) (*llmtypes.ChatResponse, error) {
	apiReq := p.buildRequest(req)
	url := p.generateURL(req.Model, false)

	data, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := p.newRequest(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, p.mapError(resp)
	}

	var apiResp generateResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	if len(apiResp.Candidates) == 0 || len(apiResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("gemini returned empty candidates")
	}

	content := ""
	for _, part := range apiResp.Candidates[0].Content.Parts {
		content += part.Text
	}

	usage := llmtypes.Usage{
		PromptTokens:     apiResp.UsageMetadata.PromptTokenCount,
		CompletionTokens: apiResp.UsageMetadata.CandidatesTokenCount,
		TotalTokens:      apiResp.UsageMetadata.TotalTokenCount,
	}

	return &llmtypes.ChatResponse{
		Content:      content,
		Model:        req.Model,
		Provider:     "gemini",
		FinishReason: apiResp.Candidates[0].FinishReason,
		Usage:        usage,
	}, nil
}

// ChatStream sends a streaming GenerateContent request.
func (p *Provider) ChatStream(ctx context.Context, req llmtypes.ChatRequest) (io.ReadCloser, error) {
	apiReq := p.buildRequest(req)
	url := p.generateURL(req.Model, true)

	data, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := p.newRequest(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("gemini stream failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, p.mapError(resp)
	}

	return &geminiStreamReader{body: resp.Body}, nil
}

// --- Gemini API types ---

type generateRequest struct {
	Contents          []content   `json:"contents"`
	GenerationConfig  *genConfig  `json:"generationConfig,omitempty"`
	SystemInstruction *systemInst `json:"systemInstruction,omitempty"`
}

type content struct {
	Role  string `json:"role,omitempty"`
	Parts []part `json:"parts"`
}

type part struct {
	Text string `json:"text"`
}

type genConfig struct {
	Temperature      float64 `json:"temperature,omitempty"`
	MaxOutputTokens  int     `json:"maxOutputTokens,omitempty"`
	ResponseMimeType string  `json:"responseMimeType,omitempty"`
}

type systemInst struct {
	Parts []part `json:"parts"`
}

type generateResponse struct {
	Candidates    []candidate `json:"candidates"`
	UsageMetadata usageMeta   `json:"usageMetadata"`
}

type candidate struct {
	Content      content `json:"content"`
	FinishReason string  `json:"finishReason"`
}

type usageMeta struct {
	PromptTokenCount     int `json:"promptTokenCount"`
	CandidatesTokenCount int `json:"candidatesTokenCount"`
	TotalTokenCount      int `json:"totalTokenCount"`
}

type apiError struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
	} `json:"error"`
}

// --- streaming ---

type geminiStreamReader struct {
	body    io.ReadCloser
	scanner *bufio.Scanner
	buf     []byte
	done    bool
}

func (sr *geminiStreamReader) Read(p []byte) (int, error) {
	if len(sr.buf) > 0 {
		n := copy(p, sr.buf)
		sr.buf = sr.buf[n:]
		return n, nil
	}

	if sr.done {
		return 0, io.EOF
	}

	if sr.scanner == nil {
		sr.scanner = bufio.NewScanner(sr.body)
	}

	for sr.scanner.Scan() {
		line := sr.scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		data := strings.TrimPrefix(line, "data: ")

		var apiResp generateResponse
		if err := json.Unmarshal([]byte(data), &apiResp); err != nil {
			continue
		}

		if len(apiResp.Candidates) == 0 || len(apiResp.Candidates[0].Content.Parts) == 0 {
			continue
		}

		chunk := llmtypes.StreamChunk{
			Content: apiResp.Candidates[0].Content.Parts[0].Text,
		}

		if apiResp.Candidates[0].FinishReason != "" {
			chunk.Done = true
			chunk.FinishReason = apiResp.Candidates[0].FinishReason
		}

		out, err := json.Marshal(chunk)
		if err != nil {
			continue
		}
		out = append(out, '\n')

		n := copy(p, out)
		if n < len(out) {
			sr.buf = out[n:]
		}
		return n, nil
	}

	sr.done = true
	return 0, io.EOF
}

func (sr *geminiStreamReader) Close() error {
	return sr.body.Close()
}

// --- helpers ---

func (p *Provider) buildRequest(req llmtypes.ChatRequest) generateRequest {
	var systemMsg string
	var contents []content

	for _, m := range req.Messages {
		if m.Role == "system" {
			systemMsg = m.Content
		} else {
			role := "user"
			if m.Role == "assistant" {
				role = "model"
			}
			contents = append(contents, content{
				Role:  role,
				Parts: []part{{Text: m.Content}},
			})
		}
	}

	apiReq := generateRequest{Contents: contents}

	if systemMsg != "" {
		apiReq.SystemInstruction = &systemInst{
			Parts: []part{{Text: systemMsg}},
		}
	}

	genCfg := &genConfig{}
	if req.Temperature > 0 {
		genCfg.Temperature = req.Temperature
	}
	if req.MaxTokens > 0 {
		genCfg.MaxOutputTokens = req.MaxTokens
	}
	if req.JSONMode {
		genCfg.ResponseMimeType = "application/json"
	}
	apiReq.GenerationConfig = genCfg

	return apiReq
}

func (p *Provider) generateURL(model string, stream bool) string {
	action := "generateContent"
	if stream {
		action = "streamGenerateContent"
	}
	return fmt.Sprintf("%s/models/%s:%s", p.baseURL, model, action)
}

func (p *Provider) mapError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	var errResp apiError
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error.Message != "" {
		switch resp.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf("%w: %s", llmtypes.ErrAuthFailed, errResp.Error.Message)
		case http.StatusTooManyRequests:
			retryAfter := resp.Header.Get("Retry-After")
			return fmt.Errorf("%w (retry-after %s): %s", llmtypes.ErrRateLimited, retryAfter, errResp.Error.Message)
		case http.StatusNotFound:
			return fmt.Errorf("%w: %s", llmtypes.ErrModelNotFound, errResp.Error.Message)
		default:
			return fmt.Errorf("gemini API error (%d): %s", errResp.Error.Code, errResp.Error.Message)
		}
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w: status %d", llmtypes.ErrAuthFailed, resp.StatusCode)
	case http.StatusTooManyRequests:
		return fmt.Errorf("%w: status %d", llmtypes.ErrRateLimited, resp.StatusCode)
	default:
		return fmt.Errorf("gemini API error: status %d: %s", resp.StatusCode, string(body))
	}
}
