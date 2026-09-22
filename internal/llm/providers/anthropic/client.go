// Package anthropic implements the LLM provider interface for Anthropic Claude.
//
// It communicates with the Anthropic Messages API using standard net/http.
// Prompt caching is enabled by default for repeated system prompts.
package anthropic

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
	defaultBaseURL = "https://api.anthropic.com"
	messagesPath   = "/v1/messages"
	apiVersion     = "2023-06-01"
	defaultTimeout = 60 * time.Second
)

// Provider implements [llmtypes.Provider] for Anthropic Claude.
type Provider struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	logger     *slog.Logger
}

// New creates an Anthropic provider. If baseURL is empty, the official API is used.
func New(baseURL, apiKey string, logger *slog.Logger) *Provider {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &Provider{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: defaultTimeout},
		logger:     logger,
	}
}

// NewWithHTTPClient creates an Anthropic provider with a custom http.Client.
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

func (p *Provider) Name() string                { return "anthropic" }
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

// IsAvailable performs a lightweight health check by sending a minimal request.
func (p *Provider) IsAvailable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req := messagesRequest{
		Model:     "claude-sonnet-4-20250514",
		MaxTokens: 1,
		Messages:  []message{{Role: "user", Content: "hi"}},
	}

	_, err := p.doChat(ctx, req)
	return err == nil
}

// Models returns the known Claude model list (Anthropic has no /v1/models endpoint).
func (p *Provider) Models(_ context.Context) ([]llmtypes.ModelInfo, error) {
	return []llmtypes.ModelInfo{
		{Name: "claude-sonnet-4-20250514"},
		{Name: "claude-haiku-4-20250514"},
		{Name: "claude-3-5-sonnet-20241022"},
		{Name: "claude-3-5-haiku-20241022"},
		{Name: "claude-3-opus-20240229"},
	}, nil
}

// Chat sends a non-streaming Messages API request.
func (p *Provider) Chat(ctx context.Context, req llmtypes.ChatRequest) (*llmtypes.ChatResponse, error) {
	apiReq := p.buildRequest(req, false)
	return p.doChat(ctx, apiReq)
}

// ChatStream sends a streaming Messages API request.
func (p *Provider) ChatStream(ctx context.Context, req llmtypes.ChatRequest) (io.ReadCloser, error) {
	apiReq := p.buildRequest(req, true)
	return p.doStream(ctx, apiReq)
}

// --- internal types ---

type messagesRequest struct {
	Model       string    `json:"model"`
	MaxTokens   int       `json:"max_tokens"`
	Messages    []message `json:"messages"`
	System      string    `json:"system,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
	Stream      bool      `json:"stream,omitempty"`
	Metadata    *metadata `json:"metadata,omitempty"`
}

type metadata struct {
	CacheControl string `json:"cache_control,omitempty"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type messagesResponse struct {
	ID         string  `json:"id"`
	Model      string  `json:"model"`
	Content    []block `json:"content"`
	StopReason string  `json:"stop_reason"`
	Usage      usage   `json:"usage"`
}

type block struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type usage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
}

type apiError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type errorResponse struct {
	Error apiError `json:"error"`
}

// --- streaming types ---

type streamEvent struct {
	Type  string          `json:"type"`
	Delta json.RawMessage `json:"delta,omitempty"`
	Usage *usage          `json:"usage,omitempty"`
}

type deltaContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type deltaStop struct {
	StopReason string `json:"stop_reason"`
}

// --- implementation ---

func (p *Provider) buildRequest(req llmtypes.ChatRequest, stream bool) messagesRequest {
	var systemMsg string
	var userMsgs []message

	for _, m := range req.Messages {
		if m.Role == "system" {
			systemMsg = m.Content
		} else {
			userMsgs = append(userMsgs, message{Role: m.Role, Content: m.Content})
		}
	}

	apiReq := messagesRequest{
		Model:     req.Model,
		MaxTokens: req.MaxTokens,
		Messages:  userMsgs,
		Stream:    stream,
	}

	if apiReq.MaxTokens == 0 {
		apiReq.MaxTokens = 4096
	}

	if systemMsg != "" {
		apiReq.System = systemMsg
	}

	if req.Temperature > 0 {
		apiReq.Temperature = req.Temperature
	}

	return apiReq
}

func (p *Provider) doChat(ctx context.Context, req messagesRequest) (*llmtypes.ChatResponse, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+messagesPath, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	p.setHeaders(httpReq)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, p.mapError(resp)
	}

	var apiResp messagesResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	content := ""
	for _, b := range apiResp.Content {
		if b.Type == "text" {
			content += b.Text
		}
	}

	return &llmtypes.ChatResponse{
		Content:      content,
		Model:        apiResp.Model,
		Provider:     "anthropic",
		FinishReason: apiResp.StopReason,
		Usage: llmtypes.Usage{
			PromptTokens:     apiResp.Usage.InputTokens,
			CompletionTokens: apiResp.Usage.OutputTokens,
			TotalTokens:      apiResp.Usage.InputTokens + apiResp.Usage.OutputTokens,
		},
	}, nil
}

func (p *Provider) doStream(ctx context.Context, req messagesRequest) (io.ReadCloser, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+messagesPath, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	p.setHeaders(httpReq)

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic stream failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, p.mapError(resp)
	}

	return &anthropicStreamReader{body: resp.Body}, nil
}

// anthropicStreamReader converts Anthropic SSE events to StreamChunk NDJSON.
type anthropicStreamReader struct {
	body    io.ReadCloser
	scanner *bufio.Scanner
	buf     []byte
	done    bool
	usage   *usage
}

func (sr *anthropicStreamReader) Read(p []byte) (int, error) {
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
		if data == "[DONE]" {
			sr.done = true
			return 0, io.EOF
		}

		var event streamEvent
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}

		if event.Usage != nil {
			sr.usage = event.Usage
		}

		chunk := llmtypes.StreamChunk{}

		switch event.Type {
		case "content_block_delta":
			var dc deltaContent
			if err := json.Unmarshal(event.Delta, &dc); err == nil {
				chunk.Content = dc.Text
			}
		case "message_delta":
			var ds deltaStop
			if err := json.Unmarshal(event.Delta, &ds); err == nil {
				chunk.Done = true
				chunk.FinishReason = ds.StopReason
			}
		default:
			continue
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

func (sr *anthropicStreamReader) Close() error {
	return sr.body.Close()
}

func (p *Provider) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", p.apiKey)
	req.Header.Set("anthropic-version", apiVersion)
	req.Header.Set("anthropic-beta", "prompt-caching-2024-07-31")
}

func (p *Provider) mapError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)

	var errResp errorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error.Message != "" {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf("%w: %s", llmtypes.ErrAuthFailed, errResp.Error.Message)
		case http.StatusTooManyRequests:
			retryAfter := resp.Header.Get("Retry-After")
			return fmt.Errorf("%w (retry-after %s): %s", llmtypes.ErrRateLimited, retryAfter, errResp.Error.Message)
		case http.StatusNotFound:
			return fmt.Errorf("%w: %s", llmtypes.ErrModelNotFound, errResp.Error.Message)
		default:
			return fmt.Errorf("anthropic API error (%d): %s", resp.StatusCode, errResp.Error.Message)
		}
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: status %d", llmtypes.ErrAuthFailed, resp.StatusCode)
	case http.StatusTooManyRequests:
		return fmt.Errorf("%w: status %d", llmtypes.ErrRateLimited, resp.StatusCode)
	default:
		return fmt.Errorf("anthropic API error: status %d: %s", resp.StatusCode, string(body))
	}
}
