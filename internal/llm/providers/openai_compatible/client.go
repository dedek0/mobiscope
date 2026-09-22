// Package openaicompatible implements the LLM provider interface for any
// API that follows the OpenAI chat completions specification.
//
// This single adapter covers: OpenAI, llama.cpp, LM Studio, vLLM, LocalAI,
// TGI, OpenRouter, Groq, Together, Azure OpenAI, Fireworks, DeepInfra,
// Perplexity, and any other compatible endpoint.
package openaicompatible

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	openai "github.com/sashabaranov/go-openai"

	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
)

// Provider implements [llmtypes.Provider] for OpenAI-compatible APIs.
type Provider struct {
	name       string
	baseURL    string
	apiKey     string
	kind       llmtypes.ProviderKind
	caps       llmtypes.Capabilities
	client     *openai.Client
	httpClient *http.Client
	logger     *slog.Logger
}

// Config holds all configuration for creating a Provider.
type Config struct {
	// Name is the provider identifier (e.g., "openai", "llamacpp").
	Name string
	// BaseURL is the API endpoint (e.g., "https://api.openai.com/v1").
	BaseURL string
	// APIKey is the authentication key (empty for local providers).
	APIKey string
	// Kind overrides auto-detection of local vs cloud.
	Kind llmtypes.ProviderKind
	// Capabilities overrides the default capabilities.
	Capabilities *llmtypes.Capabilities
	// HTTPClient allows injecting a custom http.Client (for tests).
	HTTPClient *http.Client
	// Logger for diagnostic output.
	Logger *slog.Logger
}

// New creates a Provider from a Config.
func New(cfg Config) *Provider {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:8080/v1"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	kind := cfg.Kind
	if kind == 0 && cfg.BaseURL != "" {
		kind = KindFromURL(cfg.BaseURL)
	}

	caps := llmtypes.Capabilities{
		JSONMode:    true,
		Streaming:   true,
		ToolCalling: true,
	}
	if cfg.Capabilities != nil {
		caps = *cfg.Capabilities
	}

	clientCfg := openai.DefaultConfig(cfg.APIKey)
	clientCfg.BaseURL = cfg.BaseURL
	if cfg.HTTPClient != nil {
		clientCfg.HTTPClient = cfg.HTTPClient
	}

	return &Provider{
		name:       cfg.Name,
		baseURL:    cfg.BaseURL,
		apiKey:     cfg.APIKey,
		kind:       kind,
		caps:       caps,
		client:     openai.NewClientWithConfig(clientCfg),
		httpClient: cfg.HTTPClient,
		logger:     cfg.Logger,
	}
}

// NewFromLegacy creates a Provider from individual parameters (backwards-compat).
func NewFromLegacy(name, baseURL, apiKey string, logger *slog.Logger) *Provider {
	return New(Config{
		Name:    name,
		BaseURL: baseURL,
		APIKey:  apiKey,
		Logger:  logger,
	})
}

// NewFromPreset creates a Provider from a named preset with optional overrides.
func NewFromPreset(presetName string, apiKey string, overrides *Config, logger *slog.Logger) (*Provider, error) {
	preset, ok := Presets[presetName]
	if !ok {
		return nil, fmt.Errorf("unknown preset %q: available presets: %s", presetName, availablePresets())
	}

	cfg := Config{
		Name:    presetName,
		BaseURL: preset.BaseURL,
		APIKey:  apiKey,
		Kind:    llmtypes.KindCloud,
		Logger:  logger,
	}
	if preset.IsLocal {
		cfg.Kind = llmtypes.KindLocal
	}

	if overrides != nil {
		if overrides.BaseURL != "" {
			cfg.BaseURL = overrides.BaseURL
		}
		if overrides.Name != "" {
			cfg.Name = overrides.Name
		}
		if overrides.HTTPClient != nil {
			cfg.HTTPClient = overrides.HTTPClient
		}
	}

	if preset.NeedsKey && apiKey == "" {
		return nil, fmt.Errorf("preset %q requires an API key", presetName)
	}

	return New(cfg), nil
}

func availablePresets() string {
	names := make([]string, 0, len(Presets))
	for k := range Presets {
		names = append(names, k)
	}
	return strings.Join(names, ", ")
}

func (p *Provider) Name() string                        { return p.name }
func (p *Provider) Kind() llmtypes.ProviderKind         { return p.kind }
func (p *Provider) IsLocal() bool                       { return p.kind == llmtypes.KindLocal }
func (p *Provider) Capabilities() llmtypes.Capabilities { return p.caps }

// IsAvailable probes the /v1/models endpoint with a short timeout.
func (p *Provider) IsAvailable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	_, err := p.client.ListModels(ctx)
	if err != nil {
		p.logger.Debug("provider not available", "provider", p.name, "error", err)
		return false
	}
	return true
}

// Models lists available models via /v1/models.
func (p *Provider) Models(ctx context.Context) ([]llmtypes.ModelInfo, error) {
	resp, err := p.client.ListModels(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing models on %s: %w\n  hint: is %s running at %s?",
			p.name, err, p.displayName(), p.baseURL)
	}

	models := make([]llmtypes.ModelInfo, len(resp.Models))
	for i, m := range resp.Models {
		models[i] = llmtypes.ModelInfo{
			Name: m.ID,
		}
	}
	return models, nil
}

// Chat sends a non-streaming chat completion request.
func (p *Provider) Chat(ctx context.Context, req llmtypes.ChatRequest) (*llmtypes.ChatResponse, error) {
	messages := toOpenAIMessages(req.Messages)

	oaiReq := openai.ChatCompletionRequest{
		Model:       req.Model,
		Messages:    messages,
		MaxTokens:   req.MaxTokens,
		Temperature: float32(req.Temperature),
	}

	if req.JSONMode {
		oaiReq.ResponseFormat = &openai.ChatCompletionResponseFormat{
			Type: openai.ChatCompletionResponseFormatTypeJSONObject,
		}
	}

	resp, err := p.client.CreateChatCompletion(ctx, oaiReq)
	if err != nil {
		return nil, fmt.Errorf("%s chat failed: %w", p.name, p.hintError(err))
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("%s returned empty choices", p.name)
	}

	return &llmtypes.ChatResponse{
		Content:      resp.Choices[0].Message.Content,
		Model:        resp.Model,
		Provider:     p.name,
		FinishReason: string(resp.Choices[0].FinishReason),
		Usage: llmtypes.Usage{
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		},
	}, nil
}

// ChatStream sends a streaming chat completion request.
// The returned ReadCloser yields newline-delimited JSON StreamChunk objects.
func (p *Provider) ChatStream(ctx context.Context, req llmtypes.ChatRequest) (io.ReadCloser, error) {
	messages := toOpenAIMessages(req.Messages)

	oaiReq := openai.ChatCompletionRequest{
		Model:       req.Model,
		Messages:    messages,
		MaxTokens:   req.MaxTokens,
		Temperature: float32(req.Temperature),
		Stream:      true,
	}

	if req.JSONMode {
		oaiReq.ResponseFormat = &openai.ChatCompletionResponseFormat{
			Type: openai.ChatCompletionResponseFormatTypeJSONObject,
		}
	}

	stream, err := p.client.CreateChatCompletionStream(ctx, oaiReq)
	if err != nil {
		return nil, fmt.Errorf("%s stream failed: %w", p.name, p.hintError(err))
	}

	return &streamReader{stream: stream}, nil
}

// streamReader adapts openai.ChatCompletionStream to io.ReadCloser with
// newline-delimited JSON StreamChunk output.
type streamReader struct {
	stream *openai.ChatCompletionStream
	buf    []byte
}

func (sr *streamReader) Read(p []byte) (int, error) {
	if len(sr.buf) > 0 {
		n := copy(p, sr.buf)
		sr.buf = sr.buf[n:]
		return n, nil
	}

	resp, err := sr.stream.Recv()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, io.EOF
		}
		return 0, err
	}

	if len(resp.Choices) == 0 {
		return 0, nil
	}

	chunk := llmtypes.StreamChunk{
		Content: resp.Choices[0].Delta.Content,
		Done:    resp.Choices[0].FinishReason != "",
	}
	if chunk.Done {
		chunk.FinishReason = string(resp.Choices[0].FinishReason)
	}

	data, err := json.Marshal(chunk)
	if err != nil {
		return 0, err
	}
	data = append(data, '\n')

	n := copy(p, data)
	if n < len(data) {
		sr.buf = data[n:]
	}
	return n, nil
}

func (sr *streamReader) Close() error {
	sr.stream.Close()
	return nil
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

// ProbeCapabilities tests which capabilities actually work with this endpoint.
func (p *Provider) ProbeCapabilities(ctx context.Context) llmtypes.Capabilities {
	caps := p.caps

	// Probe JSON mode with a minimal request.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := p.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model:     p.defaultModel(),
		MaxTokens: 1,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: "ok"},
		},
		ResponseFormat: &openai.ChatCompletionResponseFormat{
			Type: openai.ChatCompletionResponseFormatTypeJSONObject,
		},
	})
	if err != nil {
		p.logger.Debug("JSON mode probe failed", "provider", p.name, "error", err)
		caps.JSONMode = false
	}

	return caps
}

func (p *Provider) defaultModel() string {
	if preset := ResolvePreset(p.name, p.baseURL); preset != nil {
		return preset.DefaultModel
	}
	return "gpt-4o-mini"
}

func (p *Provider) displayName() string {
	if preset := ResolvePreset(p.name, p.baseURL); preset != nil {
		return preset.DisplayName
	}
	return p.name
}

func (p *Provider) hintError(err error) error {
	if err == nil {
		return nil
	}
	if IsLocalURL(p.baseURL) {
		return fmt.Errorf("%w\n  hint: is %s running at %s?", err, p.displayName(), p.baseURL)
	}
	return err
}

func toOpenAIMessages(msgs []llmtypes.Message) []openai.ChatCompletionMessage {
	out := make([]openai.ChatCompletionMessage, len(msgs))
	for i, m := range msgs {
		out[i] = openai.ChatCompletionMessage{
			Role:    m.Role,
			Content: m.Content,
		}
	}
	return out
}
