package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/dedek0/mobiscope/internal/config"
	"github.com/dedek0/mobiscope/internal/llm"
	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Server holds the HTTP server dependencies.
type Server struct {
	router    *chi.Mux
	cfg       *config.Config
	factory   *llm.Factory
	providers map[string]llm.Provider
	logger    *slog.Logger
	authToken string
}

// NewServer creates a new API server.
//
// Authentication is disabled unless MOBISCOPE_API_TOKEN is set. The server is
// intended for local use; see SECURITY.md before exposing it on a network.
func NewServer(cfg *config.Config, logger *slog.Logger) (*Server, error) {
	factory := llm.NewFactory(logger)
	providers, err := factory.CreateAll(cfg.LLM.Providers)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:       cfg,
		factory:   factory,
		providers: providers,
		logger:    logger,
		authToken: os.Getenv("MOBISCOPE_API_TOKEN"),
	}

	s.router = s.buildRouter()
	return s, nil
}

// Handler returns the http.Handler for testing and for the serve command.
func (s *Server) Handler() http.Handler {
	return s.router
}

// maxBodyBytes caps request payloads (1 MiB).
const maxBodyBytes = 1 << 20

func (s *Server) buildRouter() *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/healthz"))
	r.Use(limitBody)
	if s.authToken != "" {
		r.Use(bearerAuth(s.authToken))
	}

	r.Route("/api", func(r chi.Router) {
		r.Route("/llm", func(r chi.Router) {
			r.Get("/providers", s.handleLLMProviders)
			r.Get("/providers/{name}/models", s.handleLLMProviderModels)
			r.Get("/config", s.handleLLMConfig)
			r.Post("/test", s.handleLLMTest)
			r.Post("/pull", s.handleLLMPull)
		})

		r.Route("/sessions", func(r chi.Router) {
			r.Get("/", s.handleSessions)
			r.Get("/{id}", s.handleSessionGet)
		})
	})

	return r
}

// limitBody rejects oversized request payloads.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxBodyBytes {
			JSONError(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// decodeJSON decodes a request body and maps size-limit errors to 413.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}) error {
	err := json.NewDecoder(r.Body).Decode(dst)
	if err == nil {
		return nil
	}
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) || strings.Contains(err.Error(), "request body too large") {
		JSONError(w, "request body too large", http.StatusRequestEntityTooLarge)
		return err
	}
	JSONError(w, "invalid request body", http.StatusBadRequest)
	return err
}

// bearerAuth enforces a static bearer token. Only installed when a token is
// configured; the default local deployment is unauthenticated.
func bearerAuth(token string) func(http.Handler) http.Handler {
	want := "Bearer " + token
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != want {
				JSONError(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// --- LLM Handlers ---

// handleLLMProviders returns all detected providers with their status.
func (s *Server) handleLLMProviders(w http.ResponseWriter, r *http.Request) {
	detector := llm.NewDetector(s.logger)
	results := detector.DetectAvailable(r.Context(), s.providers)
	JSONOK(w, results)
}

// handleLLMProviderModels returns models for a specific provider.
func (s *Server) handleLLMProviderModels(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	p, ok := s.providers[name]
	if !ok {
		JSONError(w, "provider not found: "+name, http.StatusNotFound)
		return
	}

	models, err := p.Models(r.Context())
	if err != nil {
		JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}

	JSONOK(w, map[string]interface{}{
		"provider": name,
		"models":   models,
	})
}

// handleLLMConfig returns the effective LLM configuration.
func (s *Server) handleLLMConfig(w http.ResponseWriter, _ *http.Request) {
	type taskInfo struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
	}

	tasks := make(map[string]taskInfo)
	for k, t := range s.cfg.LLM.Tasks {
		tasks[k] = taskInfo{Provider: t.Provider, Model: t.Model}
	}

	JSONOK(w, map[string]interface{}{
		"default_provider":    s.cfg.LLM.DefaultProvider,
		"allow_cloud":         s.cfg.LLM.AllowCloud,
		"allow_cloud_secrets": s.cfg.LLM.AllowCloudSecrets,
		"tasks":               tasks,
	})
}

// handleLLMTest sends a test prompt to a provider and returns the response.
// The provider and model from the request body are honored when set.
func (s *Server) handleLLMTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string `json:"provider"`
		Task     string `json:"task"`
		Model    string `json:"model"`
	}

	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	if req.Task == "" {
		req.Task = "triage"
	}

	llmRouter := llm.NewRouter(s.providers, s.cfg.LLM, s.logger)
	task := llmtypes.TaskType(req.Task)

	var route *llm.RouteResult
	var err error
	if req.Provider != "" {
		p, ok := s.providers[req.Provider]
		if !ok {
			JSONError(w, "provider not found: "+req.Provider, http.StatusNotFound)
			return
		}
		model := req.Model
		if model == "" {
			model = s.cfg.LLM.Tasks[req.Task].Model
		}
		if model == "" {
			JSONError(w, "model is required when provider is set explicitly", http.StatusBadRequest)
			return
		}
		if p.Kind() == llmtypes.KindCloud && !s.cfg.LLM.AllowCloud {
			JSONError(w, "cloud providers are disabled (allow_cloud=false)", http.StatusForbidden)
			return
		}
		route = &llm.RouteResult{Provider: p, Model: model, TaskName: req.Task}
	} else {
		route, err = llmRouter.Route(r.Context(), task, false)
		if err != nil {
			JSONError(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	}

	prompt := "Respond with exactly: {\"status\":\"ok\"}"
	chatReq := llmtypes.ChatRequest{
		Model: route.Model,
		Messages: []llmtypes.Message{
			{Role: "user", Content: prompt},
		},
		JSONMode: route.Provider.Capabilities().JSONMode,
	}

	resp, err := route.Provider.Chat(r.Context(), chatReq)
	if err != nil {
		JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}

	cost := llm.EstimateCost(route.Model, resp.Usage)

	JSONOK(w, map[string]interface{}{
		"provider": route.Provider.Name(),
		"model":    route.Model,
		"response": resp.Content,
		"usage":    resp.Usage,
		"cost_usd": cost,
		"task":     req.Task,
	})
}

// handleLLMPull downloads a model (ollama only).
func (s *Server) handleLLMPull(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
	}

	if err := decodeJSON(w, r, &req); err != nil {
		return
	}

	if req.Provider == "" {
		req.Provider = "ollama"
	}

	p, ok := s.providers[req.Provider]
	if !ok {
		JSONError(w, "provider not found: "+req.Provider, http.StatusNotFound)
		return
	}

	if !p.IsLocal() {
		JSONError(w, "pull is only supported for local providers", http.StatusBadRequest)
		return
	}

	type puller interface {
		Pull(ctx context.Context, model string) error
	}

	if pullProv, ok := p.(puller); ok {
		if err := pullProv.Pull(r.Context(), req.Model); err != nil {
			JSONError(w, err.Error(), http.StatusBadGateway)
			return
		}
		JSONOK(w, map[string]string{"status": "ok", "model": req.Model})
		return
	}

	JSONError(w, "provider does not support pull", http.StatusBadRequest)
}

// --- Session Handlers ---

func (s *Server) handleSessions(w http.ResponseWriter, _ *http.Request) {
	JSONOK(w, []interface{}{})
}

func (s *Server) handleSessionGet(w http.ResponseWriter, _ *http.Request) {
	JSONError(w, "not implemented", http.StatusNotImplemented)
}
