package llm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/dedek0/mobiscope/internal/config"
	"github.com/dedek0/mobiscope/internal/llm/llmtypes"
)

// Router selects the best provider and model for a given task, respecting
// configuration, fallback chains, and privacy policy.
type Router struct {
	providers map[string]Provider
	cfg       config.LLMConfig
	logger    *slog.Logger
}

// NewRouter creates a Router from configured providers and LLM config.
func NewRouter(providers map[string]Provider, cfg config.LLMConfig, logger *slog.Logger) *Router {
	return &Router{
		providers: providers,
		cfg:       cfg,
		logger:    logger,
	}
}

// RouteResult holds the outcome of a routing decision.
type RouteResult struct {
	Provider Provider
	Model    string
	TaskName string
}

// Route selects the provider and model for the given task.
// It follows this order:
//  1. Explicit task config (e.g., [llm.tasks.triage])
//  2. Default provider from [llm] section
//  3. Any available provider (local first, then cloud if allowed)
//
// Privacy policy is enforced:
//   - If AllowCloud is false, cloud providers are skipped
//   - If containsSecret is true, only local providers are used unless AllowCloudSecrets is set
func (r *Router) Route(ctx context.Context, task llmtypes.TaskType, containsSecret bool) (*RouteResult, error) {
	var cloudErr error

	// 1. Try explicit task config.
	if taskCfg, ok := r.cfg.Tasks[string(task)]; ok {
		result, err := r.tryProvider(ctx, taskCfg.Provider, taskCfg.Model, string(task), containsSecret)
		if err == nil {
			return result, nil
		}
		if errors.Is(err, ErrCloudNotAllowed) {
			cloudErr = err
		}
		r.logger.Warn("task provider unavailable, trying fallback",
			"task", task, "provider", taskCfg.Provider, "error", err)
	}

	// 2. Try default provider.
	if r.cfg.DefaultProvider != "" {
		model := r.defaultModel(r.cfg.DefaultProvider)
		result, err := r.tryProvider(ctx, r.cfg.DefaultProvider, model, string(task), containsSecret)
		if err == nil {
			return result, nil
		}
		if errors.Is(err, ErrCloudNotAllowed) {
			cloudErr = err
		}
		r.logger.Warn("default provider unavailable, trying auto-detect",
			"provider", r.cfg.DefaultProvider, "error", err)
	}

	// 3. Auto-detect: local first, then cloud if allowed.
	result, err := r.autoDetect(ctx, containsSecret)
	if err == nil {
		return result, nil
	}
	if errors.Is(err, ErrCloudNotAllowed) {
		cloudErr = err
	}

	// If the reason for failure was a cloud policy violation, surface that error.
	if cloudErr != nil {
		return nil, cloudErr
	}

	return nil, fmt.Errorf("no available provider for task %s: %w", task, ErrProviderUnavailable)
}

func (r *Router) tryProvider(ctx context.Context, name, model, taskName string, containsSecret bool) (*RouteResult, error) {
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("provider %q not configured", name)
	}

	// Privacy policy: block cloud if not allowed.
	if p.Kind() == llmtypes.KindCloud {
		if !r.cfg.AllowCloud {
			return nil, fmt.Errorf("%w: provider %q is cloud-based and allow_cloud=false", ErrCloudNotAllowed, name)
		}
		if containsSecret && !r.cfg.AllowCloudSecrets {
			return nil, fmt.Errorf("%w: finding contains secrets; use --allow-cloud-secrets to override", ErrCloudNotAllowed)
		}
	}

	if !p.IsAvailable(ctx) {
		return nil, fmt.Errorf("provider %q: %w", name, ErrProviderUnavailable)
	}

	r.logger.Debug("routed task", "task", taskName, "provider", name, "model", model)
	return &RouteResult{Provider: p, Model: model, TaskName: taskName}, nil
}

func (r *Router) autoDetect(ctx context.Context, containsSecret bool) (*RouteResult, error) {
	// Try local providers first.
	for name, p := range r.providers {
		if !p.IsLocal() {
			continue
		}
		if p.IsAvailable(ctx) {
			model := r.defaultModel(name)
			return &RouteResult{Provider: p, Model: model, TaskName: "auto-local"}, nil
		}
	}

	// Try cloud if allowed.
	if r.cfg.AllowCloud && (!containsSecret || r.cfg.AllowCloudSecrets) {
		for name, p := range r.providers {
			if p.IsLocal() {
				continue
			}
			if p.IsAvailable(ctx) {
				model := r.defaultModel(name)
				return &RouteResult{Provider: p, Model: model, TaskName: "auto-cloud"}, nil
			}
		}
	}

	return nil, fmt.Errorf("no available provider: %w", ErrProviderUnavailable)
}

func (r *Router) defaultModel(providerName string) string {
	if taskCfg, ok := r.cfg.Tasks["triage"]; ok && taskCfg.Provider == providerName {
		return taskCfg.Model
	}
	for _, t := range r.cfg.Tasks {
		if t.Provider == providerName {
			return t.Model
		}
	}
	return ""
}

// RouteStrict is like Route but returns ErrCloudNotAllowed when cloud is blocked
// instead of falling back silently.
func (r *Router) RouteStrict(ctx context.Context, task llmtypes.TaskType, containsSecret bool) (*RouteResult, error) {
	result, err := r.Route(ctx, task, containsSecret)
	if err != nil {
		if errors.Is(err, ErrCloudNotAllowed) {
			return nil, err
		}
	}
	return result, err
}

// Providers returns all configured providers.
func (r *Router) Providers() map[string]Provider {
	return r.providers
}
