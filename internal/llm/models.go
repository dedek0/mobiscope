package llm

// ModelInfo contains metadata about an LLM model.
type ModelInfo struct {
	ID            string       `json:"id"`
	Provider      string       `json:"provider"`
	DisplayName   string       `json:"display_name"`
	ContextWindow int          `json:"context_window"`
	CostPer1KIn   float64      `json:"cost_per_1k_in"`
	CostPer1KOut  float64      `json:"cost_per_1k_out"`
	Capabilities  Capabilities `json:"capabilities"`
	IsLocal       bool         `json:"is_local"`
}

// Registry holds known models and their metadata.
type Registry struct {
	models map[string]ModelInfo
}

// NewRegistry creates a new model registry with default models.
func NewRegistry() *Registry {
	r := &Registry{
		models: make(map[string]ModelInfo),
	}
	r.registerDefaults()
	return r
}

func (r *Registry) registerDefaults() {
	defaults := []ModelInfo{
		{
			ID:            "qwen2.5-coder:7b",
			Provider:      "ollama",
			DisplayName:   "Qwen 2.5 Coder 7B",
			ContextWindow: 32768,
			IsLocal:       true,
			Capabilities:  Capabilities{JSONMode: true, Streaming: true},
		},
		{
			ID:            "llama3.1:8b",
			Provider:      "ollama",
			DisplayName:   "Llama 3.1 8B",
			ContextWindow: 131072,
			IsLocal:       true,
			Capabilities:  Capabilities{JSONMode: true, Streaming: true},
		},
		{
			ID:            "gpt-4o",
			Provider:      "openai",
			DisplayName:   "GPT-4o",
			ContextWindow: 128000,
			CostPer1KIn:   0.0025,
			CostPer1KOut:  0.01,
			Capabilities:  Capabilities{JSONMode: true, Streaming: true, ToolCalling: true, Vision: true},
		},
		{
			ID:            "gpt-4o-mini",
			Provider:      "openai",
			DisplayName:   "GPT-4o Mini",
			ContextWindow: 128000,
			CostPer1KIn:   0.00015,
			CostPer1KOut:  0.0006,
			Capabilities:  Capabilities{JSONMode: true, Streaming: true, ToolCalling: true, Vision: true},
		},
		{
			ID:            "claude-sonnet-4",
			Provider:      "anthropic",
			DisplayName:   "Claude Sonnet 4",
			ContextWindow: 200000,
			CostPer1KIn:   0.003,
			CostPer1KOut:  0.015,
			Capabilities:  Capabilities{JSONMode: true, Streaming: true, ToolCalling: true, Vision: true},
		},
		{
			ID:            "gemini-2.0-flash",
			Provider:      "gemini",
			DisplayName:   "Gemini 2.0 Flash",
			ContextWindow: 1048576,
			CostPer1KIn:   0.0001,
			CostPer1KOut:  0.0004,
			Capabilities:  Capabilities{JSONMode: true, Streaming: true, ToolCalling: true, Vision: true},
		},
	}

	for _, m := range defaults {
		r.models[m.ID] = m
	}
}

// Get returns model info by ID.
func (r *Registry) Get(id string) (ModelInfo, bool) {
	m, ok := r.models[id]
	return m, ok
}

// Register adds or updates a model in the registry.
func (r *Registry) Register(m ModelInfo) {
	r.models[m.ID] = m
}

// List returns all registered models.
func (r *Registry) List() []ModelInfo {
	result := make([]ModelInfo, 0, len(r.models))
	for _, m := range r.models {
		result = append(result, m)
	}
	return result
}

// ListByProvider returns models for a specific provider.
func (r *Registry) ListByProvider(provider string) []ModelInfo {
	var result []ModelInfo
	for _, m := range r.models {
		if m.Provider == provider {
			result = append(result, m)
		}
	}
	return result
}
