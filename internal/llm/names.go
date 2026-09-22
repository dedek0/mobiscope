package llm

// Canonical provider names used in configuration, routing, and detection.
const (
	NameOllama    = "ollama"
	NameOpenAI    = "openai"
	NameAnthropic = "anthropic"
	NameGemini    = "gemini"
)

// Default model names used when a provider has no configured task model.
const (
	ModelOllamaDefault = "qwen2.5-coder:7b"
	ModelOpenAIDefault = "gpt-4o-mini"
	ModelGeminiDefault = "gemini-2.0-flash"
)
