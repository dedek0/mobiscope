package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func FuzzLoadTOML(f *testing.F) {
	f.Add([]byte(`[llm]\ndefault_provider = "ollama"\n`))
	f.Add([]byte(``))
	f.Add([]byte(`not toml at all`))
	f.Add([]byte(`[llm]\ndefault_provider = 5`))
	f.Add([]byte(`[llm.providers.ollama]\nbase_url = "http://localhost:11434"`))
	f.Add([]byte(`[llm.tasks.triage]\nprovider = "x"`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		// Must never panic; may return a validation error.
		cfg, err := Load(context.Background(), path, nil)
		if err != nil {
			return
		}
		if cfg == nil {
			t.Fatal("nil config with nil error")
		}
		if cfg.LLM.DefaultProvider == "" {
			t.Fatal("default provider must never be empty after defaults")
		}
		if _, ok := cfg.LLM.Providers["ollama"]; !ok {
			t.Fatal("ollama provider must always be present after defaults")
		}
	})
}
