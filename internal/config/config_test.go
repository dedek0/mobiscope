package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(context.Background(), "", nil)
	require.NoError(t, err)

	assert.Equal(t, "ollama", cfg.LLM.DefaultProvider)
	require.NotNil(t, cfg.LLM.Providers["ollama"])
	assert.Equal(t, "http://localhost:11434", cfg.LLM.Providers["ollama"].BaseURL)
	assert.False(t, cfg.LLM.AllowCloud)
	assert.False(t, cfg.LLM.AllowCloudSecrets)
	assert.Len(t, cfg.LLM.Tasks, 4)
	assert.Contains(t, cfg.LLM.Tasks, "triage")
	assert.Contains(t, cfg.LLM.Tasks, "remediation")
	assert.Contains(t, cfg.LLM.Tasks, "chat")
	assert.Contains(t, cfg.LLM.Tasks, "correlate")
}

func TestLoadFromTOMLFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[llm]
default_provider = "anthropic"
allow_cloud = true

[llm.tasks.triage]
provider = "anthropic"
model = "claude-3-5-haiku"

[llm.providers.anthropic]
type = "anthropic"
api_key_env = "ANTHROPIC_API_KEY"
timeout = 45
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	cfg, err := Load(context.Background(), path, nil)
	require.NoError(t, err)

	assert.Equal(t, "anthropic", cfg.LLM.DefaultProvider)
	assert.True(t, cfg.LLM.AllowCloud)
	require.NotNil(t, cfg.LLM.Providers["anthropic"])
	assert.Equal(t, "anthropic", cfg.LLM.Providers["anthropic"].Type)
	assert.Equal(t, "ANTHROPIC_API_KEY", cfg.LLM.Providers["anthropic"].APIKeyEnv)
	assert.Equal(t, 45, cfg.LLM.Providers["anthropic"].Timeout)

	// Defaults fill the rest of the tasks and the ollama provider.
	require.NotNil(t, cfg.LLM.Providers["ollama"])
	assert.Equal(t, "anthropic", cfg.LLM.Tasks["triage"].Provider)
	assert.Equal(t, "ollama", cfg.LLM.Tasks["chat"].Provider)
}

func TestLoadFromTOML_PartialTasksKeepDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[llm]
default_provider = "ollama"

[llm.tasks.triage]
provider = "ollama"
model = "llama3:8b"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	cfg, err := Load(context.Background(), path, nil)
	require.NoError(t, err)

	assert.Equal(t, "llama3:8b", cfg.LLM.Tasks["triage"].Model)
	assert.Equal(t, "qwen2.5-coder:7b", cfg.LLM.Tasks["chat"].Model)
	assert.Equal(t, "qwen2.5-coder:7b", cfg.LLM.Tasks["remediation"].Model)
	assert.Equal(t, "qwen2.5-coder:7b", cfg.LLM.Tasks["correlate"].Model)
}

func TestLoadFromTOML_MultipleProviders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[llm]
default_provider = "openrouter"

[llm.providers.ollama]
base_url = "http://localhost:11434"

[llm.providers.openrouter]
type = "openai_compatible"
preset = "openrouter"
api_key_env = "OPENROUTER_API_KEY"

[llm.providers.groq]
type = "openai_compatible"
preset = "groq"
api_key_env = "GROQ_API_KEY"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	cfg, err := Load(context.Background(), path, nil)
	require.NoError(t, err)

	assert.Len(t, cfg.LLM.Providers, 3)
	require.NotNil(t, cfg.LLM.Providers["openrouter"])
	assert.Equal(t, "openrouter", cfg.LLM.Providers["openrouter"].Preset)
	require.NotNil(t, cfg.LLM.Providers["groq"])
}

func TestLoadEnv_OverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[llm]
default_provider = "ollama"
allow_cloud = false

[llm.providers.ollama]
base_url = "http://localhost:11434"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	t.Setenv("MOBISCOPE_LLM__ALLOW_CLOUD", "true")
	t.Setenv("MOBISCOPE_LLM__PROVIDERS__OLLAMA__BASE_URL", "http://127.0.0.1:9999")

	cfg, err := Load(context.Background(), path, nil)
	require.NoError(t, err)

	assert.True(t, cfg.LLM.AllowCloud)
	assert.Equal(t, "http://127.0.0.1:9999", cfg.LLM.Providers["ollama"].BaseURL)
	// File value survives when env does not override it.
	assert.Equal(t, "ollama", cfg.LLM.DefaultProvider)
}

func TestLoadEnv_WellKnownAPIKeys(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test-openai")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	t.Setenv("OLLAMA_HOST", "http://192.168.1.50:11434")

	cfg, err := Load(context.Background(), "", nil)
	require.NoError(t, err)

	require.NotNil(t, cfg.LLM.Providers["openai"])
	assert.Equal(t, "sk-test-openai", cfg.LLM.Providers["openai"].APIKey)
	require.NotNil(t, cfg.LLM.Providers["anthropic"])
	assert.Equal(t, "sk-ant-test", cfg.LLM.Providers["anthropic"].APIKey)
	assert.Equal(t, "http://192.168.1.50:11434", cfg.LLM.Providers["ollama"].BaseURL)
}

func TestLoadEnv_IgnoresUnrelatedVars(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:/bin")
	t.Setenv("HOME", "/tmp")
	t.Setenv("SOME_RANDOM_VAR", "value")

	cfg, err := Load(context.Background(), "", nil)
	require.NoError(t, err)
	assert.Len(t, cfg.LLM.Providers, 1)
	assert.Contains(t, cfg.LLM.Providers, "ollama")
}

func TestLoadFlags_OverrideEnvAndFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[llm]
default_provider = "ollama"
allow_cloud = true

[llm.providers.ollama]
type = "ollama"

[llm.providers.gemini]
type = "gemini"
api_key_env = "GEMINI_API_KEY"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	t.Setenv("MOBISCOPE_LLM__ALLOW_CLOUD", "true")

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	var provider string
	var allowCloud bool
	var cfgPath string
	fs.StringVar(&cfgPath, "config", "", "")
	fs.StringVar(&provider, "provider", "", "")
	fs.BoolVar(&allowCloud, "allow-cloud", false, "")
	require.NoError(t, fs.Parse([]string{"--provider", "gemini", "--allow-cloud=false"}))

	cfg, err := Load(context.Background(), path, fs)
	require.NoError(t, err)

	// Flags win over env and file.
	assert.Equal(t, "gemini", cfg.LLM.DefaultProvider)
	assert.False(t, cfg.LLM.AllowCloud)
}

func TestLoadFlags_UnchangedDoNotOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[llm]
default_provider = "anthropic"
allow_cloud = true

[llm.providers.ollama]
type = "ollama"

[llm.providers.anthropic]
type = "anthropic"
api_key_env = "ANTHROPIC_API_KEY"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	var provider string
	var allowCloud bool
	fs.StringVar(&provider, "provider", "", "")
	fs.BoolVar(&allowCloud, "allow-cloud", false, "")
	// No args: flags remain at defaults and must not clobber the file.

	cfg, err := Load(context.Background(), path, fs)
	require.NoError(t, err)

	assert.Equal(t, "anthropic", cfg.LLM.DefaultProvider)
	assert.True(t, cfg.LLM.AllowCloud)
}

func TestLoad_PrecedenceDefaultsFileEnvFlags(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[llm]
default_provider = "ollama"
allow_cloud = false

[llm.tasks.triage]
provider = "ollama"
model = "file-model"

[llm.providers.ollama]
type = "ollama"
base_url = "http://file:1"

[llm.providers.anthropic]
type = "anthropic"
api_key_env = "ANTHROPIC_API_KEY"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	t.Setenv("MOBISCOPE_LLM__TASKS__TRIAGE__MODEL", "env-model")

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	var provider string
	fs.StringVar(&provider, "provider", "", "")
	require.NoError(t, fs.Parse([]string{"--provider", "anthropic"}))

	cfg, err := Load(context.Background(), path, fs)
	require.NoError(t, err)

	// flags > env > file > defaults
	assert.Equal(t, "anthropic", cfg.LLM.DefaultProvider)
	assert.Equal(t, "env-model", cfg.LLM.Tasks["triage"].Model)
	assert.Equal(t, "ollama", cfg.LLM.Tasks["triage"].Provider)
	// untouched by file/env/flags
	assert.Equal(t, "qwen2.5-coder:7b", cfg.LLM.Tasks["chat"].Model)
}

func TestLoad_EnvConfigPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.toml")
	content := `
[llm]
default_provider = "anthropic"

[llm.providers.anthropic]
type = "anthropic"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	t.Setenv("MOBISCOPE_CONFIG", path)

	cfg, err := Load(context.Background(), "", nil)
	require.NoError(t, err)
	assert.Equal(t, "anthropic", cfg.LLM.DefaultProvider)
}

func TestLoad_MissingExplicitPath(t *testing.T) {
	_, err := Load(context.Background(), "/nonexistent/config.toml", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config file not found")
}

func TestLoad_MissingEnvConfigPath(t *testing.T) {
	t.Setenv("MOBISCOPE_CONFIG", "/nonexistent/config.toml")
	_, err := Load(context.Background(), "", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config file not found")
}

func TestLoad_UnsupportedFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("llm: {}\n"), 0o600))

	_, err := Load(context.Background(), path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only TOML is supported")
}

func TestLoad_InvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(path, []byte("this is [not toml"), 0o600))

	_, err := Load(context.Background(), path, nil)
	require.Error(t, err)
}

func TestLoad_InvalidBaseURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[llm]
default_provider = "ollama"

[llm.providers.ollama]
base_url = "not-a-url"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	_, err := Load(context.Background(), path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validating config")
}

func TestLoad_InvalidTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[llm]
default_provider = "ollama"

[llm.providers.ollama]
timeout = -5
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	_, err := Load(context.Background(), path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validating config")
}

func TestLoad_InvalidAPIKeyEnvName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[llm]
default_provider = "ollama"

[llm.providers.ollama]
api_key_env = "not valid!"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	_, err := Load(context.Background(), path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validating config")
}

func TestLoad_TaskReferencesUnknownProvider(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[llm]
default_provider = "ollama"

[llm.tasks.triage]
provider = "ghost"
model = "x"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	_, err := Load(context.Background(), path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestLoad_DefaultProviderNotDefined(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[llm]
default_provider = "ghost"

[llm.tasks.triage]
provider = "ollama"
model = "x"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	_, err := Load(context.Background(), path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "default_provider")
}

func TestLoad_MissingTaskFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := `
[llm]
default_provider = "ollama"

[llm.tasks.triage]
provider = "ollama"
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	_, err := Load(context.Background(), path, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validating config")
}

func TestApplyDefaults_PartialTasks(t *testing.T) {
	cfg := &Config{
		LLM: LLMConfig{
			Tasks: map[string]Task{
				"triage": {Provider: "ollama", Model: "custom"},
			},
		},
	}
	applyDefaults(cfg)

	assert.Equal(t, "custom", cfg.LLM.Tasks["triage"].Model)
	assert.Equal(t, "ollama", cfg.LLM.Tasks["chat"].Provider)
	assert.Equal(t, "ollama", cfg.LLM.Tasks["remediation"].Provider)
	assert.Equal(t, "ollama", cfg.LLM.Tasks["correlate"].Provider)
	assert.Equal(t, "ollama", cfg.LLM.DefaultProvider)
	require.NotNil(t, cfg.LLM.Providers["ollama"])
}

func TestApplyDefaults_NilProviders(t *testing.T) {
	cfg := &Config{}
	applyDefaults(cfg)
	require.NotNil(t, cfg.LLM.Providers["ollama"])
	assert.Equal(t, "http://localhost:11434", cfg.LLM.Providers["ollama"].BaseURL)
}

func TestResolveConfigPath_Explicit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.toml")
	require.NoError(t, os.WriteFile(path, []byte("[llm]\n"), 0o600))

	got, err := resolveConfigPath(path)
	require.NoError(t, err)
	assert.Equal(t, path, got)
}

func TestResolveConfigPath_Discovery(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(path, []byte("[llm]\n"), 0o600))

	t.Chdir(dir)
	t.Setenv("MOBISCOPE_CONFIG", "")

	got, err := resolveConfigPath("")
	require.NoError(t, err)
	assert.Equal(t, "config.toml", got)
}

func TestResolveConfigPath_NoneFound(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("MOBISCOPE_CONFIG", "")
	t.Setenv("HOME", filepath.Join(dir, "no-home"))

	got, err := resolveConfigPath("")
	require.NoError(t, err)
	assert.Equal(t, "", got)
}
