// Package config loads and validates mobiscope configuration.
//
// Configuration is resolved in layers, later layers overriding earlier ones:
//
//  1. built-in defaults
//  2. TOML config file
//  3. environment variables
//  4. command-line flags (only those explicitly set)
//
// See resolveConfigPath for the config file discovery order.
package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/parsers/toml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/spf13/pflag"
)

// Config represents the complete application configuration.
type Config struct {
	LLM      LLMConfig      `koanf:"llm"      validate:"required"`
	Pipeline PipelineConfig `koanf:"pipeline"`
}

// PipelineConfig controls analyzer execution.
type PipelineConfig struct {
	// MaxConcurrency bounds how many external tools run at once.
	MaxConcurrency int `koanf:"max_concurrency" validate:"omitempty,gt=0"`
	// FailFast aborts the pipeline on the first analyzer error.
	FailFast bool `koanf:"fail_fast"`
}

// LLMConfig holds all LLM-related configuration.
type LLMConfig struct {
	DefaultProvider   string `koanf:"default_provider" validate:"omitempty"`
	AllowCloud        bool   `koanf:"allow_cloud"`
	AllowCloudSecrets bool   `koanf:"allow_cloud_secrets"`
	// MaxRetries is the number of retries for transient LLM failures.
	MaxRetries int `koanf:"max_retries" validate:"omitempty,gte=0,lte=10"`
	// RetryBaseDelayMS is the base backoff delay in milliseconds.
	RetryBaseDelayMS int `koanf:"retry_base_delay_ms" validate:"omitempty,gt=0"`
	// TimeoutSeconds caps a single LLM call.
	TimeoutSeconds int             `koanf:"timeout_seconds" validate:"omitempty,gt=0"`
	Tasks          map[string]Task `koanf:"tasks" validate:"dive"`
	Providers      ProvidersConfig `koanf:"providers" validate:"required,dive,required"`
}

// Task defines which provider/model to use for a specific task type.
type Task struct {
	Provider string `koanf:"provider" validate:"required"`
	Model    string `koanf:"model"    validate:"required"`
}

// ProvidersConfig holds configuration for every configured LLM provider,
// keyed by provider name (e.g. "ollama", "openai", "anthropic").
type ProvidersConfig map[string]*ProviderConfig

// ProviderConfig holds configuration for a single LLM provider.
type ProviderConfig struct {
	Type      string `koanf:"type" validate:"omitempty,oneof=ollama openai openai_compatible anthropic gemini"`
	Preset    string `koanf:"preset"`
	BaseURL   string `koanf:"base_url" validate:"omitempty,http_url"`
	APIKeyEnv string `koanf:"api_key_env" validate:"omitempty,envvar"`
	APIKey    string `koanf:"api_key"`
	Timeout   int    `koanf:"timeout" validate:"omitempty,gt=0"`
}

// wellKnownEnv maps conventional environment variables to config keys so
// existing provider credentials keep working without a config file.
var wellKnownEnv = map[string]string{
	"OLLAMA_HOST":          "llm.providers.ollama.base_url",
	"OPENAI_API_KEY":       "llm.providers.openai.api_key",
	"ANTHROPIC_API_KEY":    "llm.providers.anthropic.api_key",
	"GOOGLE_API_KEY":       "llm.providers.gemini.api_key",
	"GEMINI_API_KEY":       "llm.providers.gemini.api_key",
	"OPENROUTER_API_KEY":   "llm.providers.openrouter.api_key",
	"GROQ_API_KEY":         "llm.providers.groq.api_key",
	"TOGETHER_API_KEY":     "llm.providers.together.api_key",
	"AZURE_OPENAI_API_KEY": "llm.providers.azure.api_key",
}

// envVarNameRe matches POSIX-style environment variable names.
var envVarNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Load reads configuration from file, environment variables, and flags.
//
// cfgPath is an explicit config file path; when empty the path is taken from
// $MOBISCOPE_CONFIG and then from the default discovery locations. flags may
// be nil; only flags explicitly set on the command line override lower layers.
func Load(ctx context.Context, cfgPath string, flags *pflag.FlagSet) (*Config, error) {
	k := koanf.New(".")

	path, err := resolveConfigPath(cfgPath)
	if err != nil {
		return nil, err
	}
	if path != "" {
		if err := loadFromFile(k, path); err != nil {
			return nil, fmt.Errorf("loading config file: %w", err)
		}
	}

	if err := loadEnv(k); err != nil {
		return nil, fmt.Errorf("loading environment variables: %w", err)
	}

	if flags != nil {
		if err := loadFlags(k, flags); err != nil {
			return nil, fmt.Errorf("loading flags: %w", err)
		}
	}

	cfg := &Config{}
	if err := unmarshal(k, cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	applyDefaults(cfg)

	if err := validate(ctx, cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// unmarshal decodes koanf keys into cfg, coercing string values (from env
// vars and flags) into the typed struct fields.
func unmarshal(k *koanf.Koanf, cfg *Config) error {
	return k.UnmarshalWithConf("", cfg, koanf.UnmarshalConf{
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook:       mapstructure.StringToTimeDurationHookFunc(),
			WeaklyTypedInput: true,
			Result:           cfg,
			TagName:          "koanf",
		},
	})
}

// resolveConfigPath returns the config file to load.
//
// Order: explicit path, $MOBISCOPE_CONFIG, then default locations.
// An empty explicit path is not an error when no file exists anywhere;
// an explicit (or env-selected) path that is missing is an error.
func resolveConfigPath(explicit string) (string, error) {
	if explicit != "" {
		if !configFileExists(explicit) {
			return "", fmt.Errorf("config file not found: %s", explicit)
		}
		return explicit, nil
	}

	if p := os.Getenv("MOBISCOPE_CONFIG"); p != "" {
		if !configFileExists(p) {
			return "", fmt.Errorf("config file not found: %s", p)
		}
		return p, nil
	}

	for _, p := range defaultConfigPaths() {
		if configFileExists(p) {
			return p, nil
		}
	}
	return "", nil
}

// configFileExists reports whether path exists. The path is user-provided
// (flag/env/discovery) by design in this local CLI tool; no network exposure.
func configFileExists(path string) bool {
	_, err := os.Stat(filepath.Clean(path)) //nolint:gosec // G703: user-supplied config path is intentional
	return err == nil
}

func defaultConfigPaths() []string {
	paths := []string{"config.toml", "mobiscope.toml"}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths,
			filepath.Join(home, ".config", "mobiscope", "config.toml"),
			filepath.Join(home, ".mobiscope", "config.toml"),
		)
	}
	return paths
}

// loadFromFile loads a TOML config file into k.
func loadFromFile(k *koanf.Koanf, path string) error {
	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case "", ".toml":
	default:
		return fmt.Errorf("unsupported config format %q: only TOML is supported", ext)
	}

	if !configFileExists(path) {
		return fmt.Errorf("config file not found: %s", path)
	}

	if err := k.Load(file.Provider(path), toml.Parser()); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	return nil
}

// loadEnv loads environment variables into k.
//
// Two families are recognized:
//   - MOBISCOPE_<PATH> where PATH uses "__" as the key separator
//     (MOBISCOPE_LLM__ALLOW_CLOUD -> llm.allow_cloud)
//   - well-known provider variables such as OPENAI_API_KEY or OLLAMA_HOST
func loadEnv(k *koanf.Koanf) error {
	return k.Load(env.ProviderWithValue("", ".", func(key, value string) (string, interface{}) {
		if strings.HasPrefix(key, "MOBISCOPE_") {
			path := strings.TrimPrefix(key, "MOBISCOPE_")
			if path == "CONFIG" {
				return "", nil // path is handled by resolveConfigPath
			}
			path = strings.ToLower(strings.ReplaceAll(path, "__", "."))
			if path == "" {
				return "", nil
			}
			return path, value
		}
		if mapped, ok := wellKnownEnv[key]; ok {
			return mapped, value
		}
		return "", nil
	}), nil)
}

// loadFlags merges explicitly-set command-line flags into k (highest precedence).
// Unchanged flags only apply when no lower layer provided a value.
func loadFlags(k *koanf.Koanf, flags *pflag.FlagSet) error {
	return k.Load(posflag.ProviderWithValue(flags, ".", k, func(name, value string) (string, interface{}) {
		switch name {
		case "config":
			return "", nil // path is handled by resolveConfigPath
		case "provider":
			if value == "" {
				return "", nil
			}
			return "llm.default_provider", value
		case "allow-cloud":
			return "llm.allow_cloud", value
		default:
			return name, value
		}
	}), nil)
}

// applyDefaults fills gaps left by lower-precedence layers. It never
// overwrites a value that is already set.
func applyDefaults(cfg *Config) {
	if cfg.LLM.DefaultProvider == "" {
		cfg.LLM.DefaultProvider = "ollama"
	}

	if cfg.LLM.Providers == nil {
		cfg.LLM.Providers = ProvidersConfig{}
	}
	if cfg.LLM.Providers["ollama"] == nil {
		cfg.LLM.Providers["ollama"] = &ProviderConfig{
			BaseURL: "http://localhost:11434",
		}
	}

	if cfg.LLM.Tasks == nil {
		cfg.LLM.Tasks = map[string]Task{}
	}
	for name, def := range defaultTasks() {
		if _, ok := cfg.LLM.Tasks[name]; !ok {
			cfg.LLM.Tasks[name] = def
		}
	}

	if cfg.LLM.MaxRetries == 0 {
		cfg.LLM.MaxRetries = 3
	}
	if cfg.LLM.RetryBaseDelayMS == 0 {
		cfg.LLM.RetryBaseDelayMS = 500
	}
	if cfg.LLM.TimeoutSeconds == 0 {
		cfg.LLM.TimeoutSeconds = 60
	}

	if cfg.Pipeline.MaxConcurrency == 0 {
		cfg.Pipeline.MaxConcurrency = 4
	}
}

func defaultTasks() map[string]Task {
	def := Task{Provider: "ollama", Model: "qwen2.5-coder:7b"}
	return map[string]Task{
		"triage":      def,
		"remediation": def,
		"chat":        def,
		"correlate":   def,
	}
}

// validate runs struct validation and cross-field checks.
func validate(ctx context.Context, cfg *Config) error {
	v := validator.New()
	if err := v.RegisterValidation("envvar", validateEnvVarName); err != nil {
		return fmt.Errorf("registering validator: %w", err)
	}

	if err := v.StructCtx(ctx, cfg); err != nil {
		return fmt.Errorf("validating config: %w", err)
	}

	if cfg.LLM.DefaultProvider != "" {
		if _, ok := cfg.LLM.Providers[cfg.LLM.DefaultProvider]; !ok {
			return fmt.Errorf("validating config: default_provider %q is not defined in [llm.providers]", cfg.LLM.DefaultProvider)
		}
	}

	for name, task := range cfg.LLM.Tasks {
		if _, ok := cfg.LLM.Providers[task.Provider]; !ok {
			return fmt.Errorf("validating config: task %q references unknown provider %q", name, task.Provider)
		}
	}

	return nil
}

func validateEnvVarName(fl validator.FieldLevel) bool {
	return envVarNameRe.MatchString(fl.Field().String())
}
