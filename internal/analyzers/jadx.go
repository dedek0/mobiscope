package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	jadxBinary  = "jadx"
	jadxTimeout = 15 * time.Minute
)

// JADXConfig holds configuration for the JADX analyzer.
type JADXConfig struct {
	NoRes   bool
	Threads int
}

// JADX implements the Analyzer interface for jadx.
type JADX struct {
	cfg    JADXConfig
	runner CommandRunner
}

// NewJADX creates a new JADX analyzer.
func NewJADX(cfg JADXConfig) *JADX {
	if cfg.Threads <= 0 {
		cfg.Threads = runtime.NumCPU()
	}
	return &JADX{cfg: cfg, runner: &DefaultCommandRunner{}}
}

// NewJADXWithRunner creates a JADX with a custom runner (for testing).
func NewJADXWithRunner(cfg JADXConfig, runner CommandRunner) *JADX {
	if cfg.Threads <= 0 {
		cfg.Threads = runtime.NumCPU()
	}
	return &JADX{cfg: cfg, runner: runner}
}

func (a *JADX) Name() string { return "jadx" }

func (a *JADX) Available() error {
	return CheckBinary(jadxBinary)
}

func (a *JADX) Run(ctx context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()

	result := models.ToolResult{
		ToolName:  a.Name(),
		Version:   ParseVersion(jadxBinary),
		StartedAt: start,
	}

	outDir := filepath.Join(workdir, "jadx")

	args := []string{
		"--threads-count", fmt.Sprintf("%d", a.cfg.Threads),
		"-d", outDir,
	}
	if a.cfg.NoRes {
		args = append(args, "--no-res")
	}
	args = append(args, "--", target)

	cmdResult, err := a.runner.Run(ctx, jadxBinary, args, jadxTimeout, nil)
	result.Duration = time.Since(start)

	if cmdResult != nil {
		result.ExitCode = cmdResult.ExitCode
		outputData := map[string]interface{}{
			"stdout":       cmdResult.Stdout,
			"stderr":       cmdResult.Stderr,
			"dex_warnings": parseDEXWarnings(cmdResult.Stderr),
			"threads_used": a.cfg.Threads,
		}
		result.Output, _ = json.Marshal(outputData)
	}

	if err != nil {
		result.Error = err.Error()
		return result, fmt.Errorf("jadx execution failed: %w", err)
	}

	return result, nil
}

// parseDEXWarnings extracts DEX-related warnings from jadx stderr output.
func parseDEXWarnings(stderr string) []string {
	var warnings []string
	for _, line := range strings.Split(stderr, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "dex") && (strings.Contains(lower, "warn") || strings.Contains(lower, "error") || strings.Contains(lower, "fail")) {
			warnings = append(warnings, strings.TrimSpace(line))
		}
	}
	return warnings
}

// JADXArtifactPath returns the expected jadx output directory for a workdir.
func JADXArtifactPath(workdir string) string {
	return filepath.Join(workdir, "jadx")
}
