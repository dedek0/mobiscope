package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/dedek0/mobiscope/internal/utils"
)

const (
	apktoolBinary  = "apktool"
	apktoolTimeout = 10 * time.Minute
)

// APKToolConfig holds configuration for the APKTool analyzer.
type APKToolConfig struct {
	NoRes bool
}

// APKTool implements the Analyzer interface for apktool.
type APKTool struct {
	cfg    APKToolConfig
	runner CommandRunner
}

// NewAPKTool creates a new APKTool analyzer.
func NewAPKTool(cfg APKToolConfig) *APKTool {
	return &APKTool{cfg: cfg, runner: &DefaultCommandRunner{}}
}

// NewAPKToolWithRunner creates an APKTool with a custom runner (for testing).
func NewAPKToolWithRunner(cfg APKToolConfig, runner CommandRunner) *APKTool {
	return &APKTool{cfg: cfg, runner: runner}
}

func (a *APKTool) Name() string { return apktoolBinary }

func (a *APKTool) Available() error {
	return CheckBinary(apktoolBinary)
}

func (a *APKTool) Run(ctx context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()

	result := models.ToolResult{
		ToolName:  a.Name(),
		Version:   ParseVersion(apktoolBinary),
		StartedAt: start,
	}

	outDir := filepath.Join(workdir, "apktool")

	args := []string{"d", "-f", "-o", outDir}
	if a.cfg.NoRes {
		args = append(args, "-r")
	}
	args = append(args, "--", target)

	cmdResult, err := a.runner.Run(ctx, apktoolBinary, args, apktoolTimeout, nil)
	result.Duration = time.Since(start)

	if cmdResult != nil {
		result.ExitCode = cmdResult.ExitCode
		outputData := map[string]string{
			"stdout": cmdResult.Stdout,
			"stderr": cmdResult.Stderr,
		}
		result.Output, _ = json.Marshal(outputData)
	}

	if err != nil {
		result.Error = err.Error()
		return result, fmt.Errorf("apktool execution failed: %w", err)
	}

	if err := validateOutputDir(outDir); err != nil {
		result.Error = err.Error()
		return result, err
	}

	return result, nil
}

func validateOutputDir(dir string) error {
	if !utils.Exists(dir) {
		return fmt.Errorf("apktool output directory does not exist: %s", dir)
	}

	empty, err := utils.IsDirEmpty(dir)
	if err != nil {
		return fmt.Errorf("checking apktool output: %w", err)
	}
	if empty {
		return fmt.Errorf("apktool output directory is empty: %s", dir)
	}

	return nil
}

// APKToolArtifactPath returns the expected apktool output directory for a workdir.
func APKToolArtifactPath(workdir string) string {
	return filepath.Join(workdir, "apktool")
}
