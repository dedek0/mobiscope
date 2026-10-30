package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	dexdcName    = "dexdc"
	dexdcBinary  = "dex-decompile"
	dexdcTimeout = 15 * time.Minute
)

// DEXDCConfig controls the optional androguard/dex-decompiler backend.
type DEXDCConfig struct {
	// Deobf passes --deobf, which renames short/invalid identifiers.
	Deobf bool
	// Excludes are package prefixes passed as --exclude (e.g. "android.").
	Excludes []string
}

// DEXDC wraps androguard/dex-decompiler. It is an optional decompiler: when
// the binary is missing the stage records an error and the pipeline continues.
// jadx remains the reference backend.
type DEXDC struct {
	cfg    DEXDCConfig
	runner CommandRunner
}

func NewDEXDC(cfg DEXDCConfig) *DEXDC {
	return &DEXDC{cfg: cfg, runner: &DefaultCommandRunner{}}
}

func NewDEXDCWithRunner(cfg DEXDCConfig, runner CommandRunner) *DEXDC {
	return &DEXDC{cfg: cfg, runner: runner}
}

func (d *DEXDC) Name() string { return dexdcName }

func (d *DEXDC) Available() error { return CheckBinary(dexdcBinary) }

// Phase marks the analyzer as a decompiler: it produces a tree the scanners
// can read.
func (d *DEXDC) Phase() Phase { return PhaseDecompiler }

func (d *DEXDC) Run(ctx context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  d.Name(),
		Version:   ParseVersion(dexdcBinary),
		StartedAt: start,
	}

	outDir := DEXDCArtifactPath(workdir)
	args := []string{"-i", target, "-d", outDir}
	if d.cfg.Deobf {
		args = append(args, "--deobf")
	}
	for _, exclude := range d.cfg.Excludes {
		args = append(args, "--exclude", exclude)
	}

	cmdResult, err := d.runner.Run(ctx, dexdcBinary, args, dexdcTimeout, nil)
	result.Duration = time.Since(start)
	if cmdResult != nil {
		result.ExitCode = cmdResult.ExitCode
		result.Output, _ = json.Marshal(map[string]string{
			keyStdout: cmdResult.Stdout,
			keyStderr: cmdResult.Stderr,
		})
	}
	if err != nil {
		result.Error = err.Error()
		return result, fmt.Errorf("dexdc execution failed: %w", err)
	}
	if err := validateOutputDir(outDir); err != nil {
		result.Error = err.Error()
		return result, err
	}
	return result, nil
}

// DEXDCArtifactPath returns the dexdc output directory for a workdir.
func DEXDCArtifactPath(workdir string) string {
	return filepath.Join(workdir, dexdcName)
}
