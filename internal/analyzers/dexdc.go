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

// defaultDEXDCExcludes keep the optional backend from decompiling framework
// and large vendor trees. The native inventory/DEX scanners already cover
// their strings, and a full tree of a large APK can exceed the memory budget.
var defaultDEXDCExcludes = []string{
	"android.",
	"androidx.",
	"kotlin.",
	"kotlinx.",
	"com.google.",
	"com.squareup.",
	"com.bumptech.",
	"com.crashlytics.",
	"com.adjust.",
	"com.appsflyer.",
	"com.onesignal.",
	"com.segment.",
	"com.stripe.",
	"com.datadog.",
	"com.bugsnag.",
	"com.fasterxml.",
	"com.airbnb.",
	"com.facebook.",
	"io.flutter.",
	"io.grpc.",
	"io.reactivex.",
	"io.sentry.",
	"okhttp3.",
	"okio.",
	"retrofit2.",
	"org.apache.",
	"org.bouncycastle.",
	"org.jetbrains.",
	"org.json.",
	"org.intellij.",
	"javax.",
	"dagger.",
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
	excludes := d.cfg.Excludes
	if excludes == nil {
		excludes = defaultDEXDCExcludes
	}
	for _, exclude := range excludes {
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
