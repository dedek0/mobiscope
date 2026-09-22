package analyzers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

// Analyzer defines the interface every external tool wrapper must implement.
type Analyzer interface {
	// Name returns the tool identifier (e.g., "apktool", "jadx").
	Name() string

	// Available checks whether the tool binary is reachable in PATH.
	Available() error

	// Run executes the analysis and returns the tool result.
	// target is the APK path; workdir is the per-session output directory.
	Run(ctx context.Context, target string, workdir string) (models.ToolResult, error)
}

// CommandResult holds the output of an executed command.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

// CommandRunner abstracts command execution for testability.
type CommandRunner interface {
	Run(ctx context.Context, name string, args []string, timeout time.Duration, env []string) (*CommandResult, error)
}

// ErrExit reports that a command exited with a non-zero code. The companion
// CommandResult is always populated so callers can decide which exit codes
// are acceptable (e.g. gitleaks uses 1 for "leaks found").
type ErrExit struct {
	Name string
	Code int
}

func (e *ErrExit) Error() string {
	return fmt.Sprintf("%s exited with code %d", e.Name, e.Code)
}

// DefaultCommandRunner executes real commands.
type DefaultCommandRunner struct{}

// allowedBinaries is the set of external tools the command runner will
// execute. Anything else is rejected so a PATH hijack cannot run arbitrary
// binaries through the analyzer pipeline.
var allowedBinaries = map[string]struct{}{
	apktoolBinary:  {},
	jadxBinary:     {},
	gitleaksBinary: {},
	semgrepBinary:  {},
	"java":         {},
	"apksigner":    {},
}

// ErrBinaryNotAllowed is returned when a command name is not on the allowlist.
var ErrBinaryNotAllowed = errors.New("binary not in allowlist")

func isAllowedBinary(name string) bool {
	base := filepath.Base(name)
	_, ok := allowedBinaries[base]
	return ok
}

func (r *DefaultCommandRunner) Run(ctx context.Context, name string, args []string, timeout time.Duration, env []string) (*CommandResult, error) {
	if !isAllowedBinary(name) {
		return nil, fmt.Errorf("%w: %s", ErrBinaryNotAllowed, name)
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: name is checked against allowBinaries above
	if len(env) > 0 {
		cmd.Env = append(cmd.Environ(), env...)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	result := &CommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: duration,
	}

	if err != nil {
		if ctx.Err() != nil {
			return result, fmt.Errorf("command %s timed out or cancelled: %w", name, ctx.Err())
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			return result, &ErrExit{Name: name, Code: result.ExitCode}
		}
		return nil, fmt.Errorf("executing %s: %w", name, err)
	}

	return result, nil
}

// RunCommand is a convenience wrapper that uses the default runner.
func RunCommand(ctx context.Context, name string, args []string, timeout time.Duration, env []string) (*CommandResult, error) {
	return (&DefaultCommandRunner{}).Run(ctx, name, args, timeout, env)
}

// CheckBinary verifies a binary exists in PATH and returns its version.
func CheckBinary(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%s not found in PATH: %w", name, err)
	}
	return nil
}

// versionCache memoizes `binary --version` output per process so every
// analyzer Run does not spawn an extra subprocess.
var (
	versionMu    sync.Mutex
	versionCache = map[string]string{}
)

// ParseVersion runs `<binary> --version` once per binary and returns the first line.
func ParseVersion(binary string) string {
	versionMu.Lock()
	if v, ok := versionCache[binary]; ok {
		versionMu.Unlock()
		return v
	}
	versionMu.Unlock()

	v := "unknown"
	cmd := exec.CommandContext(context.Background(), binary, "--version") //nolint:gosec // G204: binary name comes from a fixed analyzer allowlist
	if out, err := cmd.Output(); err == nil {
		lines := strings.SplitN(string(out), "\n", 2)
		v = strings.TrimSpace(lines[0])
	}

	versionMu.Lock()
	versionCache[binary] = v
	versionMu.Unlock()
	return v
}
