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

// Phase describes when an analyzer runs relative to the decompilers.
type Phase int

const (
	// PhaseScanner is an analyzer that reads decompiler output.
	PhaseScanner Phase = iota
	// PhaseDecompiler is an analyzer that produces the tree the other stages
	// read.
	PhaseDecompiler
	// PhaseIndependent is an analyzer that reads the target artifact
	// directly and does not depend on decompiler output. It runs
	// concurrently with the decompilers.
	PhaseIndependent
)

// PhasedAnalyzer is an optional interface an Analyzer can implement to
// declare which pipeline phase it belongs to. Analyzers that do not
// implement it are treated as scanners, so a new stage is never silently
// dropped from the run.
type PhasedAnalyzer interface {
	Phase() Phase
}

// PhaseOf reports the phase an analyzer belongs to, defaulting to scanner.
func PhaseOf(a Analyzer) Phase {
	if p, ok := a.(PhasedAnalyzer); ok {
		return p.Phase()
	}
	return PhaseScanner
}

// SourceRoot returns the scan root for a session: jadx output when present,
// then apktool output (apktool-only runs such as `--stages apktool,...`),
// then the session directory itself. Scanners, the manifest reader and the
// inventory all resolve through this helper so they agree on one root.
func SourceRoot(workdir string) string {
	for _, dir := range []string{JADXArtifactPath(workdir), APKToolArtifactPath(workdir), workdir} {
		if dirExists(dir) {
			return dir
		}
	}
	return workdir
}

// CommandResult holds the output of an executed command.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
	// TimedOut is set when the command was killed by the runner's deadline
	// or by context cancellation.
	TimedOut bool
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
	apktoolBinary:   {},
	jadxBinary:      {},
	gitleaksBinary:  {},
	semgrepBinary:   {},
	"java":          {},
	apksignerBinary: {},
}

// ErrBinaryNotAllowed is returned when a command name is not on the allowlist.
var ErrBinaryNotAllowed = errors.New("binary not in allowlist")

// isAllowedBinary reports whether a bare command name is on the allowlist.
// Only bare names are accepted: a name carrying a path separator is rejected
// so a caller cannot point the runner at an arbitrary file that merely
// shares an allowed base name.
func isAllowedBinary(name string) bool {
	if name == "" || filepath.Base(name) != name {
		return false
	}
	_, ok := allowedBinaries[name]
	return ok
}

// resolveAllowedBinary validates a command name against the allowlist and
// resolves it through PATH, returning the absolute path to execute.
func resolveAllowedBinary(name string) (string, error) {
	if !isAllowedBinary(name) {
		return "", fmt.Errorf("%w: %s", ErrBinaryNotAllowed, name)
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found in PATH: %w", name, err)
	}
	return path, nil
}

// maxToolOutputBytes caps how much stdout/stderr is buffered from an
// external tool. Chatty decompilers emit tens of megabytes and the buffer
// is embedded verbatim in session.json.
const maxToolOutputBytes = 4 << 20

// toolWaitDelay bounds how long Run waits for the output pipes to close after
// the process was killed. Without it a grandchild that inherited the pipe
// (semgrep-core under semgrep, for instance) keeps the pipe open and the
// timeout never fires.
const toolWaitDelay = 5 * time.Second

// cappedBuffer is a bytes.Buffer that stops growing past a limit and records
// that output was dropped.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.buf.Len() < c.limit {
		n := c.limit - c.buf.Len()
		if n > len(p) {
			n = len(p)
		}
		c.buf.Write(p[:n])
		if len(p) > n {
			c.truncated = true
		}
		return len(p), nil
	}
	c.truncated = true
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	if c.truncated {
		return c.buf.String() + "\n[output truncated]"
	}
	return c.buf.String()
}

func (r *DefaultCommandRunner) Run(ctx context.Context, name string, args []string, timeout time.Duration, env []string) (*CommandResult, error) {
	path, err := resolveAllowedBinary(name)
	if err != nil {
		return nil, err
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, path, args...) //nolint:gosec // G204: path is resolved from the allowlist above
	if len(env) > 0 {
		cmd.Env = append(cmd.Environ(), env...)
	}
	cmd.WaitDelay = toolWaitDelay

	var stdout, stderr cappedBuffer
	stdout.limit = maxToolOutputBytes
	stderr.limit = maxToolOutputBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	runErr := cmd.Run()
	duration := time.Since(start)

	result := &CommandResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: duration,
	}

	if runErr != nil {
		if ctx.Err() != nil {
			result.TimedOut = true
			return result, fmt.Errorf("command %s timed out or cancelled: %w", name, ctx.Err())
		}
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			return result, &ErrExit{Name: name, Code: result.ExitCode}
		}
		return result, fmt.Errorf("executing %s: %w", name, runErr)
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

// versionProbeTimeout bounds the `<binary> --version` probe.
const versionProbeTimeout = 10 * time.Second

// versionCache memoizes `binary --version` output per process so every
// analyzer Run does not spawn an extra subprocess.
var (
	versionMu    sync.Mutex
	versionCache = map[string]string{}
)

// ResetVersionCache clears the memoized binary versions. Tests that swap
// the toolchain on PATH must call this or they will see stale versions.
func ResetVersionCache() {
	versionMu.Lock()
	versionCache = map[string]string{}
	versionMu.Unlock()
}

// ParseVersion runs `<binary> --version` once per binary and returns the first line.
// The binary must be on the allowlist and the probe is bounded by a timeout so
// a hung or hijacked binary cannot stall the first analyzer of a run.
func ParseVersion(binary string) string {
	versionMu.Lock()
	if v, ok := versionCache[binary]; ok {
		versionMu.Unlock()
		return v
	}
	versionMu.Unlock()

	v := unknownVersion
	if path, err := resolveAllowedBinary(binary); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), versionProbeTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, path, "--version") //nolint:gosec // G204: path is resolved from the allowlist above
		if out, err := cmd.Output(); err == nil {
			v = parseVersionOutput(out)
		}
	}

	versionMu.Lock()
	versionCache[binary] = v
	versionMu.Unlock()
	return v
}

// parseVersionOutput extracts the first non-empty line of a --version probe.
func parseVersionOutput(out []byte) string {
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return unknownVersion
}
