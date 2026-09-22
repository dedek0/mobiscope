package analyzers

import (
	"context"
	"time"
)

// MockCommandRunner is a test double for CommandRunner.
type MockCommandRunner struct {
	Result *CommandResult
	Err    error
	Calls  []MockCall
}

type MockCall struct {
	Name    string
	Args    []string
	Timeout time.Duration
	Env     []string
}

func (m *MockCommandRunner) Run(_ context.Context, name string, args []string, timeout time.Duration, env []string) (*CommandResult, error) {
	m.Calls = append(m.Calls, MockCall{
		Name:    name,
		Args:    args,
		Timeout: timeout,
		Env:     env,
	})
	if m.Err != nil {
		return m.Result, m.Err
	}
	return m.Result, nil
}

// NewMockRunner creates a runner that returns the given stdout/stderr/exitCode.
func NewMockRunner(stdout, stderr string, exitCode int) *MockCommandRunner {
	return &MockCommandRunner{
		Result: &CommandResult{
			Stdout:   stdout,
			Stderr:   stderr,
			ExitCode: exitCode,
			Duration: 100 * time.Millisecond,
		},
	}
}

// NewFailingRunner creates a runner that returns an error.
func NewFailingRunner(err error) *MockCommandRunner {
	return &MockCommandRunner{
		Result: &CommandResult{
			Stderr:   err.Error(),
			ExitCode: 1,
			Duration: 50 * time.Millisecond,
		},
		Err: err,
	}
}

// Ensure MockCommandRunner implements CommandRunner.
var _ CommandRunner = (*MockCommandRunner)(nil)

// Ensure Analyzer interface is satisfied at compile time.
var (
	_ Analyzer = (*APKTool)(nil)
	_ Analyzer = (*JADX)(nil)
)
