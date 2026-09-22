package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJADX_Name(t *testing.T) {
	a := NewJADX(JADXConfig{})
	assert.Equal(t, "jadx", a.Name())
}

func TestJADX_Run_Success(t *testing.T) {
	runner := NewMockRunner("decompiled", "", 0)
	a := NewJADXWithRunner(JADXConfig{}, runner)

	result, err := a.Run(context.Background(), "test.apk", t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, "jadx", result.ToolName)
	assert.Equal(t, 0, result.ExitCode)

	assert.Len(t, runner.Calls, 1)
	assert.Equal(t, "jadx", runner.Calls[0].Name)
	assert.Contains(t, runner.Calls[0].Args, "--no-res")
}

func TestJADX_Run_WithThreads(t *testing.T) {
	runner := NewMockRunner("", "", 0)
	a := NewJADXWithRunner(JADXConfig{Threads: 4}, runner)

	_, err := a.Run(context.Background(), "test.apk", t.TempDir())
	require.NoError(t, err)

	args := runner.Calls[0].Args
	assert.Contains(t, args, "--threads-count")
	idx := indexOf(args, "--threads-count")
	assert.Equal(t, "4", args[idx+1])
}

func TestJADX_Run_DefaultThreads(t *testing.T) {
	runner := NewMockRunner("", "", 0)
	a := NewJADXWithRunner(JADXConfig{}, runner)

	_, err := a.Run(context.Background(), "test.apk", t.TempDir())
	require.NoError(t, err)

	args := runner.Calls[0].Args
	idx := indexOf(args, "--threads-count")
	assert.Equal(t, fmt.Sprintf("%d", runtime.NumCPU()), args[idx+1])
}

func TestJADX_Run_ExecutionError(t *testing.T) {
	runner := NewFailingRunner(fmt.Errorf("jadx failed"))
	a := NewJADXWithRunner(JADXConfig{}, runner)

	result, err := a.Run(context.Background(), "test.apk", t.TempDir())
	assert.Error(t, err)
	assert.NotEmpty(t, result.Error)
}

func TestJADX_Run_DEXWarnings(t *testing.T) {
	stderr := "WARNING: Failed to load classes.dex\nnormal output\nERROR: dex file corrupted"
	runner := NewMockRunner("", stderr, 0)
	a := NewJADXWithRunner(JADXConfig{}, runner)

	result, err := a.Run(context.Background(), "test.apk", t.TempDir())
	require.NoError(t, err)

	var output map[string]interface{}
	require.NoError(t, json.Unmarshal(result.Output, &output))

	warnings, ok := output["dex_warnings"].([]interface{})
	require.True(t, ok)
	assert.Len(t, warnings, 2)
}

func TestJADX_Run_NoWarnings(t *testing.T) {
	runner := NewMockRunner("", "normal output only", 0)
	a := NewJADXWithRunner(JADXConfig{}, runner)

	result, err := a.Run(context.Background(), "test.apk", t.TempDir())
	require.NoError(t, err)

	var output map[string]interface{}
	require.NoError(t, json.Unmarshal(result.Output, &output))

	warnings := output["dex_warnings"]
	assert.Nil(t, warnings)
}

func TestJADX_Run_OutputJSON(t *testing.T) {
	runner := NewMockRunner("stdout data", "stderr data", 0)
	a := NewJADXWithRunner(JADXConfig{Threads: 2}, runner)

	result, err := a.Run(context.Background(), "test.apk", t.TempDir())
	require.NoError(t, err)

	var output map[string]interface{}
	require.NoError(t, json.Unmarshal(result.Output, &output))
	assert.Equal(t, "stdout data", output["stdout"])
	assert.Equal(t, "stderr data", output["stderr"])
	assert.Equal(t, float64(2), output["threads_used"])
}

func TestJADX_Run_NonZeroExit(t *testing.T) {
	runner := NewMockRunner("", "error", 3)
	a := NewJADXWithRunner(JADXConfig{}, runner)

	result, err := a.Run(context.Background(), "test.apk", t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, 3, result.ExitCode)
}

func TestJADArtifactPath(t *testing.T) {
	assert.Equal(t, "/work/session/jadx", JADXArtifactPath("/work/session"))
}

func TestParseDEXWarnings(t *testing.T) {
	stderr := "WARNING: Failed to load classes.dex\nnormal line\nERROR: dex corrupted\nclean"
	warnings := parseDEXWarnings(stderr)
	assert.Len(t, warnings, 2)
}

func TestParseDEXWarnings_Empty(t *testing.T) {
	assert.Nil(t, parseDEXWarnings(""))
	assert.Nil(t, parseDEXWarnings("no warnings here"))
}

func TestParseDEXWarnings_CaseInsensitive(t *testing.T) {
	stderr := "WARN: dex file issue\nDEX Error occurred"
	warnings := parseDEXWarnings(stderr)
	assert.Len(t, warnings, 2)
}

func TestJADX_NewJADX_ZeroThreads(t *testing.T) {
	a := NewJADX(JADXConfig{Threads: 0})
	assert.Equal(t, runtime.NumCPU(), a.cfg.Threads)
}

func TestJADX_NewJADXWithRunner_ZeroThreads(t *testing.T) {
	runner := NewMockRunner("", "", 0)
	a := NewJADXWithRunner(JADXConfig{Threads: -1}, runner)
	assert.Equal(t, runtime.NumCPU(), a.cfg.Threads)
}

func indexOf(ss []string, s string) int {
	for i, v := range ss {
		if v == s {
			return i
		}
	}
	return -1
}
