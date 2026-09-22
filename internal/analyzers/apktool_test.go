package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPKTool_Name(t *testing.T) {
	a := NewAPKTool(APKToolConfig{})
	assert.Equal(t, "apktool", a.Name())
}

func TestAPKTool_Run_Success(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "apktool")
	require.NoError(t, os.MkdirAll(outDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(outDir, "AndroidManifest.xml"), []byte("<manifest/>"), 0o600))

	runner := NewMockRunner("decompiled", "", 0)
	a := NewAPKToolWithRunner(APKToolConfig{}, runner)

	result, err := a.Run(context.Background(), "test.apk", dir)
	require.NoError(t, err)
	assert.Equal(t, "apktool", result.ToolName)
	assert.Equal(t, 0, result.ExitCode)
	assert.Empty(t, result.Error)

	assert.Len(t, runner.Calls, 1)
	assert.Equal(t, "apktool", runner.Calls[0].Name)
	assert.Contains(t, runner.Calls[0].Args, "d")
}

func TestAPKTool_Run_WithNoRes(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "apktool")
	require.NoError(t, os.MkdirAll(outDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(outDir, "file"), []byte("x"), 0o600))

	runner := NewMockRunner("", "", 0)
	a := NewAPKToolWithRunner(APKToolConfig{NoRes: true}, runner)

	_, err := a.Run(context.Background(), "test.apk", dir)
	require.NoError(t, err)

	assert.Contains(t, runner.Calls[0].Args, "-r")
}

func TestAPKTool_Run_ExecutionError(t *testing.T) {
	dir := t.TempDir()
	runner := NewFailingRunner(fmt.Errorf("execution failed"))
	a := NewAPKToolWithRunner(APKToolConfig{}, runner)

	result, err := a.Run(context.Background(), "test.apk", dir)
	assert.Error(t, err)
	assert.NotEmpty(t, result.Error)
}

func TestAPKTool_Run_EmptyOutputDir(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "apktool")
	require.NoError(t, os.MkdirAll(outDir, 0o755))

	runner := NewMockRunner("", "", 0)
	a := NewAPKToolWithRunner(APKToolConfig{}, runner)

	result, err := a.Run(context.Background(), "test.apk", dir)
	assert.Error(t, err)
	assert.Contains(t, result.Error, "empty")
}

func TestAPKTool_Run_NoOutputDir(t *testing.T) {
	dir := t.TempDir()

	runner := NewMockRunner("", "", 0)
	a := NewAPKToolWithRunner(APKToolConfig{}, runner)

	result, err := a.Run(context.Background(), "test.apk", dir)
	assert.Error(t, err)
	assert.Contains(t, result.Error, "does not exist")
}

func TestAPKTool_Run_OutputJSON(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "apktool")
	require.NoError(t, os.MkdirAll(outDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(outDir, "f"), []byte("x"), 0o600))

	runner := NewMockRunner("out content", "err content", 0)
	a := NewAPKToolWithRunner(APKToolConfig{}, runner)

	result, err := a.Run(context.Background(), "test.apk", dir)
	require.NoError(t, err)

	var output map[string]string
	require.NoError(t, json.Unmarshal(result.Output, &output))
	assert.Equal(t, "out content", output["stdout"])
	assert.Equal(t, "err content", output["stderr"])
}

func TestAPKTool_Run_NonZeroExit(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "apktool")
	require.NoError(t, os.MkdirAll(outDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(outDir, "f"), []byte("x"), 0o600))

	runner := NewMockRunner("", "some error", 2)
	a := NewAPKToolWithRunner(APKToolConfig{}, runner)

	result, err := a.Run(context.Background(), "test.apk", dir)
	require.NoError(t, err)
	assert.Equal(t, 2, result.ExitCode)
}

func TestAPKToolArtifactPath(t *testing.T) {
	assert.Equal(t, "/work/session/apktool", APKToolArtifactPath("/work/session"))
}

func TestCheckBinary_Found(t *testing.T) {
	err := CheckBinary("go")
	assert.NoError(t, err)
}

func TestCheckBinary_NotFound(t *testing.T) {
	err := CheckBinary("nonexistent_binary_12345")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in PATH")
}

func TestParseVersion(t *testing.T) {
	v := ParseVersion("ls")
	assert.NotEqual(t, "unknown", v)
	assert.NotEmpty(t, v)
}

func TestParseVersion_Unknown(t *testing.T) {
	v := ParseVersion("nonexistent_binary_12345")
	assert.Equal(t, "unknown", v)
}

func TestCommandResult_Fields(t *testing.T) {
	r := &CommandResult{
		Stdout:   "out",
		Stderr:   "err",
		ExitCode: 42,
		Duration: time.Second,
	}
	assert.Equal(t, "out", r.Stdout)
	assert.Equal(t, "err", r.Stderr)
	assert.Equal(t, 42, r.ExitCode)
	assert.Equal(t, time.Second, r.Duration)
}

func TestDefaultCommandRunner_InvalidBinary(t *testing.T) {
	r := &DefaultCommandRunner{}
	_, err := r.Run(context.Background(), "/nonexistent/binary/12345", nil, 0, nil)
	assert.Error(t, err)
}

func TestDefaultCommandRunner_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timeout test in short mode")
	}
	r := &DefaultCommandRunner{}
	_, err := r.Run(context.Background(), "sleep", []string{"10"}, 50*time.Millisecond, nil)
	assert.Error(t, err)
}
