package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func executeCmd(args ...string) (string, error) {
	buf := new(bytes.Buffer)
	cmd := newRootCmd()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

func TestLLMCmd_Help(t *testing.T) {
	out, err := executeCmd("llm", "--help")
	require.NoError(t, err)
	assert.Contains(t, out, "health")
	assert.Contains(t, out, "list")
	assert.Contains(t, out, "detect")
	assert.Contains(t, out, "config")
	assert.Contains(t, out, "test")
	assert.Contains(t, out, "models")
	assert.Contains(t, out, "pull")
}

func TestLLMModelsCmd(t *testing.T) {
	// llm models writes to os.Stdout, so we just verify it doesn't error.
	err := newLLMModelsCmd().Execute()
	assert.NoError(t, err)
}

func TestLLMConfigCmd(t *testing.T) {
	// llm config writes to os.Stdout, so we just verify it doesn't error.
	err := newLLMConfigCmd().Execute()
	assert.NoError(t, err)
}

func TestLLMHealthCmd(t *testing.T) {
	t.Skip("skipping health test (probes take ~30s)")
	err := newLLMHealthCmd().Execute()
	assert.NoError(t, err)
}

func TestVersionCmd(t *testing.T) {
	// Version writes to os.Stdout, just verify no error.
	cmd := newVersionCmd()
	err := cmd.Execute()
	assert.NoError(t, err)
}

func TestRootHelp(t *testing.T) {
	out, err := executeCmd("--help")
	require.NoError(t, err)
	assert.Contains(t, out, "mobiscope")
	assert.Contains(t, out, "analyze")
	assert.Contains(t, out, "llm")
	assert.Contains(t, out, "version")
	assert.Contains(t, out, "--allow-cloud")
	assert.Contains(t, out, "--provider")
}

func TestLLMTestCmd_NoProvider(t *testing.T) {
	t.Skip("skipping test command (requires running provider)")
	err := newLLMTestCmd().Execute()
	assert.Error(t, err)
}

func TestLLMDetectCmd(t *testing.T) {
	// detect writes to os.Stdout and probes endpoints; just verify no panic.
	// This may take a few seconds due to timeouts on unreachable endpoints.
	t.Skip("skipping detect test (probes take ~10s)")
	err := newLLMDetectCmd().Execute()
	assert.NoError(t, err)
}

func TestLLMPullCmd_NoProvider(t *testing.T) {
	t.Skip("skipping pull test (requires running ollama)")
	cmd := newLLMPullCmd()
	cmd.SetArgs([]string{"test-model"})
	err := cmd.Execute()
	assert.Error(t, err)
}

func TestNewRootCmd_HasGlobalFlags(t *testing.T) {
	cmd := newRootCmd()
	assert.NotNil(t, cmd.PersistentFlags().Lookup("provider"))
	assert.NotNil(t, cmd.PersistentFlags().Lookup("allow-cloud"))
}

func TestNewLLMCmd_Subcommands(t *testing.T) {
	cmd := newLLMCmd()
	names := make(map[string]bool)
	for _, sub := range cmd.Commands() {
		names[sub.Name()] = true
	}
	assert.True(t, names["health"])
	assert.True(t, names["list"])
	assert.True(t, names["pull"])
	assert.True(t, names["detect"])
	assert.True(t, names["config"])
	assert.True(t, names["test"])
	assert.True(t, names["models"])
}
