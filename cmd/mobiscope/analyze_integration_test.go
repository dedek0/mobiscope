//go:build integration

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dedek0/mobiscope/internal/analyzers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakebinPATH prepends testdata/fakebin to PATH and points the stub logging
// file at logPath.
func fakebinPATH(t *testing.T, logPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs")
	}
	fakebin, err := filepath.Abs(filepath.Join("testdata", "fakebin"))
	require.NoError(t, err)

	orig := os.Getenv("PATH")
	t.Setenv("PATH", fakebin+string(os.PathListSeparator)+orig)
	t.Setenv("MOBISCOPE_FAKEBIN_LOG", logPath)
	analyzers.ResetVersionCache()
	t.Cleanup(func() {
		_ = os.Setenv("PATH", orig)
		analyzers.ResetVersionCache()
	})
}

// readStubLog returns the (sorted) tool invocations recorded by the stubs.
func readStubLog(t *testing.T, logPath string) []string {
	t.Helper()
	data, err := os.ReadFile(logPath) //nolint:gosec
	if os.IsNotExist(err) {
		return nil
	}
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

func invokedTools(lines []string) []string {
	var out []string
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) > 0 {
			out = append(out, fields[0])
		}
	}
	return out
}

// TestAnalyzeCLI_DefaultStages runs the full analyze command against the
// fake toolchain and asserts the default Android stage set executes.
func TestAnalyzeCLI_DefaultStages(t *testing.T) {
	apk := buildTestAPK(t)
	logPath := filepath.Join(t.TempDir(), "stub.log")
	fakebinPATH(t, logPath)
	workdir := filepath.Join(t.TempDir(), "out")

	_, err := executeCmd("analyze", apk, "--workdir", workdir)
	require.NoError(t, err)

	tools := invokedTools(readStubLog(t, logPath))
	assert.Contains(t, tools, "apktool")
	assert.Contains(t, tools, "jadx")
	// Default stages never include the scanners.
	assert.NotContains(t, tools, "gitleaks")
	assert.NotContains(t, tools, "semgrep")

	// A session with persisted artifacts exists.
	entries, err := os.ReadDir(workdir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	sessionDir := filepath.Join(workdir, entries[0].Name())
	assert.FileExists(t, filepath.Join(sessionDir, "findings.json"))
	assert.FileExists(t, filepath.Join(sessionDir, "report.md"))
}

// TestAnalyzeCLI_StagesTrimming asserts --stages selects exactly the named
// stages and nothing else.
func TestAnalyzeCLI_StagesTrimming(t *testing.T) {
	apk := buildTestAPK(t)
	logPath := filepath.Join(t.TempDir(), "stub.log")
	fakebinPATH(t, logPath)
	workdir := filepath.Join(t.TempDir(), "out")

	_, err := executeCmd("analyze", apk,
		"--workdir", workdir,
		"--stages", "jadx,gitleaks")
	require.NoError(t, err)

	tools := invokedTools(readStubLog(t, logPath))
	assert.ElementsMatch(t, []string{"jadx", "gitleaks"}, tools)
}

// TestAnalyzeCLI_FailFast asserts --fail-fast aborts the command when a tool
// exits non-zero, while the default continues and completes.
func TestAnalyzeCLI_FailFast(t *testing.T) {
	apk := buildTestAPK(t)
	logPath := filepath.Join(t.TempDir(), "stub.log")
	fakebinPATH(t, logPath)

	t.Run("fail-fast aborts", func(t *testing.T) {
		t.Setenv("FAKE_APKTOOL_EXIT", "2")
		workdir := filepath.Join(t.TempDir(), "out")

		_, err := executeCmd("analyze", apk,
			"--workdir", workdir,
			"--stages", "apktool",
			"--fail-fast")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "fail-fast")
	})

	t.Run("default continues after tool failure", func(t *testing.T) {
		t.Setenv("FAKE_APKTOOL_EXIT", "2")
		workdir := filepath.Join(t.TempDir(), "out")

		_, err := executeCmd("analyze", apk,
			"--workdir", workdir,
			"--stages", "apktool")
		require.NoError(t, err, "without --fail-fast the run completes")

		entries, err := os.ReadDir(workdir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.FileExists(t, filepath.Join(workdir, entries[0].Name(), "meta.json"))
	})
}
