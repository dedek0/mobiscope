package analyzers

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withMockBinaries prepends dir to PATH so analyzer Available()/ParseVersion
// resolve the mock toolchain. Restores PATH on cleanup.
func withMockBinaries(t *testing.T, dir string) {
	t.Helper()
	orig := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+orig)
	t.Cleanup(func() { _ = os.Setenv("PATH", orig) })
}

// writeMockTool writes an executable shell stub that echoes a fixed version
// and exits with the requested code.
func writeMockTool(t *testing.T, dir, name, version string, exitCode int) {
	t.Helper()
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo '" + version + "'; exit 0; fi\nexit " + itoa(exitCode) + "\n"
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(script), 0o755))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

func TestMockToolchain_AvailableAndVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs")
	}
	dir := t.TempDir()
	writeMockTool(t, dir, "jadx", "jadx 1.5.1", 0)
	writeMockTool(t, dir, "apktool", "2.11.1", 0)
	writeMockTool(t, dir, "gitleaks", "8.24.3", 0)
	writeMockTool(t, dir, "semgrep", "1.127.1", 0)
	writeMockTool(t, dir, "apksigner", "0.9", 0)
	withMockBinaries(t, dir)

	assert.NoError(t, CheckBinary("jadx"))
	assert.NoError(t, CheckBinary("apktool"))
	assert.NoError(t, CheckBinary("gitleaks"))
	assert.NoError(t, CheckBinary("semgrep"))
	assert.Equal(t, "jadx 1.5.1", ParseVersion("jadx"))
	assert.Equal(t, "2.11.1", ParseVersion("apktool"))
}

func TestMockToolchain_APKToolRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs")
	}
	dir := t.TempDir()
	writeMockTool(t, dir, "apktool", "2.11.1", 0)
	withMockBinaries(t, dir)

	workdir := t.TempDir()
	outDir := filepath.Join(workdir, "apktool")
	require.NoError(t, os.MkdirAll(outDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(outDir, "AndroidManifest.xml"), []byte("<manifest/>"), 0o600))

	a := NewAPKTool(APKToolConfig{})
	res, err := a.Run(context.Background(), "test.apk", workdir)
	require.NoError(t, err)
	assert.Equal(t, 0, res.ExitCode)
	assert.Equal(t, "apktool", res.ToolName)
}

func TestMockToolchain_GitleaksExitCodes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs")
	}
	// Exit 1 = leaks found: success for us.
	dir := t.TempDir()
	writeMockTool(t, dir, "gitleaks", "8.24.3", 1)
	withMockBinaries(t, dir)

	g := NewGitleaks()
	res, err := g.Run(context.Background(), "test.apk", t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, 1, res.ExitCode)

	// Exit 2 = tool failure.
	writeMockTool(t, dir, "gitleaks", "8.24.3", 2)
	res, err = g.Run(context.Background(), "test.apk", t.TempDir())
	require.Error(t, err)
	assert.Equal(t, 2, res.ExitCode)
}

func TestMockToolchain_AllowlistRejectsUnknown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs")
	}
	dir := t.TempDir()
	writeMockTool(t, dir, "eviltool", "1.0", 0)
	withMockBinaries(t, dir)

	r := &DefaultCommandRunner{}
	_, err := r.Run(context.Background(), "eviltool", []string{"--version"}, 0, nil)
	require.ErrorIs(t, err, ErrBinaryNotAllowed)
}

func TestMockToolchain_JADXNoRes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs")
	}
	dir := t.TempDir()
	writeMockTool(t, dir, "jadx", "1.5.1", 0)
	withMockBinaries(t, dir)

	workdir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(workdir, "jadx"), 0o755))

	// Default: resources decoded (no --no-res).
	j := NewJADX(JADXConfig{})
	runner := NewMockRunner("", "", 0)
	j.runner = runner
	_, err := j.Run(context.Background(), "test.apk", workdir)
	require.NoError(t, err)
	assert.NotContains(t, runner.Calls[0].Args, "--no-res")

	// --no-res: flag present.
	j2 := NewJADXWithRunner(JADXConfig{NoRes: true}, runner)
	_, err = j2.Run(context.Background(), "test.apk", workdir)
	require.NoError(t, err)
	assert.Contains(t, runner.Calls[1].Args, "--no-res")
}
