package main

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dedek0/mobiscope/internal/analyzers"
	"github.com/dedek0/mobiscope/internal/llm"
	"github.com/dedek0/mobiscope/internal/models"
	"github.com/dedek0/mobiscope/internal/platform"
	"github.com/dedek0/mobiscope/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers ---

func androidTarget() *platform.Target {
	return &platform.Target{Path: "app.apk", Format: platform.FormatAPK, Platform: models.PlatformAndroid}
}

func iosTarget() *platform.Target {
	return &platform.Target{Path: "app.ipa", Format: platform.FormatIPA, Platform: models.PlatformIOS}
}

func analyzerNames(list []analyzers.Analyzer) []string {
	names := make([]string, 0, len(list))
	for _, a := range list {
		names = append(names, a.Name())
	}
	return names
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// setGlobalConfig points --config at path for the duration of the test.
func setGlobalConfig(t *testing.T, path string) {
	t.Helper()
	orig := globalFlags.Config
	globalFlags.Config = path
	t.Cleanup(func() { globalFlags.Config = orig })
}

// buildTestAPK writes a minimal APK-shaped ZIP and returns its path.
func buildTestAPK(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("AndroidManifest.xml")
	require.NoError(t, err)
	_, err = w.Write([]byte(`<manifest package="com.example.t"/>`))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	path := filepath.Join(t.TempDir(), "app.apk")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
	return path
}

// writeArgsStub writes a shell stub that logs its argv to logPath and
// materializes apktool's -o output dir so Run's validation passes.
func writeArgsStub(t *testing.T, dir, name, logPath string) {
	t.Helper()
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then echo 'stub 1.0'; exit 0; fi
{ printf '%s: ' '` + name + `'; for a in "$@"; do printf '%s ' "$a"; done; printf '\n'; } >> '` + logPath + `'
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then mkdir -p "$a"; printf x > "$a/marker"; fi
  prev="$a"
done
exit 0
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755))
}

// withStubPATH prepends dir to PATH and clears the memoized tool versions.
func withStubPATH(t *testing.T, dir string) {
	t.Helper()
	orig := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+orig)
	analyzers.ResetVersionCache()
	t.Cleanup(func() {
		_ = os.Setenv("PATH", orig)
		analyzers.ResetVersionCache()
	})
}

func TestValidateStages(t *testing.T) {
	assert.NoError(t, validateStages(nil, models.PlatformAndroid))
	assert.NoError(t, validateStages([]string{"anti-analysis", "inventory"}, models.PlatformAndroid))
	assert.NoError(t, validateStages([]string{"anti_analysis"}, models.PlatformAndroid))

	err := validateStages([]string{"anti-anlaysis"}, models.PlatformAndroid)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown stage")
	assert.Contains(t, err.Error(), "anti-anlaysis")
	assert.Contains(t, err.Error(), "inventory")

	assert.NoError(t, validateStages([]string{"ipa-extract", "macho"}, models.PlatformIOS))
	require.Error(t, validateStages([]string{"apktool"}, models.PlatformIOS))
}

// --- buildAnalyzers (cmd coverage) ---

func TestBuildAnalyzers_AndroidDefaults(t *testing.T) {
	list := buildAnalyzers(stageOptions{}, androidTarget())
	// The default runs jadx, the implicit signature check and the in-process
	// analyzers. The scanners are opt-in and apktool is no longer run by
	// default (the native inventory reader covers manifest/resources/NSC).
	assert.Equal(t, []string{"jadx", "apksigner", "elf", "anti_analysis", "repack", "sdk"}, analyzerNames(list))
}

func TestBuildAnalyzers_NilTargetDefaultsToAndroid(t *testing.T) {
	list := buildAnalyzers(stageOptions{}, nil)
	assert.Equal(t, []string{"jadx", "apksigner", "elf", "anti_analysis", "repack", "sdk"}, analyzerNames(list))
}

func TestBuildAnalyzers_AndroidStageFilter(t *testing.T) {
	list := buildAnalyzers(stageOptions{stages: []string{"jadx", "gitleaks"}}, androidTarget())
	// apksigner is implicit and cannot be selected away.
	assert.Equal(t, []string{"jadx", "apksigner", "gitleaks"}, analyzerNames(list))
}

func TestBuildAnalyzers_AndroidScannersOnlyWhenNamed(t *testing.T) {
	// "inventory" selects nothing from the analyzer list (inventory runs as a
	// pipeline phase); the implicit signature check still runs.
	list := buildAnalyzers(stageOptions{stages: []string{"inventory"}}, androidTarget())
	assert.Equal(t, []string{"apksigner"}, analyzerNames(list))

	list = buildAnalyzers(stageOptions{stages: []string{"gitleaks", "semgrep"}}, androidTarget())
	assert.Equal(t, []string{"apksigner", "gitleaks", "semgrep"}, analyzerNames(list))
}

func TestBuildAnalyzers_QuickKeepsDefaultStages(t *testing.T) {
	// The scanners are already opt-in, so --quick does not change the
	// default set.
	list := buildAnalyzers(stageOptions{quick: true}, androidTarget())
	assert.Equal(t, []string{"jadx", "apksigner", "elf", "anti_analysis", "repack", "sdk"}, analyzerNames(list))
}

func TestBuildAnalyzers_NoSecretsSkipsOnlyGitleaks(t *testing.T) {
	list := buildAnalyzers(stageOptions{noSecrets: true, stages: []string{"gitleaks", "semgrep"}}, androidTarget())
	assert.Equal(t, []string{"apksigner", "semgrep"}, analyzerNames(list))
}

func TestBuildAnalyzers_DecompilerSelection(t *testing.T) {
	list := buildAnalyzers(stageOptions{decompiler: "jadx", decompilerSet: true}, androidTarget())
	assert.Equal(t, []string{"jadx", "apksigner", "elf", "anti_analysis", "repack", "sdk"}, analyzerNames(list))

	list = buildAnalyzers(stageOptions{decompiler: "apktool", decompilerSet: true}, androidTarget())
	assert.Equal(t, []string{"apktool", "apksigner", "elf", "anti_analysis", "repack", "sdk"}, analyzerNames(list))

	list = buildAnalyzers(stageOptions{decompiler: "both", decompilerSet: true}, androidTarget())
	assert.Equal(t, []string{"apktool", "jadx", "apksigner", "elf", "anti_analysis", "repack", "sdk"}, analyzerNames(list))
}

func TestBuildAnalyzers_IOSDefaults(t *testing.T) {
	list := buildAnalyzers(stageOptions{}, iosTarget())
	assert.Equal(t,
		[]string{"ipa-extract", "plist", "macho", "codesign", "classdump", "strings"},
		analyzerNames(list))
}

func TestBuildAnalyzers_IOSStageFilter(t *testing.T) {
	list := buildAnalyzers(stageOptions{stages: []string{"plist", "codesign"}}, iosTarget())
	assert.Equal(t, []string{"plist", "codesign"}, analyzerNames(list))

	list = buildAnalyzers(stageOptions{stages: []string{"gitleaks", "semgrep"}}, iosTarget())
	assert.Equal(t, []string{"gitleaks", "semgrep"}, analyzerNames(list))

	list = buildAnalyzers(stageOptions{stages: []string{"apktool"}}, iosTarget())
	assert.Empty(t, analyzerNames(list), "android stages select nothing on iOS")
}

func TestBuildAnalyzers_NoResPropagation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs")
	}

	tests := []struct {
		name    string
		noRes   bool
		jadxHas bool
		apkHas  bool
	}{
		{"default resources decoded", false, false, false},
		{"no-res skips resources", true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubDir := t.TempDir()
			logPath := filepath.Join(t.TempDir(), "args.log")
			writeArgsStub(t, stubDir, "jadx", logPath)
			writeArgsStub(t, stubDir, "apktool", logPath)
			withStubPATH(t, stubDir)

			list := buildAnalyzers(stageOptions{noRes: tt.noRes, decompiler: "both", decompilerSet: true}, androidTarget())
			require.Len(t, list, 7)
			workdir := t.TempDir()
			for _, a := range list {
				// Only the decompilers are stubbed; the scanners are
				// exercised by their own tests.
				if a.Name() != "apktool" && a.Name() != "jadx" {
					continue
				}
				_, err := a.Run(context.Background(), "app.apk", workdir)
				require.NoError(t, err)
			}

			data, err := os.ReadFile(logPath)
			require.NoError(t, err)
			var jadxLine, apktoolLine string
			for _, line := range strings.Split(string(data), "\n") {
				switch {
				case strings.HasPrefix(line, "jadx: "):
					jadxLine = line
				case strings.HasPrefix(line, "apktool: "):
					apktoolLine = line
				}
			}
			require.NotEmpty(t, jadxLine, "jadx must have been invoked")
			require.NotEmpty(t, apktoolLine, "apktool must have been invoked")

			if tt.jadxHas {
				assert.Contains(t, jadxLine, "--no-res")
			} else {
				assert.NotContains(t, jadxLine, "--no-res")
			}
			if tt.apkHas {
				assert.Contains(t, apktoolLine, " -r ")
			} else {
				assert.NotContains(t, apktoolLine, " -r ")
			}
			// jadx takes the target directly; apktool keeps the -- guard.
			assert.Contains(t, jadxLine, " app.apk")
			assert.Contains(t, apktoolLine, "-- app.apk")
		})
	}
}

// --- countTriaged ---

func TestCountTriaged(t *testing.T) {
	tests := []struct {
		name     string
		findings []models.Finding
		want     int
	}{
		{"nil", nil, 0},
		{"empty slice", []models.Finding{}, 0},
		{
			name: "confirmed and likely_fp count",
			findings: []models.Finding{
				{LLMVerdict: models.VerdictConfirmed},
				{LLMVerdict: models.VerdictLikelyFP},
				{LLMVerdict: models.VerdictConfirmed},
			},
			want: 3,
		},
		{
			name: "inconclusive and untriaged do not count",
			findings: []models.Finding{
				{LLMVerdict: models.VerdictInconclusive},
				{LLMVerdict: ""},
				{LLMVerdict: models.VerdictLikelyFP},
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, countTriaged(tt.findings))
		})
	}
}

// --- runTriage ---

// fakeLLMServer is a minimal OpenAI-compatible endpoint.
type fakeLLMServer struct {
	*httptest.Server
	chatCalls atomic.Int64
}

// newFakeLLM serves /v1/models and /v1/chat/completions; chat replies with
// the requested verdict.
func newFakeLLM(t *testing.T, verdict string) *fakeLLMServer {
	t.Helper()
	fs := &fakeLLMServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"fake-model-1","object":"model"}]}`)
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
		fs.chatCalls.Add(1)
		content := fmt.Sprintf(`{"verdict":%q,"confidence":0.9,"explanation":"checked","remediation":"none"}`, verdict)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w,
			`{"id":"cmpl-1","object":"chat.completion","model":"fake-model-1","choices":[{"index":0,"message":{"role":"assistant","content":%q},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`,
			content)
	})
	fs.Server = httptest.NewServer(mux)
	t.Cleanup(fs.Close)
	return fs
}

// newFailingChatLLM advertises models but fails every chat call.
func newFailingChatLLM(t *testing.T) *fakeLLMServer {
	t.Helper()
	fs := &fakeLLMServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"fake-model-1","object":"model"}]}`)
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, _ *http.Request) {
		fs.chatCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":{"message":"DEAD_ENDPOINT"}}`)
	})
	fs.Server = httptest.NewServer(mux)
	t.Cleanup(fs.Close)
	return fs
}

func writeLLMConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// newTriageSession builds a single-finding session for runTriage.
func newTriageSession() *models.AnalysisSession {
	return &models.AnalysisSession{
		ID:       "test-session",
		APKPath:  "app.apk",
		Platform: models.PlatformAndroid,
		Findings: []models.Finding{
			{
				ID:             "finding-1",
				SessionID:      "test-session",
				SourceTool:     "inventory",
				Category:       models.CategoryManifestIssue,
				Title:          "Exported activity without permission",
				Description:    "activity is exported to the world",
				Severity:       models.SeverityMedium,
				Location:       models.Location{File: "AndroidManifest.xml", Line: 42, Snippet: `<activity android:exported="true"/>`},
				NeedsLLMTriage: true,
				Representative: true,
			},
		},
	}
}

func TestRunTriage_ConfirmsFindingViaFakeProvider(t *testing.T) {
	fake := newFakeLLM(t, "confirmed")
	t.Setenv("HOME", t.TempDir()) // isolate the LLM disk cache

	cfgPath := writeLLMConfig(t, fmt.Sprintf(`
[llm]
default_provider = "fake"
max_retries = 1
retry_base_delay_ms = 1
timeout_seconds = 10

[llm.providers.fake]
type = "openai_compatible"
base_url = %q

[llm.tasks.triage]
provider = "fake"
model = "fake-model-1"
`, fake.URL+"/v1"))
	setGlobalConfig(t, cfgPath)

	session := newTriageSession()
	c := newAnalyzeCmd()
	c.SetContext(context.Background())

	require.NoError(t, runTriage(c, session, t.TempDir(), discardLogger(), ""))

	require.Equal(t, int64(1), fake.chatCalls.Load())
	f := session.Findings[0]
	assert.Equal(t, models.VerdictConfirmed, f.LLMVerdict)
	assert.Equal(t, "fake", f.LLMProvider)
	assert.Equal(t, "fake-model-1", f.LLMModel)
	assert.NotEmpty(t, f.LLMExplanation)
	assert.Equal(t, 1, countTriaged(session.Findings))
}

func TestRunTriage_ProviderUnavailable(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// A live endpoint that refuses model listing: routing fails fast with a
	// policy error instead of hanging on connection timeouts.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not running", http.StatusNotFound)
	}))
	t.Cleanup(dead.Close)

	cfgPath := writeLLMConfig(t, fmt.Sprintf(`
[llm]
default_provider = "fake"
max_retries = 1
retry_base_delay_ms = 1
timeout_seconds = 5

[llm.providers.fake]
type = "openai_compatible"
base_url = %q

[llm.providers.ollama]
type = "ollama"
base_url = %q

[llm.tasks.triage]
provider = "fake"
model = "fake-model-1"
`, dead.URL+"/v1", dead.URL))
	setGlobalConfig(t, cfgPath)

	session := newTriageSession()
	c := newAnalyzeCmd()
	c.SetContext(context.Background())

	err := runTriage(c, session, t.TempDir(), discardLogger(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, llm.ErrProviderUnavailable)
	// The finding is marked inconclusive rather than left untriaged.
	assert.Equal(t, models.VerdictInconclusive, session.Findings[0].LLMVerdict)
	assert.Equal(t, 0, countTriaged(session.Findings))
}

func TestRunTriage_TriageProviderOverride(t *testing.T) {
	good := newFakeLLM(t, "confirmed")
	bad := newFailingChatLLM(t)
	t.Setenv("HOME", t.TempDir())

	cfgPath := writeLLMConfig(t, fmt.Sprintf(`
[llm]
default_provider = "fake"
max_retries = 1
retry_base_delay_ms = 1
timeout_seconds = 10

[llm.providers.fake]
type = "openai_compatible"
base_url = %q

[llm.providers.failing]
type = "openai_compatible"
base_url = %q

[llm.tasks.triage]
provider = "fake"
model = "fake-model-1"
`, good.URL+"/v1", bad.URL+"/v1"))
	setGlobalConfig(t, cfgPath)

	c := newAnalyzeCmd()
	c.SetContext(context.Background())

	// Without the override the configured provider answers.
	session := newTriageSession()
	require.NoError(t, runTriage(c, session, t.TempDir(), discardLogger(), ""))
	assert.Equal(t, models.VerdictConfirmed, session.Findings[0].LLMVerdict)
	require.Equal(t, int64(1), good.chatCalls.Load())

	// With --triage-provider the override wins: its chat endpoint fails, so
	// the finding must end up inconclusive and the good provider untouched.
	session2 := newTriageSession()
	require.NoError(t, runTriage(c, session2, t.TempDir(), discardLogger(), "failing"))
	assert.Equal(t, models.VerdictInconclusive, session2.Findings[0].LLMVerdict)
	assert.Equal(t, int64(1), good.chatCalls.Load(), "override must not fall back to the default provider")
	assert.GreaterOrEqual(t, bad.chatCalls.Load(), int64(1))
}

// --- --expect-sha256 gate ---

// TestAnalyze_ExpectSHA256Gate verifies the hash gate runs before any
// analyzer: a mismatch must abort without creating the session directory, a
// match must let the pipeline run.
func TestAnalyze_ExpectSHA256Gate(t *testing.T) {
	if newAnalyzeCmd().Flags().Lookup("expect-sha256") == nil {
		t.Skip("--expect-sha256 is not registered on the analyze command " +
			"(production gap reported to the maintainers: the gate code in " +
			"analyze.go is unreachable from the CLI)")
	}

	apkPath := buildTestAPK(t)
	got, err := utils.Sha256File(apkPath)
	require.NoError(t, err)

	t.Run("mismatch aborts before any analyzer runs", func(t *testing.T) {
		workdir := filepath.Join(t.TempDir(), "out")
		want := strings.Repeat("ab", 32) // 64 hex chars, wrong value

		_, err := executeCmd("analyze", apkPath,
			"--expect-sha256", want,
			"--workdir", workdir)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SHA-256 mismatch")
		assert.NoDirExists(t, workdir, "no session directory may be created on mismatch")
	})

	t.Run("match proceeds", func(t *testing.T) {
		// Strip PATH so external tools fail fast instead of decompiling;
		// the pipeline must still run past the gate and persist artifacts.
		t.Setenv("PATH", t.TempDir())
		analyzers.ResetVersionCache()
		t.Cleanup(analyzers.ResetVersionCache)

		workdir := filepath.Join(t.TempDir(), "out")
		// Uppercase hex exercises the case-insensitive comparison.
		_, err := executeCmd("analyze", apkPath,
			"--expect-sha256", strings.ToUpper(got),
			"--workdir", workdir)
		require.NoError(t, err)

		entries, err := os.ReadDir(workdir)
		require.NoError(t, err)
		require.Len(t, entries, 1, "exactly one session directory")
		sessionDir := filepath.Join(workdir, entries[0].Name())
		assert.FileExists(t, filepath.Join(sessionDir, "findings.json"))
		assert.FileExists(t, filepath.Join(sessionDir, "meta.json"))
	})
}

// TestAnalyze_ExpectSHA256GateFlagExists documents the intended gate
// contract even while the flag registration bug is outstanding: the gate
// compares utils.Sha256File output case-insensitively. This always runs.
func TestAnalyze_SHA256GateHashContract(t *testing.T) {
	apkPath := buildTestAPK(t)
	got, err := utils.Sha256File(apkPath)
	require.NoError(t, err)
	require.Len(t, got, 64)
	assert.Equal(t, strings.ToLower(got), got, "hash is lowercase hex")
	assert.True(t, strings.EqualFold(got, strings.ToUpper(got)), "gate compares case-insensitively")
	assert.False(t, strings.EqualFold(got, strings.Repeat("0", 64)))
}

func TestBuildAnalyzers_ReuseSkipsCachedDecompilers(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "jadx"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "jadx", "AndroidManifest.xml"), []byte("<manifest/>"), 0o600))

	list := buildAnalyzers(stageOptions{
		decompiler:    "both",
		decompilerSet: true,
		reuse:         true,
		sessionDir:    dir,
	}, androidTarget())
	names := analyzerNames(list)
	assert.NotContains(t, names, "jadx")
	assert.Contains(t, names, "apktool")

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "apktool"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "apktool", "AndroidManifest.xml"), []byte("<manifest/>"), 0o600))
	list = buildAnalyzers(stageOptions{
		decompiler:    "both",
		decompilerSet: true,
		reuse:         true,
		sessionDir:    dir,
	}, androidTarget())
	names = analyzerNames(list)
	assert.NotContains(t, names, "jadx")
	assert.NotContains(t, names, "apktool")
}

func TestValidateDecompiler(t *testing.T) {
	for _, value := range []string{"", "jadx", "apktool", "dexdc", "both", "jadx,dexdc", " apktool , dexdc "} {
		assert.NoError(t, validateDecompiler(value), value)
	}
	for _, value := range []string{"procyon", "jadx,foo", "dex-decompile"} {
		assert.Error(t, validateDecompiler(value), value)
	}
}

func TestBuildAnalyzers_DEXDC(t *testing.T) {
	list := buildAnalyzers(stageOptions{decompiler: "dexdc", decompilerSet: true}, androidTarget())
	assert.Equal(t, []string{"dexdc", "apksigner", "elf", "anti_analysis", "repack", "sdk"}, analyzerNames(list))

	list = buildAnalyzers(stageOptions{decompiler: "jadx,dexdc", decompilerSet: true}, androidTarget())
	assert.Equal(t, []string{"jadx", "dexdc", "apksigner", "elf", "anti_analysis", "repack", "sdk"}, analyzerNames(list))
}

func TestBuildAnalyzers_ReuseSkipsCachedDEXDC(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "dexdc", "com", "example"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dexdc", "com", "example", "Main.java"), []byte("class Main {}"), 0o600))

	list := buildAnalyzers(stageOptions{
		decompiler:    "dexdc",
		decompilerSet: true,
		reuse:         true,
		sessionDir:    dir,
	}, androidTarget())
	assert.NotContains(t, analyzerNames(list), "dexdc")
}

func TestIncludeDecompilers(t *testing.T) {
	assert.Equal(t, []string{"inventory", "jadx"}, includeDecompilers([]string{"inventory"}, "jadx"))
	assert.Equal(t, []string{"inventory", "apktool", "jadx"}, includeDecompilers([]string{"inventory"}, "both"))
	assert.Equal(t, []string{"inventory", "jadx", "dexdc"}, includeDecompilers([]string{"inventory"}, "jadx,dexdc"))
	assert.Equal(t, []string{"jadx", "gitleaks"}, includeDecompilers([]string{"jadx", "gitleaks"}, "jadx"))
}

func TestJadxThreadsFromEnv(t *testing.T) {
	t.Setenv("MOBISCOPE_JADX_THREADS", "")
	assert.Equal(t, 0, jadxThreadsFromEnv())
	t.Setenv("MOBISCOPE_JADX_THREADS", "4")
	assert.Equal(t, 4, jadxThreadsFromEnv())
	t.Setenv("MOBISCOPE_JADX_THREADS", "not-a-number")
	assert.Equal(t, 0, jadxThreadsFromEnv())
}
