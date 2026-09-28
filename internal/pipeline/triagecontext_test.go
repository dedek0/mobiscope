package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildTriageContext_Android(t *testing.T) {
	workdir := t.TempDir()
	jadxDir := filepath.Join(workdir, "jadx")
	require.NoError(t, os.MkdirAll(filepath.Join(jadxDir, "res", "xml"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "AndroidManifest.xml"),
		[]byte(`<manifest><application android:debuggable="true"/></manifest>`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "res", "xml", "network_security_config.xml"),
		[]byte(`<network-security-config/>`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "Config.java"),
		[]byte("class Config { String key = \"AKIA123\"; }"), 0o600))

	findings := []models.Finding{{Location: models.Location{File: "Config.java", Line: 1}}}
	codeCtx, manifest := BuildTriageContext(workdir, models.PlatformAndroid, findings)

	assert.Contains(t, manifest, "AndroidManifest.xml")
	assert.Contains(t, manifest, "debuggable")
	assert.Contains(t, manifest, "network-security-config")
	require.Contains(t, codeCtx, "Config.java")
	assert.Contains(t, codeCtx["Config.java"], "AKIA123")
}

func TestBuildTriageContext_IOS(t *testing.T) {
	workdir := t.TempDir()
	bundle := filepath.Join(workdir, "extract", "Payload", "App.app")
	require.NoError(t, os.MkdirAll(bundle, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(bundle, "Info.plist"),
		[]byte("plistdata"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(bundle, "entitlements.plist"),
		[]byte("get-task-allow"), 0o600))

	findings := []models.Finding{{Location: models.Location{File: "App"}}}
	codeCtx, manifest := BuildTriageContext(workdir, models.PlatformIOS, findings)

	assert.Contains(t, manifest, "Info.plist")
	assert.Contains(t, manifest, "get-task-allow")
	assert.NotNil(t, codeCtx)
}

func TestBuildTriageContext_EmptyWhenNoFiles(t *testing.T) {
	workdir := t.TempDir()
	codeCtx, manifest := BuildTriageContext(workdir, models.PlatformAndroid, nil)
	assert.Empty(t, codeCtx)
	assert.Empty(t, manifest)
}

func TestTriageConfigFor_PopulatesManifest(t *testing.T) {
	workdir := t.TempDir()
	jadxDir := filepath.Join(workdir, "jadx")
	require.NoError(t, os.MkdirAll(jadxDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "AndroidManifest.xml"),
		[]byte(`<manifest><uses-permission android:name="android.permission.CAMERA"/></manifest>`), 0o600))

	codeCtx, cfg := TriageConfigFor(workdir, models.PlatformAndroid, nil)
	assert.Empty(t, codeCtx)
	assert.Contains(t, cfg.ManifestContext, "CAMERA")
	assert.Equal(t, 4000, cfg.MaxContextChars)
}

func TestTruncateRunes_UTF8Safe(t *testing.T) {
	s := strings.Repeat("日", 100) // 300 bytes
	got := truncateRunes(s, 5)
	assert.True(t, strings.HasSuffix(got, "[truncated]"))
	assert.NotContains(t, got, "\uFFFD")
}
