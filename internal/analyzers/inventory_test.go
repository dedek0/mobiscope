package analyzers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInventory_Name(t *testing.T) {
	inv := NewInventory()
	assert.Equal(t, "inventory", inv.Name())
	assert.NoError(t, inv.Available())
}

func TestInventory_AnalyzeManifest_Debuggable(t *testing.T) {
	dir := t.TempDir()
	jadxDir := filepath.Join(dir, "jadx")
	require.NoError(t, os.MkdirAll(jadxDir, 0o755))

	manifest := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app">
    <application android:debuggable="true" />
</manifest>`
	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "AndroidManifest.xml"), []byte(manifest), 0o600))

	inv := NewInventory()
	findings := inv.analyzeManifest(jadxDir, "test-sess")

	require.Len(t, findings, 1)
	assert.Equal(t, "manifest_issue", string(findings[0].Category))
	assert.Equal(t, "high", string(findings[0].Severity))
	assert.Contains(t, findings[0].Title, "debuggable")
}

func TestInventory_AnalyzeManifest_ExportedComponent(t *testing.T) {
	dir := t.TempDir()
	jadxDir := filepath.Join(dir, "jadx")
	require.NoError(t, os.MkdirAll(jadxDir, 0o755))

	manifest := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".MainActivity" android:exported="true" />
        <service android:name=".BgService" android:exported="true" />
    </application>
</manifest>`
	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "AndroidManifest.xml"), []byte(manifest), 0o600))

	inv := NewInventory()
	findings := inv.analyzeManifest(jadxDir, "s")
	assert.Len(t, findings, 2)
	for _, f := range findings {
		assert.Equal(t, "manifest_issue", string(f.Category))
		assert.Equal(t, "medium", string(f.Severity))
	}
}

func TestInventory_AnalyzeManifest_DangerousPermission(t *testing.T) {
	dir := t.TempDir()
	jadxDir := filepath.Join(dir, "jadx")
	require.NoError(t, os.MkdirAll(jadxDir, 0o755))

	manifest := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.INTERNET" />
</manifest>`
	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "AndroidManifest.xml"), []byte(manifest), 0o600))

	inv := NewInventory()
	findings := inv.analyzeManifest(jadxDir, "s")
	assert.Len(t, findings, 1)
	assert.Contains(t, findings[0].Title, "CAMERA")
}

func TestInventory_AnalyzeManifest_NoFile(t *testing.T) {
	inv := NewInventory()
	findings := inv.analyzeManifest(t.TempDir(), "s")
	assert.Nil(t, findings)
}

func TestInventory_AnalyzeNetworkSecurityConfig(t *testing.T) {
	dir := t.TempDir()
	nscDir := filepath.Join(dir, "jadx", "res", "xml")
	require.NoError(t, os.MkdirAll(nscDir, 0o755))

	nsc := `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="true">example.com</domain>
        <pin-set>
            <pin digest="SHA-256">abc123=</pin>
        </pin-set>
    </domain-config>
</network-security-config>`
	require.NoError(t, os.WriteFile(filepath.Join(nscDir, "network_security_config.xml"), []byte(nsc), 0o600))

	inv := NewInventory()
	findings := inv.analyzeNetworkSecurityConfig(filepath.Join(dir, "jadx"), "s")

	// src="system" trust-anchors is the Android default and is NOT a finding;
	// only cleartext + pin-set should be reported here.
	assert.Len(t, findings, 2)

	categories := make(map[string]bool)
	for _, f := range findings {
		categories[string(f.Category)] = true
	}
	assert.True(t, categories["network_config"])
	assert.True(t, categories["pinning_indicator"])
}

func TestInventory_AnalyzeNetworkSecurityConfig_NoFile(t *testing.T) {
	inv := NewInventory()
	findings := inv.analyzeNetworkSecurityConfig(t.TempDir(), "s")
	assert.Nil(t, findings)
}

func TestInventory_ScanPatterns_AWSKey(t *testing.T) {
	dir := t.TempDir()
	jadxDir := filepath.Join(dir, "jadx")
	require.NoError(t, os.MkdirAll(jadxDir, 0o755))

	java := `public class Config {
    private static final String KEY = "AKIAIOSFODNN7EXAMPLE";
}`
	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "Config.java"), []byte(java), 0o600))

	inv := NewInventory()
	findings, _ := inv.scanPatterns(jadxDir, "s")

	var awsFindings []models.Finding
	for _, f := range findings {
		if f.Title == "AWS Access Key" {
			awsFindings = append(awsFindings, f)
		}
	}
	require.Len(t, awsFindings, 1)
	assert.Equal(t, "critical", string(awsFindings[0].Severity))
	assert.Equal(t, "secret", string(awsFindings[0].Sensitivity))
}

func TestInventory_ScanPatterns_PinningIndicators(t *testing.T) {
	dir := t.TempDir()
	jadxDir := filepath.Join(dir, "jadx")
	require.NoError(t, os.MkdirAll(jadxDir, 0o755))

	java := `public class Pinning {
    CertificatePinner pinner;
    // sha256/abc123
}`
	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "Pinning.java"), []byte(java), 0o600))

	inv := NewInventory()
	findings, _ := inv.scanPatterns(jadxDir, "s")

	pinningCount := 0
	for _, f := range findings {
		if f.Category == "pinning_indicator" {
			pinningCount++
		}
	}
	assert.GreaterOrEqual(t, pinningCount, 2)
}

func TestInventory_ScanPatterns_SkipsNonRelevantFiles(t *testing.T) {
	dir := t.TempDir()
	jadxDir := filepath.Join(dir, "jadx")
	require.NoError(t, os.MkdirAll(jadxDir, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "image.png"), []byte("AKIAIOSFODNN7EXAMPLE"), 0o600))

	inv := NewInventory()
	findings, _ := inv.scanPatterns(jadxDir, "s")
	assert.Empty(t, findings)
}

func TestIsDangerousPermission(t *testing.T) {
	assert.True(t, isDangerousPermission("android.permission.CAMERA"))
	assert.True(t, isDangerousPermission("android.permission.ACCESS_FINE_LOCATION"))
	assert.False(t, isDangerousPermission("android.permission.INTERNET"))
	assert.False(t, isDangerousPermission("android.permission.SET_WALLPAPER"))
}

func TestInventory_ScanPatterns_URLAggregate(t *testing.T) {
	dir := t.TempDir()
	jadxDir := filepath.Join(dir, "jadx")
	require.NoError(t, os.MkdirAll(jadxDir, 0o755))

	src := `String a = "https://api.example.com/v1";
String b = "https://api.example.com/v1";
String c = "http://insecure.example.org/";
`
	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "Net.java"), []byte(src), 0o600))

	inv := NewInventory()
	findings, agg := inv.scanPatterns(jadxDir, "s")

	assert.Equal(t, 3, agg.Count, "every URL occurrence is counted")
	require.Len(t, agg.URLs, 2, "unique sample is deduplicated")
	assert.Equal(t, []string{"http://insecure.example.org/", "https://api.example.com/v1"}, agg.URLs)

	// Generic URLs must never surface as findings (demoted to aggregate).
	for _, f := range findings {
		assert.NotEqual(t, models.CategorySecret, f.Category, "URL flood must not become findings")
	}
}

func TestInventory_ScanPatterns_JWT(t *testing.T) {
	dir := t.TempDir()
	jadxDir := filepath.Join(dir, "jadx")
	require.NoError(t, os.MkdirAll(jadxDir, 0o755))

	src := `String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";`
	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "Auth.java"), []byte(src), 0o600))

	inv := NewInventory()
	findings, _ := inv.scanPatterns(jadxDir, "s")

	var jwt *models.Finding
	for i := range findings {
		if findings[i].Title == "JWT" {
			jwt = &findings[i]
		}
	}
	require.NotNil(t, jwt, "JWT pattern must match")
	assert.Equal(t, "high", string(jwt.Severity))
	assert.Equal(t, "secret", string(jwt.Category))
}

func TestInventory_ScanPatterns_AzureConnectionString(t *testing.T) {
	dir := t.TempDir()
	jadxDir := filepath.Join(dir, "jadx")
	require.NoError(t, os.MkdirAll(jadxDir, 0o755))

	src := `String conn = "DefaultEndpointsProtocol=https;AccountName=storacct;AccountKey=aGVsbG9td29ybGRzZWNyZXR2YWx1ZTEyMzQ1Njc4OTAxMjM0NTY=";`
	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "Storage.java"), []byte(src), 0o600))

	inv := NewInventory()
	findings, _ := inv.scanPatterns(jadxDir, "s")

	found := false
	for _, f := range findings {
		if f.Title == "Azure Storage Connection String" {
			found = true
			assert.Equal(t, "critical", string(f.Severity))
		}
	}
	assert.True(t, found, "Azure connection string pattern must match")
}

func TestInventory_ScanPatterns_PredictableIV(t *testing.T) {
	dir := t.TempDir()
	jadxDir := filepath.Join(dir, "jadx")
	require.NoError(t, os.MkdirAll(jadxDir, 0o755))

	src := `Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(null));`
	require.NoError(t, os.WriteFile(filepath.Join(jadxDir, "Crypto.java"), []byte(src), 0o600))

	inv := NewInventory()
	findings, _ := inv.scanPatterns(jadxDir, "s")

	found := false
	for _, f := range findings {
		if f.Title == "Predictable IV (IvParameterSpec)" {
			found = true
			assert.Equal(t, "medium", string(f.Severity))
			assert.Equal(t, "code_pattern", string(f.Category))
		}
	}
	assert.True(t, found, "IvParameterSpec(null) must be flagged")
}

func TestSourceRoot(t *testing.T) {
	dir := t.TempDir()

	// Nothing yet -> session root.
	assert.Equal(t, dir, SourceRoot(dir))

	// apktool-only run -> apktool dir.
	apktoolDir := filepath.Join(dir, "apktool")
	require.NoError(t, os.MkdirAll(apktoolDir, 0o755))
	assert.Equal(t, apktoolDir, SourceRoot(dir))

	// jadx wins when both exist.
	jadxDir := filepath.Join(dir, "jadx")
	require.NoError(t, os.MkdirAll(jadxDir, 0o755))
	assert.Equal(t, jadxDir, SourceRoot(dir))
}

func TestCountLines(t *testing.T) {
	assert.Equal(t, 1, countLines(""))
	assert.Equal(t, 1, countLines("hello"))
	assert.Equal(t, 2, countLines("hello\nworld"))
	assert.Equal(t, 3, countLines("a\nb\nc"))
}
