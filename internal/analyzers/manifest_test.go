package analyzers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeManifest_AttributeOrder(t *testing.T) {
	data := []byte(`<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
    <uses-permission android:maxSdkVersion="30" android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.INTERNET" />
    <application android:networkSecurityConfig="@xml/my_nsc" android:allowBackup="false">
        <activity android:exported="true" android:name=".Main">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="https" android:host="example.com"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`)
	m, err := decodeManifest(data)
	require.NoError(t, err)
	assert.Equal(t, "com.x", m.Package)

	perms := m.permissions()
	assert.Contains(t, perms, "android.permission.CAMERA")
	assert.Contains(t, perms, "android.permission.INTERNET")

	comps := m.components()
	require.Len(t, comps, 1)
	assert.Equal(t, "activity", comps[0].Kind)
	assert.Equal(t, ".Main", comps[0].Name)
	assert.True(t, comps[0].Exported)
	require.Len(t, comps[0].IntentFilters, 1)
	assert.Contains(t, comps[0].IntentFilters[0].Schemes, "https")

	assert.Equal(t, "my_nsc", nscResourceName(m))
}

func TestResolveNSCPath_FromManifest(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "res", "xml"), 0o755))
	custom := filepath.Join(dir, "res", "xml", "my_nsc.xml")
	require.NoError(t, os.WriteFile(custom, []byte("<network-security-config/>"), 0o600))

	m, err := decodeManifest([]byte(`<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:networkSecurityConfig="@xml/my_nsc"/>
</manifest>`))
	require.NoError(t, err)

	abs, rel := resolveNSCPath(dir, m)
	assert.Equal(t, custom, abs)
	assert.Equal(t, "res/xml/my_nsc.xml", rel)
}

func TestHasCustomTrustAnchor(t *testing.T) {
	assert.False(t, hasCustomTrustAnchor(`<trust-anchors><certificates src="system"/></trust-anchors>`))
	assert.True(t, hasCustomTrustAnchor(`<trust-anchors><certificates src="user"/></trust-anchors>`))
	assert.True(t, hasCustomTrustAnchor(`<trust-anchors><certificates src="@raw/ca"/></trust-anchors>`))
	assert.False(t, hasCustomTrustAnchor(`<pin-set></pin-set>`))
}

func TestIsDangerousPermission_Suffix(t *testing.T) {
	assert.True(t, isDangerousPermission("android.permission.CAMERA"))
	assert.True(t, isDangerousPermission("android.permission.READ_MEDIA_IMAGES"))
	assert.False(t, isDangerousPermission("android.permission.INTERNET"))
	assert.False(t, isDangerousPermission("com.foo.MANAGE_CAMERA"))
}

func TestAnalyzeManifest_CustomWeakPermission(t *testing.T) {
	dir := t.TempDir()
	manifest := `<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <permission android:name="com.x.SYNC" android:protectionLevel="normal"/>
    <application/>
</manifest>`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "AndroidManifest.xml"), []byte(manifest), 0o600))

	inv := NewInventory()
	findings := inv.analyzeManifest(dir, "s")
	require.Len(t, findings, 1)
	assert.Contains(t, findings[0].Title, "weak protection")
}

func TestAnalyzeManifest_ExportedProviderWithGrant(t *testing.T) {
	dir := t.TempDir()
	manifest := `<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <provider android:name=".P" android:exported="true" android:grantUriPermissions="true"/>
    </application>
</manifest>`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "AndroidManifest.xml"), []byte(manifest), 0o600))

	inv := NewInventory()
	findings := inv.analyzeManifest(dir, "s")
	// grantUriPermissions + exported provider + provider without a
	// read/write permission = 3 findings
	require.Len(t, findings, 3)
	all := findings[0].Title + "|" + findings[1].Title + "|" + findings[2].Title
	assert.Contains(t, all, "grants URI permissions")
	assert.Contains(t, all, "Exported provider")
	assert.Contains(t, all, "without read/write permission")

	// Every finding must carry a distinct ID: two findings that share an
	// ID would be collapsed by the dedup pass.
	ids := map[string]bool{}
	for _, f := range findings {
		assert.False(t, ids[f.ID], "duplicate finding id %s", f.ID)
		ids[f.ID] = true
	}
}

func TestAnalyzeManifest_ImplicitExport(t *testing.T) {
	dir := t.TempDir()
	manifest := `<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
    <application>
        <activity android:name=".Leaky">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "AndroidManifest.xml"), []byte(manifest), 0o600))

	findings := NewInventory().analyzeManifest(dir, "s")
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Implicitly exported") {
			found = true
		}
	}
	assert.True(t, found, "an activity with an intent-filter and no android:exported must be reported")
}

func TestAnalyzeManifest_CustomSchemeAndBackupRules(t *testing.T) {
	dir := t.TempDir()
	manifest := `<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app" android:sharedUserId="com.example.shared">
    <application android:dataExtractionRules="@xml/data_extraction_rules" android:fullBackupContent="@xml/backup_rules">
        <activity android:name=".Deep" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="myapp"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "AndroidManifest.xml"), []byte(manifest), 0o600))

	findings := NewInventory().analyzeManifest(dir, "s")
	all := ""
	for _, f := range findings {
		all += f.Title + "|"
	}
	assert.Contains(t, all, "Custom URI scheme")
	assert.Contains(t, all, "Cloud backup rules")
	assert.Contains(t, all, "Backup content rules")
	assert.Contains(t, all, "shares a user ID")
}
