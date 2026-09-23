package analyzers

import (
	"os"
	"path/filepath"
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
	// grantUriPermissions + exported provider = 2 findings
	require.Len(t, findings, 2)
	titles := []string{findings[0].Title, findings[1].Title}
	assert.Contains(t, titles[0]+titles[1], "grants URI permissions")
	assert.Contains(t, titles[0]+titles[1], "Exported provider")
}
