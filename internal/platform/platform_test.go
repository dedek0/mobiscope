package platform

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildZip writes a ZIP with the given entry names and returns its path.
func buildZip(t *testing.T, name string, entries ...string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e)
		require.NoError(t, err)
		_, err = w.Write([]byte("x"))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())

	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
	return path
}

func TestDetect_APK(t *testing.T) {
	path := buildZip(t, "app.apk", "AndroidManifest.xml", "classes.dex", "res/layout.xml")
	target, err := Detect(path)
	require.NoError(t, err)
	assert.Equal(t, models.PlatformAndroid, target.Platform)
	assert.Equal(t, "apk", target.Format)
}

func TestDetect_APK_MultipleDex(t *testing.T) {
	path := buildZip(t, "app.apk", "AndroidManifest.xml", "classes.dex", "classes2.dex")
	target, err := Detect(path)
	require.NoError(t, err)
	assert.Equal(t, models.PlatformAndroid, target.Platform)
}

func TestDetect_IPA(t *testing.T) {
	path := buildZip(t, "app.ipa",
		"Payload/My App.app/Info.plist",
		"Payload/My App.app/MyApp",
		"Payload/My App.app/_CodeSignature/CodeResources",
	)
	target, err := Detect(path)
	require.NoError(t, err)
	assert.Equal(t, models.PlatformIOS, target.Platform)
	assert.Equal(t, "ipa", target.Format)
}

func TestDetect_IPA_NestedAppex(t *testing.T) {
	path := buildZip(t, "app.ipa",
		"Payload/Main.app/Info.plist",
		"Payload/Main.app/PlugIns/Ext.appex/Info.plist",
	)
	target, err := Detect(path)
	require.NoError(t, err)
	assert.Equal(t, models.PlatformIOS, target.Platform)
}

func TestDetect_IPA_FallbackToExtension(t *testing.T) {
	path := buildZip(t, "mystery.ipa", "Payload/My App.app/Other")
	target, err := Detect(path)
	require.NoError(t, err)
	assert.Equal(t, models.PlatformIOS, target.Platform)
}

func TestDetect_APK_FallbackToExtension(t *testing.T) {
	path := buildZip(t, "mystery.apk", "some/other/file")
	target, err := Detect(path)
	require.NoError(t, err)
	assert.Equal(t, models.PlatformAndroid, target.Platform)
}

func TestDetect_Unrecognized(t *testing.T) {
	path := buildZip(t, "notes.zip", "readme.txt", "photo.png")
	_, err := Detect(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognized")
}

func TestDetect_NotAZip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fake.apk")
	require.NoError(t, os.WriteFile(path, []byte("this is not a zip"), 0o600))
	_, err := Detect(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a ZIP")
}

func TestDetect_ExtBeatsNothing(t *testing.T) {
	// Extension alone is enough when no content marker is present.
	path := buildZip(t, "thin.apk", "META-INF/MANIFEST.MF")
	target, err := Detect(path)
	require.NoError(t, err)
	assert.Equal(t, models.PlatformAndroid, target.Platform)
}

func TestDetect_BackslashSeparators(t *testing.T) {
	path := buildZip(t, "win.ipa", `Payload\My App.app\Info.plist`)
	target, err := Detect(path)
	require.NoError(t, err)
	assert.Equal(t, models.PlatformIOS, target.Platform)
}

func TestMustExist(t *testing.T) {
	path := buildZip(t, "a.apk", "AndroidManifest.xml")
	require.NoError(t, MustExist(path))
	require.Error(t, MustExist(filepath.Join(t.TempDir(), "nope.apk")))
	require.Error(t, MustExist(t.TempDir()))
}
