package analyzers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildConfigVersions(t *testing.T) {
	dir := t.TempDir()
	javaPath := filepath.Join(dir, "jadx", "sources", "com", "squareup", "okhttp3", "BuildConfig.java")
	require.NoError(t, os.MkdirAll(filepath.Dir(javaPath), 0o755))
	require.NoError(t, os.WriteFile(javaPath, []byte(`package com.squareup.okhttp3;
public final class BuildConfig {
    public static final String VERSION = "4.12.0";
}`), 0o600))

	kotlinPath := filepath.Join(dir, "jadx", "sources", "com", "adjust", "sdk", "BuildConfig.kt")
	require.NoError(t, os.MkdirAll(filepath.Dir(kotlinPath), 0o755))
	require.NoError(t, os.WriteFile(kotlinPath, []byte(`package com.adjust.sdk
object BuildConfig {
    const val VERSION_NAME: String = "5.0.1"
}`), 0o600))

	versions := buildConfigVersions(dir)
	assert.Equal(t, "4.12.0", versions["com.squareup.okhttp3"])
	assert.Equal(t, "5.0.1", versions["com.adjust.sdk"])
	assert.Equal(t, "4.12.0", buildConfigVersionFor(versions, "com.squareup.okhttp3"))
	assert.Equal(t, "5.0.1", buildConfigVersionFor(versions, "com.adjust.sdk"))
	assert.Equal(t, "", buildConfigVersionFor(versions, "com.example.unknown"))
}

func TestNativeSDKsFromArchive(t *testing.T) {
	path := buildZipFile(t, filepath.Join(t.TempDir(), "native.apk"), map[string]string{
		"lib/arm64-v8a/libflutter.so": "x",
		"lib/arm64-v8a/libunity.so":   "x",
		"lib/arm64-v8a/libfoo.so":     "x",
	})

	sdks := nativeSDKsFromArchive(path)
	names := make([]string, 0, len(sdks))
	for _, sdk := range sdks {
		names = append(names, sdk.Name)
	}
	assert.ElementsMatch(t, []string{"Flutter", "Unity"}, names)
}

func TestDetectSDKs_NativeOnly(t *testing.T) {
	path := buildZipFile(t, filepath.Join(t.TempDir(), "native.apk"), map[string]string{
		"lib/arm64-v8a/libhermes.so": "x",
		"lib/arm64-v8a/libfoo.so":    "x",
	})
	sdks := DetectSDKs(path, t.TempDir())
	require.Len(t, sdks, 1)
	assert.Equal(t, "Hermes JS Engine", sdks[0].Name)
	assert.Equal(t, "lib/arm64-v8a/libhermes.so", sdks[0].Evidence)
}
