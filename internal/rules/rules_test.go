package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaterializeWritesBothPacks(t *testing.T) {
	t.Cleanup(Cleanup)

	android, err := Materialize(PackAndroid)
	require.NoError(t, err)
	ios, err := Materialize(PackIOS)
	require.NoError(t, err)

	require.FileExists(t, android)
	require.FileExists(t, ios)
	assert.True(t, strings.HasSuffix(filepath.ToSlash(android), "mastg/rules.yaml"))
	assert.True(t, strings.HasSuffix(filepath.ToSlash(ios), "mastg-ios/rules.yaml"))

	got, err := os.ReadFile(android)
	require.NoError(t, err)
	assert.Equal(t, AndroidYAML(), got)

	got, err = os.ReadFile(ios)
	require.NoError(t, err)
	assert.Equal(t, IOSYAML(), got)
}

func TestCleanupRemovesDirectoryAndAllowsRematerialize(t *testing.T) {
	t.Cleanup(Cleanup)

	path, err := Materialize(PackAndroid)
	require.NoError(t, err)
	dir := filepath.Dir(filepath.Dir(path))
	require.DirExists(t, dir)

	Cleanup()
	assert.NoDirExists(t, dir)

	// The one-shot state must be reset, otherwise the next call would
	// return a path inside the directory that was just removed.
	again, err := Materialize(PackAndroid)
	require.NoError(t, err)
	assert.FileExists(t, again)
}

func TestMaterializeUnknownPack(t *testing.T) {
	t.Cleanup(Cleanup)

	path, err := Materialize(Pack("bogus"))
	require.Error(t, err)
	assert.Empty(t, path)
	assert.Contains(t, err.Error(), "unknown rule pack")
}

func TestEmbeddedPacksContainRules(t *testing.T) {
	require.NotEmpty(t, AndroidYAML())
	require.NotEmpty(t, IOSYAML())
	assert.Contains(t, string(AndroidYAML()), "rules:")
	assert.Contains(t, string(IOSYAML()), "rules:")
}
