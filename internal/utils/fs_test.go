package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSha256File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	content := []byte("hello world")
	require.NoError(t, os.WriteFile(path, content, 0o600))

	expected := sha256.Sum256(content)
	got, err := Sha256File(path)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(expected[:]), got)
}

func TestSha256File_NotFound(t *testing.T) {
	_, err := Sha256File("/nonexistent/file")
	assert.Error(t, err)
}

func TestEnsureDir(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "a", "b", "c")
	require.NoError(t, EnsureDir(target))
	assert.DirExists(t, target)
}

func TestSafeRmtree(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0o755))
	require.NoError(t, SafeRmtree(dir, sub))
	assert.NoDirExists(t, sub)
}

func TestSafeRmtree_NotExists(t *testing.T) {
	dir := t.TempDir()
	assert.NoError(t, SafeRmtree(dir, filepath.Join(dir, "nope")))
}

func TestSafeRmtree_RefusesEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	require.Error(t, SafeRmtree(root, outside))
	assert.DirExists(t, outside)
}

func TestSafeRmtree_RefusesRootFS(t *testing.T) {
	require.Error(t, SafeRmtree("/", "/"))
}

func TestSafeRmtree_RefusesParent(t *testing.T) {
	root := t.TempDir()
	require.Error(t, SafeRmtree(root, filepath.Dir(root)))
}

func TestHumanSize(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, HumanSize(tt.bytes))
	}
}

func TestExists(t *testing.T) {
	dir := t.TempDir()
	assert.True(t, Exists(dir))
	assert.False(t, Exists(filepath.Join(dir, "nope")))
}

func TestIsDirEmpty(t *testing.T) {
	dir := t.TempDir()
	empty, err := IsDirEmpty(dir)
	require.NoError(t, err)
	assert.True(t, empty)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "f"), []byte("x"), 0o600))
	empty, err = IsDirEmpty(dir)
	require.NoError(t, err)
	assert.False(t, empty)
}

func TestNormalizePath(t *testing.T) {
	p, err := NormalizePath("./relative/path")
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(p))
}

func TestSanitizeFilename(t *testing.T) {
	assert.Equal(t, "a_b_c", SanitizeFilename("a/b/c"))
	assert.Equal(t, "a_b_c", SanitizeFilename(`a\b\c`))
	assert.Equal(t, "a.b", SanitizeFilename("a.b"))
	assert.Equal(t, "_", SanitizeFilename(".."))
	assert.Equal(t, "a_b", SanitizeFilename("a\nb"))
	assert.Equal(t, "_", SanitizeFilename(""))
	assert.NotContains(t, SanitizeFilename("..\\..\\etc"), "..")
}

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "file.txt")
	require.NoError(t, WriteFile(path, []byte("data")))
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), got)

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestDirSize(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a"), []byte("12345"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b"), []byte("12345"), 0o600))
	size, err := DirSize(dir)
	require.NoError(t, err)
	assert.Equal(t, int64(10), size)
}
