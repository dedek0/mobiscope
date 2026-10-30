package pipeline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeMapping(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mapping.txt")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestLoadMapping_RewriteFindings(t *testing.T) {
	path := writeMapping(t, `com.example.RealActivity -> a.a:
    void onCreate(android.os.Bundle) -> a
com.other.Inner$Thing -> a.b$c:
`)
	mapping, err := LoadMapping(path)
	require.NoError(t, err)

	findings := []models.Finding{
		{
			Title:       "Issue",
			Description: "found in a.a",
			Evidence:    "a.a",
			Location:    models.Location{File: "sources/a/a.java", Line: 3},
		},
		{
			Title:       "Inner",
			Description: "inner",
			Evidence:    "a.b$c",
			Location:    models.Location{File: "sources/a/b$c.kt", Line: 1},
		},
		{
			Title:    "Unrelated",
			Evidence: "com.example.app.Main",
			Location: models.Location{File: "sources/com/example/app/Main.java", Line: 1},
		},
	}

	rewritten := mapping.RewriteFindings(findings)
	assert.Equal(t, 2, rewritten)
	assert.Equal(t, "sources/com/example/RealActivity.java", findings[0].Location.File)
	assert.Contains(t, findings[0].Evidence, "com.example.RealActivity")
	assert.Equal(t, "sources/com/other/Inner$Thing.kt", findings[1].Location.File)
	assert.Equal(t, "sources/com/example/app/Main.java", findings[2].Location.File)
}

func TestLoadMapping_Empty(t *testing.T) {
	_, err := LoadMapping(writeMapping(t, "# no classes here\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no class mappings")
}

func TestRewritePath_SegmentBoundary(t *testing.T) {
	path := writeMapping(t, "com.example.Foo -> a.b:\n")
	mapping, err := LoadMapping(path)
	require.NoError(t, err)
	// "xa/b.java" must not match the "a.b" suffix.
	got, ok := mapping.rewritePath("sources/xa/b.java")
	assert.False(t, ok)
	assert.Equal(t, "sources/xa/b.java", got)
}
