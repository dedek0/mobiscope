package pipeline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeAllowlist(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "allowlist.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestLoadAllowlist_AndFilter(t *testing.T) {
	path := writeAllowlist(t, `
allow:
  - reason: "Firebase API keys are public client identifiers"
    category: secret
    title: "*GCP API Key*"
  - reason: "AndroidX build config"
    file: "**/BuildConfig.java"
`)
	rules, err := LoadAllowlist(path)
	require.NoError(t, err)
	require.Len(t, rules, 2)

	findings := []models.Finding{
		{Category: models.CategorySecret, Title: "GCP API Key", Location: models.Location{File: "Config.java"}},
		{Category: models.CategorySecret, Title: "AWS Access Key", Location: models.Location{File: "Config.java"}},
		{Category: models.CategoryCodePattern, Title: "Something", Location: models.Location{File: "com/example/BuildConfig.java"}},
	}
	out, suppressed := FilterAllowlist(findings, rules)
	assert.Equal(t, 2, suppressed)
	require.Len(t, out, 1)
	assert.Equal(t, "AWS Access Key", out[0].Title)
}

func TestLoadAllowlist_BareList(t *testing.T) {
	path := writeAllowlist(t, `
- reason: "known test fixture"
  tool: inventory
  evidence: AKIAIOSFODNN7EXAMPLE
`)
	rules, err := LoadAllowlist(path)
	require.NoError(t, err)
	require.Len(t, rules, 1)
	assert.True(t, rules[0].Matches(models.Finding{
		SourceTool: "inventory",
		Evidence:   "prefix AKIAIOSFODNN7EXAMPLE suffix",
	}))
	assert.False(t, rules[0].Matches(models.Finding{SourceTool: "semgrep"}))
}

func TestLoadAllowlist_RequiresReasonAndCriteria(t *testing.T) {
	_, err := LoadAllowlist(writeAllowlist(t, "- title: foo\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "needs a reason")

	_, err = LoadAllowlist(writeAllowlist(t, "- reason: no criteria\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching field")
}

func TestMatchAllowPattern(t *testing.T) {
	assert.True(t, matchAllowPattern("", "anything"))
	assert.True(t, matchAllowPattern("*.java", "com/example/Foo.java"))
	assert.True(t, matchAllowPattern("com/example", "com/example/Foo.java"))
	assert.False(t, matchAllowPattern("*.kt", "com/example/Foo.java"))
}
