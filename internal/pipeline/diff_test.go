package pipeline

import (
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
)

func testFinding(cat models.Category, title, file, evidence string) models.Finding {
	return models.Finding{
		SourceTool: "inventory",
		Category:   cat,
		Title:      title,
		Evidence:   evidence,
		Location:   models.Location{File: file, Line: 1, Snippet: evidence},
	}
}

func TestFindingFingerprint_IgnoresLine(t *testing.T) {
	a := testFinding(models.CategorySecret, "AWS Access Key", "A.java", "AKIA")
	b := a
	b.Location.Line = 99
	assert.Equal(t, FindingFingerprint(a), FindingFingerprint(b))
}

func TestFindingFingerprint_SemgrepUsesRule(t *testing.T) {
	a := testFinding(models.CategoryCodePattern, "Rule title", "A.java", "snippet")
	a.RuleID = "mastg-x"
	b := a
	b.Title = "A different title"
	assert.Equal(t, FindingFingerprint(a), FindingFingerprint(b))
}

func TestDiffFindings(t *testing.T) {
	old := []models.Finding{
		testFinding(models.CategorySecret, "AWS Access Key", "A.java", "AKIA1"),
		testFinding(models.CategoryManifestIssue, "Exported activity", "AndroidManifest.xml", ".Main"),
		testFinding(models.CategoryManifestIssue, "Exported activity", "AndroidManifest.xml", ".Old"),
	}
	new := []models.Finding{
		testFinding(models.CategorySecret, "AWS Access Key", "A.java", "AKIA1"),
		testFinding(models.CategoryManifestIssue, "Exported activity", "AndroidManifest.xml", ".Main"),
		testFinding(models.CategoryManifestIssue, "Exported activity", "AndroidManifest.xml", ".New"),
	}

	result := DiffFindings(old, new)
	// .New replaces .Old: one new and one resolved, two unchanged.
	if assert.Len(t, result.New, 1) {
		assert.Equal(t, ".New", result.New[0].Evidence)
	}
	if assert.Len(t, result.Resolved, 1) {
		assert.Equal(t, ".Old", result.Resolved[0].Evidence)
	}
	assert.Equal(t, 2, result.Unchanged)
}

func TestDiffFindings_DuplicateOccurrences(t *testing.T) {
	one := testFinding(models.CategorySecret, "AWS Access Key", "A.java", "AKIA1")
	two := one
	two.Location.Line = 2

	result := DiffFindings([]models.Finding{one}, []models.Finding{one, two})
	assert.Len(t, result.New, 1)
	assert.Empty(t, result.Resolved)
	assert.Equal(t, 1, result.Unchanged)

	reverse := DiffFindings([]models.Finding{one, two}, []models.Finding{one})
	assert.Empty(t, reverse.New)
	assert.Len(t, reverse.Resolved, 1)
	assert.Equal(t, 1, reverse.Unchanged)
}

func TestFilterBaseline(t *testing.T) {
	known := testFinding(models.CategorySecret, "AWS Access Key", "A.java", "AKIA1")
	fresh := testFinding(models.CategorySecret, "Slack Token", "B.java", "xoxb")
	baseline := BaselineFingerprints([]models.Finding{known})

	out, suppressed := FilterBaseline([]models.Finding{known, fresh}, baseline)
	assert.Equal(t, 1, suppressed)
	assert.Equal(t, []models.Finding{fresh}, out)
}
