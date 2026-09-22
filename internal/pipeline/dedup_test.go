package pipeline

import (
	"log/slog"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
)

func TestDedup_RemovesExactDuplicates(t *testing.T) {
	findings := []models.Finding{
		{ID: "a", Category: models.CategorySecret, Location: models.Location{File: "f.java", Line: 1, Snippet: "x"}},
		{ID: "b", Category: models.CategorySecret, Location: models.Location{File: "f.java", Line: 1, Snippet: "x"}},
		{ID: "c", Category: models.CategorySecret, Location: models.Location{File: "f.java", Line: 2, Snippet: "y"}},
	}

	result := Dedup(findings)
	assert.Len(t, result, 2)
}

func TestDedup_PreservesUnique(t *testing.T) {
	findings := []models.Finding{
		{ID: "a", Category: models.CategorySecret, Location: models.Location{File: "a.java", Line: 1, Snippet: "x"}},
		{ID: "b", Category: models.CategoryCodePattern, Location: models.Location{File: "b.java", Line: 2, Snippet: "y"}},
	}

	result := Dedup(findings)
	assert.Len(t, result, 2)
}

func TestDedup_Empty(t *testing.T) {
	assert.Empty(t, Dedup(nil))
	assert.Empty(t, Dedup([]models.Finding{}))
}

func TestCluster_SingletonMarkedAsRepresentative(t *testing.T) {
	logger := slog.Default()
	findings := []models.Finding{
		{ID: "a", Category: models.CategorySecret, Title: "AWS Key", Severity: models.SeverityCritical, Location: models.Location{File: "a.java", Line: 1}},
	}

	clustered, count := Cluster(findings, logger)
	assert.Equal(t, 0, count)
	assert.Len(t, clustered, 1)
	assert.True(t, clustered[0].Representative)
	assert.True(t, clustered[0].NeedsLLMTriage)
}

func TestCluster_GroupsSimilarFindings(t *testing.T) {
	logger := slog.Default()
	findings := []models.Finding{
		{ID: "a", Category: models.CategorySecret, Title: "AWS Key", Severity: models.SeverityCritical, Location: models.Location{File: "a.java", Line: 10}},
		{ID: "b", Category: models.CategorySecret, Title: "AWS Key", Severity: models.SeverityCritical, Location: models.Location{File: "a.java", Line: 20}},
		{ID: "c", Category: models.CategorySecret, Title: "AWS Key", Severity: models.SeverityCritical, Location: models.Location{File: "b.java", Line: 5}},
	}

	clustered, count := Cluster(findings, logger)
	assert.Equal(t, 1, count)
	assert.Len(t, clustered, 3)

	repCount := 0
	for _, f := range clustered {
		if f.Representative {
			repCount++
			assert.True(t, f.NeedsLLMTriage)
		} else {
			assert.False(t, f.NeedsLLMTriage)
		}
		assert.NotEmpty(t, f.ClusterID)
	}
	assert.Equal(t, 1, repCount)
}

func TestCluster_DifferentCategoriesNotGrouped(t *testing.T) {
	logger := slog.Default()
	findings := []models.Finding{
		{ID: "a", Category: models.CategorySecret, Title: "Key", Severity: models.SeverityCritical, Location: models.Location{File: "a.java", Line: 1}},
		{ID: "b", Category: models.CategoryCodePattern, Title: "Key", Severity: models.SeverityCritical, Location: models.Location{File: "a.java", Line: 1}},
	}

	clustered, count := Cluster(findings, logger)
	assert.Equal(t, 0, count)
	for _, f := range clustered {
		assert.True(t, f.Representative)
	}
}

func TestCluster_Empty(t *testing.T) {
	logger := slog.Default()
	result, count := Cluster(nil, logger)
	assert.Empty(t, result)
	assert.Equal(t, 0, count)
}

func TestCluster_RepresentativeIsStable(t *testing.T) {
	logger := slog.Default()
	findings := []models.Finding{
		{ID: "b", Category: models.CategorySecret, Title: "Key", Severity: models.SeverityHigh, Location: models.Location{File: "z.java", Line: 100}},
		{ID: "a", Category: models.CategorySecret, Title: "Key", Severity: models.SeverityHigh, Location: models.Location{File: "a.java", Line: 1}},
	}

	clustered, _ := Cluster(findings, logger)

	var repID string
	for _, f := range clustered {
		if f.Representative {
			repID = f.ID
		}
	}
	assert.Equal(t, "a", repID)
}

func TestDedupKey_DifferentSnippets(t *testing.T) {
	f1 := models.Finding{Category: models.CategorySecret, Location: models.Location{File: "a.java", Line: 1, Snippet: "key1"}}
	f2 := models.Finding{Category: models.CategorySecret, Location: models.Location{File: "a.java", Line: 1, Snippet: "key2"}}
	assert.NotEqual(t, dedupKey(f1), dedupKey(f2))
}

func TestPatternSignature(t *testing.T) {
	f := models.Finding{
		Category: models.CategorySecret,
		Title:    "AWS Access Key detected",
		Severity: models.SeverityCritical,
		Location: models.Location{File: "Config.java"},
	}
	sig := patternSignature(f)
	assert.Contains(t, sig, "secret")
	assert.Contains(t, sig, "aws")
	assert.Contains(t, sig, ".java")
	assert.Contains(t, sig, "critical")
}
