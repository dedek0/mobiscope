package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSession() *models.AnalysisSession {
	now := time.Now()
	return &models.AnalysisSession{
		ID:      "test-session-01",
		APKPath: "/tmp/test.apk",
		Status:  models.StatusCompleted,
		Findings: []models.Finding{
			{
				ID:          "aabbccdd11223344",
				SessionID:   "test-session-01",
				SourceTool:  "gitleaks",
				Category:    models.CategorySecret,
				Title:       "AWS Access Key",
				Description: "Hardcoded AWS key",
				Evidence:    "AKIAIOSFODNN7EXAMPLE",
				Location:    models.Location{File: "Config.java", Line: 42, Snippet: "AKIAIOSFODNN7EXAMPLE"},
				Severity:    models.SeverityCritical,
				Sensitivity: models.SensitivitySecret,
				Confidence:  0.95,
				ClusterID:   "cl-abc123",
			},
			{
				ID:          "eeff001122334455",
				SessionID:   "test-session-01",
				SourceTool:  "inventory",
				Category:    models.CategoryManifestIssue,
				Title:       "Exported component",
				Location:    models.Location{File: "AndroidManifest.xml", Line: 10, Snippet: "exported=true"},
				Severity:    models.SeverityMedium,
				Sensitivity: models.SensitivityInternal,
				Confidence:  0.9,
			},
			{
				ID:          "66778899aabbccdd",
				SessionID:   "test-session-01",
				SourceTool:  "inventory",
				Category:    models.CategoryPinningIndicator,
				Title:       "CertificatePinner",
				Location:    models.Location{File: "Pinning.java", Line: 5},
				Severity:    models.SeverityInfo,
				Sensitivity: models.SensitivityPublic,
			},
		},
		StartedAt:   now,
		CompletedAt: &now,
	}
}

func TestJSONReporter_Render(t *testing.T) {
	session := testSession()
	r := &JSONReporter{}

	var buf bytes.Buffer
	require.NoError(t, r.Render(session, &buf))

	output := buf.String()
	assert.Contains(t, output, "test-session-01")
	assert.Contains(t, output, "gitleaks")
	assert.Contains(t, output, "findings")
}

func TestFindingsJSON_Render(t *testing.T) {
	session := testSession()
	r := &FindingsJSON{}

	var buf bytes.Buffer
	require.NoError(t, r.Render(session, &buf))

	output := buf.String()
	assert.Contains(t, output, "aabbccdd11223344")
	assert.Contains(t, output, "secret")
}

func TestMarkdownReporter_Render(t *testing.T) {
	session := testSession()
	r := &MarkdownReporter{}

	var buf bytes.Buffer
	require.NoError(t, r.Render(session, &buf))

	output := buf.String()
	assert.Contains(t, output, "mobiscope")
	assert.Contains(t, output, "test-session-01")
	assert.Contains(t, output, "critical")
	assert.Contains(t, output, "AWS Access Key")
	assert.Contains(t, output, "Config.java")
	assert.Contains(t, output, "Exported component")
}

func TestMarkdownReporter_GroupsBySeverity(t *testing.T) {
	session := testSession()
	r := &MarkdownReporter{}

	var buf bytes.Buffer
	require.NoError(t, r.Render(session, &buf))

	output := buf.String()
	critIdx := strings.Index(output, "critical")
	medIdx := strings.Index(output, "medium")
	assert.True(t, critIdx < medIdx, "critical should appear before medium")
}

func TestMarkdownReporter_ClusterInfo(t *testing.T) {
	session := testSession()
	r := &MarkdownReporter{}

	var buf bytes.Buffer
	require.NoError(t, r.Render(session, &buf))

	output := buf.String()
	assert.Contains(t, output, "cl-abc123")
}

func TestSortFindingsBySeverity(t *testing.T) {
	findings := []models.Finding{
		{Severity: models.SeverityInfo, Location: models.Location{File: "b.java", Line: 1}},
		{Severity: models.SeverityCritical, Location: models.Location{File: "a.java", Line: 1}},
		{Severity: models.SeverityMedium, Location: models.Location{File: "a.java", Line: 2}},
	}

	SortFindingsBySeverity(findings)
	assert.Equal(t, models.SeverityCritical, findings[0].Severity)
	assert.Equal(t, models.SeverityMedium, findings[1].Severity)
	assert.Equal(t, models.SeverityInfo, findings[2].Severity)
}

func TestSeverityRank(t *testing.T) {
	assert.Less(t, SeverityRank(models.SeverityCritical), SeverityRank(models.SeverityHigh))
	assert.Less(t, SeverityRank(models.SeverityHigh), SeverityRank(models.SeverityMedium))
	assert.Less(t, SeverityRank(models.SeverityMedium), SeverityRank(models.SeverityLow))
	assert.Less(t, SeverityRank(models.SeverityLow), SeverityRank(models.SeverityInfo))
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 10))
	assert.Equal(t, "hello wo...", truncate("hello world foo bar", 8))
	assert.Equal(t, "a b", truncate("a\nb", 10))
}

func TestBoolStr(t *testing.T) {
	assert.Equal(t, "yes", boolStr(true))
	assert.Equal(t, "no", boolStr(false))
}
