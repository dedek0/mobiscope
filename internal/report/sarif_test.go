package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSARIFReporter_Render(t *testing.T) {
	session := &models.AnalysisSession{
		ID:       "s",
		Status:   models.StatusCompleted,
		Platform: models.PlatformAndroid,
		Findings: []models.Finding{
			{
				ID:          "a",
				SessionID:   "s",
				SourceTool:  "semgrep",
				Category:    models.CategorySecret,
				Title:       "Hardcoded key",
				Description: "Found a key.",
				Severity:    models.SeverityHigh,
				Sensitivity: models.SensitivitySecret,
				RuleID:      "mastg-hardcoded-api-key",
				MASVS:       []string{"MASVS-STORAGE-1"},
				CWE:         []string{"CWE-798"},
				Location:    models.Location{File: "src/A.java", Line: 12, Snippet: "apiKey"},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, (&SARIFReporter{}).Render(session, &buf))

	var log sarifLog
	require.NoError(t, json.Unmarshal(buf.Bytes(), &log))
	assert.Equal(t, "2.1.0", log.Version)
	assert.Contains(t, log.Schema, "sarif-2.1.0")
	require.Len(t, log.Runs, 1)
	require.Len(t, log.Runs[0].Results, 1)
	assert.Equal(t, "error", log.Runs[0].Results[0].Level)
	assert.Equal(t, "mastg-hardcoded-api-key", log.Runs[0].Results[0].RuleID)
	assert.Equal(t, "src/A.java", log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
	assert.Equal(t, 12, log.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.StartLine)
	require.Len(t, log.Runs[0].Tool.Driver.Rules, 1)
	assert.Equal(t, "MASVS-STORAGE-1", log.Runs[0].Tool.Driver.Rules[0].Properties["masvs"])
}

func TestSARIFLevel(t *testing.T) {
	assert.Equal(t, "error", sarifLevel(models.SeverityCritical))
	assert.Equal(t, "error", sarifLevel(models.SeverityHigh))
	assert.Equal(t, "warning", sarifLevel(models.SeverityMedium))
	assert.Equal(t, "note", sarifLevel(models.SeverityInfo))
}
