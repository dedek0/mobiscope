package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFailOn(t *testing.T) {
	for _, value := range []string{"", "off", "none", "OFF"} {
		_, enabled, err := parseFailOn(value)
		require.NoError(t, err)
		assert.False(t, enabled, value)
	}

	sev, enabled, err := parseFailOn("HIGH")
	require.NoError(t, err)
	assert.True(t, enabled)
	assert.Equal(t, models.SeverityHigh, sev)

	_, _, err = parseFailOn("urgent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --fail-on")
}

func TestCountAtOrAbove(t *testing.T) {
	findings := []models.Finding{
		{Severity: models.SeverityCritical},
		{Severity: models.SeverityHigh},
		{Severity: models.SeverityLow},
		{Severity: models.SeverityInfo},
	}
	assert.Equal(t, 2, countAtOrAbove(findings, models.SeverityHigh))
	assert.Equal(t, 3, countAtOrAbove(findings, models.SeverityLow))
	assert.Equal(t, 4, countAtOrAbove(findings, models.SeverityInfo))
}

func TestLoadBaselineFindings_ArrayAndSession(t *testing.T) {
	dir := t.TempDir()
	findings := []models.Finding{{Title: "one", Severity: models.SeverityHigh}}

	arrayPath := filepath.Join(dir, "findings.json")
	data, err := json.Marshal(findings)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(arrayPath, data, 0o600))

	loaded, err := loadBaselineFindings(arrayPath)
	require.NoError(t, err)
	assert.Equal(t, findings, loaded)

	sessionPath := filepath.Join(dir, "session.json")
	data, err = json.Marshal(models.AnalysisSession{Findings: findings})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(sessionPath, data, 0o600))

	loaded, err = loadBaselineFindings(sessionPath)
	require.NoError(t, err)
	assert.Equal(t, findings, loaded)
}

func TestApplyBaseline(t *testing.T) {
	dir := t.TempDir()
	known := models.Finding{
		SourceTool: "inventory",
		Category:   models.CategorySecret,
		Title:      "AWS Access Key",
		Evidence:   "AKIA1",
		Location:   models.Location{File: "A.java", Line: 1, Snippet: "AKIA1"},
		Severity:   models.SeverityCritical,
	}
	fresh := known
	fresh.Title = "Slack Token"
	fresh.Evidence = "xoxb"

	baselinePath := filepath.Join(dir, "findings.json")
	data, err := json.Marshal([]models.Finding{known})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(baselinePath, data, 0o600))

	session := &models.AnalysisSession{Findings: []models.Finding{known, fresh}}
	require.NoError(t, applyBaseline(session, baselinePath, discardLogger()))

	assert.Equal(t, 1, session.BaselineSuppressed)
	require.Len(t, session.Findings, 1)
	assert.Equal(t, "Slack Token", session.Findings[0].Title)
	assert.True(t, session.Findings[0].Representative)
}

func TestClassifyExit_FindingsGate(t *testing.T) {
	assert.Equal(t, ExitFindings, classifyExit(ErrFindingsAboveThreshold))
	assert.Equal(t, 2, ExitFindings)
}
