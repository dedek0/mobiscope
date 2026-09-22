package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalysisSessionJSON(t *testing.T) {
	session := AnalysisSession{
		ID:      "test-001",
		APKPath: "/tmp/test.apk",
		Status:  StatusPending,
	}

	data, err := session.MarshalJSON()
	require.NoError(t, err)
	assert.Contains(t, string(data), `"id":"test-001"`)
	assert.Contains(t, string(data), `"status":"pending"`)
}

func TestSessionStatusConstants(t *testing.T) {
	assert.Equal(t, SessionStatus("pending"), StatusPending)
	assert.Equal(t, SessionStatus("running"), StatusRunning)
	assert.Equal(t, SessionStatus("completed"), StatusCompleted)
	assert.Equal(t, SessionStatus("failed"), StatusFailed)
}

func TestAnalysisSession_RoundTrip(t *testing.T) {
	now := time.Date(2025, 1, 15, 10, 0, 0, 0, time.UTC)
	done := now.Add(time.Minute)
	session := AnalysisSession{
		ID:          "abc123",
		APKPath:     "/tmp/test.apk",
		APKHash:     "deadbeef",
		Status:      StatusCompleted,
		StartedAt:   now,
		CompletedAt: &done,
		Findings: []Finding{{
			ID:          "f1",
			SessionID:   "abc123",
			SourceTool:  "gitleaks",
			Category:    CategorySecret,
			Title:       "Secret detected: aws-key",
			Severity:    SeverityCritical,
			Sensitivity: SensitivitySecret,
		}},
	}

	data, err := json.Marshal(&session)
	require.NoError(t, err)

	var decoded AnalysisSession
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, session.ID, decoded.ID)
	assert.Equal(t, session.APKPath, decoded.APKPath)
	assert.Equal(t, session.Status, decoded.Status)
	assert.True(t, session.StartedAt.Equal(decoded.StartedAt))
	require.NotNil(t, decoded.CompletedAt)
	assert.True(t, session.CompletedAt.Equal(*decoded.CompletedAt))
	require.Len(t, decoded.Findings, 1)
	assert.Equal(t, CategorySecret, decoded.Findings[0].Category)
}
