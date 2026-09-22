package models

import (
	"testing"

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
