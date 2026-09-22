package analyzers

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitleaks_Name(t *testing.T) {
	g := NewGitleaks()
	assert.Equal(t, "gitleaks", g.Name())
}

func TestGitleaks_Run_Success(t *testing.T) {
	findings := []GitleaksFinding{
		{
			RuleID:    "aws-access-key",
			Secret:    "AKIAIOSFODNN7EXAMPLE",
			File:      "src/Config.java",
			StartLine: 42,
			Match:     "AKIAIOSFODNN7EXAMPLE",
			Tags:      []string{"aws"},
		},
	}
	raw, _ := json.Marshal(findings)

	runner := NewMockRunner(string(raw), "", 0)
	g := NewGitleaksWithRunner(runner)

	dir := t.TempDir()
	result, err := g.Run(context.Background(), "test.apk", dir)
	require.NoError(t, err)
	assert.Equal(t, "gitleaks", result.ToolName)

	var parsed []GitleaksFinding
	require.NoError(t, json.Unmarshal(result.Output, &parsed))
	assert.Len(t, parsed, 1)
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", parsed[0].Secret)
}

func TestGitleaks_Run_EmptyResult(t *testing.T) {
	runner := NewMockRunner("[]", "", 0)
	g := NewGitleaksWithRunner(runner)

	result, err := g.Run(context.Background(), "test.apk", t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, 0, result.ExitCode)
}

func TestGitleaks_Run_Error(t *testing.T) {
	runner := NewFailingRunner(assert.AnError)
	g := NewGitleaksWithRunner(runner)

	result, err := g.Run(context.Background(), "test.apk", t.TempDir())
	assert.Error(t, err)
	assert.NotEmpty(t, result.Error)
}

func TestConvertGitleaksFindings(t *testing.T) {
	gf := []GitleaksFinding{
		{
			RuleID:      "aws-access-key",
			Description: "AWS access key detected",
			Secret:      "AKIAIOSFODNN7EXAMPLE",
			File:        "Config.java",
			StartLine:   42,
			Match:       "AKIAIOSFODNN7EXAMPLE",
		},
	}
	raw, _ := json.Marshal(gf)

	findings := ConvertGitleaksFindings(raw, "test-session")
	require.Len(t, findings, 1)

	f := findings[0]
	assert.NotEmpty(t, f.ID)
	assert.Equal(t, "test-session", f.SessionID)
	assert.Equal(t, "gitleaks", f.SourceTool)
	assert.Equal(t, "secret", string(f.Category))
	assert.Equal(t, "critical", string(f.Severity))
	assert.Equal(t, "secret", string(f.Sensitivity))
	assert.True(t, f.NeedsLLMTriage)
	assert.True(t, f.Representative)
	assert.Equal(t, "Config.java", f.Location.File)
	assert.Equal(t, 42, f.Location.Line)
}

func TestConvertGitleaksFindings_InvalidJSON(t *testing.T) {
	findings := ConvertGitleaksFindings(json.RawMessage(`{invalid`), "test")
	assert.Nil(t, findings)
}

func TestConvertGitleaksFindings_Multiple(t *testing.T) {
	gf := []GitleaksFinding{
		{RuleID: "r1", Secret: "s1", File: "a.java", StartLine: 1, Match: "m1"},
		{RuleID: "r2", Secret: "s2", File: "b.java", StartLine: 2, Match: "m2"},
	}
	raw, _ := json.Marshal(gf)
	findings := ConvertGitleaksFindings(raw, "sess")
	assert.Len(t, findings, 2)
}

func TestGitleaks_DeterministicID(t *testing.T) {
	gf := []GitleaksFinding{
		{RuleID: "r1", Secret: "s1", File: "a.java", StartLine: 1, Match: "m1"},
	}
	raw, _ := json.Marshal(gf)

	f1 := ConvertGitleaksFindings(raw, "s1")
	f2 := ConvertGitleaksFindings(raw, "s1")
	assert.Equal(t, f1[0].ID, f2[0].ID)
}
