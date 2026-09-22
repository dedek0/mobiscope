package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateID_Deterministic(t *testing.T) {
	id1 := GenerateID("semgrep", CategorySecret, "src/main.java", 42, "apiKey = \"AKIA1234\"")
	id2 := GenerateID("semgrep", CategorySecret, "src/main.java", 42, "apiKey = \"AKIA1234\"")
	assert.Equal(t, id1, id2)
	assert.Len(t, id1, 16)
}

func TestGenerateID_DifferentInputs(t *testing.T) {
	id1 := GenerateID("semgrep", CategorySecret, "a.java", 1, "x")
	id2 := GenerateID("gitleaks", CategorySecret, "a.java", 1, "x")
	assert.NotEqual(t, id1, id2)
}

func TestFinding_RoundTrip(t *testing.T) {
	original := Finding{
		ID:             "abc123456789abcd",
		SessionID:      "sess-001",
		SourceTool:     "semgrep",
		Category:       CategorySecret,
		Title:          "Hardcoded API key",
		Description:    "Found hardcoded AWS key",
		Evidence:       "apiKey = \"AKIAIOSFODNN7EXAMPLE\"",
		Location:       Location{File: "src/main.java", Line: 42, Snippet: "apiKey = \"AKIA...\""},
		Severity:       SeverityHigh,
		Sensitivity:    SensitivityConfidential,
		Confidence:     0.95,
		NeedsLLMTriage: true,
		ClusterID:      "cluster-01",
		Representative: true,
		LLMVerdict:     VerdictConfirmed,
		LLMConfidence:  0.92,
		LLMExplanation: "Pattern matches known AWS key format",
		LLMRemediation: "Use environment variables or secret manager",
		LLMProvider:    "ollama",
		LLMModel:       "qwen2.5-coder:7b",
		LLMCostUSD:     0.0,
		LLMRawResponse: "{\"verdict\":\"confirmed\"}",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var restored Finding
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, original.ID, restored.ID)
	assert.Equal(t, original.SessionID, restored.SessionID)
	assert.Equal(t, original.SourceTool, restored.SourceTool)
	assert.Equal(t, original.Category, restored.Category)
	assert.Equal(t, original.Title, restored.Title)
	assert.Equal(t, original.Description, restored.Description)
	assert.Equal(t, original.Evidence, restored.Evidence)
	assert.Equal(t, original.Location, restored.Location)
	assert.Equal(t, original.Severity, restored.Severity)
	assert.Equal(t, original.Sensitivity, restored.Sensitivity)
	assert.Equal(t, original.Confidence, restored.Confidence)
	assert.Equal(t, original.NeedsLLMTriage, restored.NeedsLLMTriage)
	assert.Equal(t, original.ClusterID, restored.ClusterID)
	assert.Equal(t, original.Representative, restored.Representative)
	assert.Equal(t, original.LLMVerdict, restored.LLMVerdict)
	assert.Equal(t, original.LLMConfidence, restored.LLMConfidence)
	assert.Equal(t, original.LLMExplanation, restored.LLMExplanation)
	assert.Equal(t, original.LLMRemediation, restored.LLMRemediation)
	assert.Equal(t, original.LLMProvider, restored.LLMProvider)
	assert.Equal(t, original.LLMModel, restored.LLMModel)
	assert.Equal(t, original.LLMCostUSD, restored.LLMCostUSD)
	assert.Equal(t, original.LLMRawResponse, restored.LLMRawResponse)
}

func TestFinding_ZeroValueOmitempty(t *testing.T) {
	f := Finding{
		ID:          "id00000000000001",
		SessionID:   "s1",
		SourceTool:  "tool",
		Category:    CategoryCodePattern,
		Title:       "test",
		Severity:    SeverityInfo,
		Sensitivity: SensitivityPublic,
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)

	s := string(data)
	assert.NotContains(t, s, `"description"`)
	assert.NotContains(t, s, `"evidence"`)
	assert.NotContains(t, s, `"confidence"`)
	assert.NotContains(t, s, `"needs_llm_triage"`)
	assert.NotContains(t, s, `"cluster_id"`)
	assert.NotContains(t, s, `"representative"`)
	assert.NotContains(t, s, `"llm_verdict"`)
	assert.NotContains(t, s, `"llm_confidence"`)
	assert.NotContains(t, s, `"llm_explanation"`)
	assert.NotContains(t, s, `"llm_remediation"`)
	assert.NotContains(t, s, `"llm_provider"`)
	assert.NotContains(t, s, `"llm_model"`)
	assert.NotContains(t, s, `"llm_cost_usd"`)
	assert.NotContains(t, s, `"llm_raw_response"`)
	assert.Contains(t, s, `"id"`)
	assert.Contains(t, s, `"title"`)
}

func TestFinding_LocationOmitempty(t *testing.T) {
	f := Finding{
		ID:       "id00000000000002",
		Location: Location{},
	}

	data, err := json.Marshal(f)
	require.NoError(t, err)
	assert.NotContains(t, string(data), `"file"`)
	assert.NotContains(t, string(data), `"line"`)
	assert.NotContains(t, string(data), `"snippet"`)
}

func TestSeverity_MarshalJSON(t *testing.T) {
	tests := []struct {
		input Severity
		want  string
	}{
		{SeverityCritical, `"critical"`},
		{SeverityHigh, `"high"`},
		{SeverityMedium, `"medium"`},
		{SeverityLow, `"low"`},
		{SeverityInfo, `"info"`},
	}
	for _, tt := range tests {
		data, err := json.Marshal(tt.input)
		require.NoError(t, err)
		assert.Equal(t, tt.want, string(data))
	}
}

func TestSeverity_UnmarshalJSON(t *testing.T) {
	var s Severity
	require.NoError(t, json.Unmarshal([]byte(`"critical"`), &s))
	assert.Equal(t, SeverityCritical, s)
}

func TestSeverity_UnmarshalJSON_Invalid(t *testing.T) {
	var s Severity
	err := json.Unmarshal([]byte(`"bogus"`), &s)
	assert.Error(t, err)
}

func TestCategory_MarshalJSON(t *testing.T) {
	tests := []struct {
		input Category
		want  string
	}{
		{CategorySecret, `"secret"`},
		{CategoryCodePattern, `"code_pattern"`},
		{CategoryManifestIssue, `"manifest_issue"`},
		{CategoryNetworkConfig, `"network_config"`},
		{CategoryPinningIndicator, `"pinning_indicator"`},
	}
	for _, tt := range tests {
		data, err := json.Marshal(tt.input)
		require.NoError(t, err)
		assert.Equal(t, tt.want, string(data))
	}
}

func TestCategory_UnmarshalJSON(t *testing.T) {
	var c Category
	require.NoError(t, json.Unmarshal([]byte(`"secret"`), &c))
	assert.Equal(t, CategorySecret, c)
}

func TestCategory_UnmarshalJSON_Invalid(t *testing.T) {
	var c Category
	err := json.Unmarshal([]byte(`"bogus"`), &c)
	assert.Error(t, err)
}

func TestSensitivity_MarshalJSON(t *testing.T) {
	tests := []struct {
		input Sensitivity
		want  string
	}{
		{SensitivityPublic, `"public"`},
		{SensitivityInternal, `"internal"`},
		{SensitivityConfidential, `"confidential"`},
		{SensitivitySecret, `"secret"`},
	}
	for _, tt := range tests {
		data, err := json.Marshal(tt.input)
		require.NoError(t, err)
		assert.Equal(t, tt.want, string(data))
	}
}

func TestSensitivity_UnmarshalJSON(t *testing.T) {
	var s Sensitivity
	require.NoError(t, json.Unmarshal([]byte(`"confidential"`), &s))
	assert.Equal(t, SensitivityConfidential, s)
}

func TestSensitivity_UnmarshalJSON_Invalid(t *testing.T) {
	var s Sensitivity
	err := json.Unmarshal([]byte(`"bogus"`), &s)
	assert.Error(t, err)
}

func TestVerdict_MarshalJSON(t *testing.T) {
	tests := []struct {
		input Verdict
		want  string
	}{
		{VerdictConfirmed, `"confirmed"`},
		{VerdictLikelyFP, `"likely_fp"`},
		{VerdictInconclusive, `"inconclusive"`},
	}
	for _, tt := range tests {
		data, err := json.Marshal(tt.input)
		require.NoError(t, err)
		assert.Equal(t, tt.want, string(data))
	}
}

func TestVerdict_UnmarshalJSON(t *testing.T) {
	var v Verdict
	require.NoError(t, json.Unmarshal([]byte(`"confirmed"`), &v))
	assert.Equal(t, VerdictConfirmed, v)
}

func TestVerdict_UnmarshalJSON_Invalid(t *testing.T) {
	var v Verdict
	err := json.Unmarshal([]byte(`"bogus"`), &v)
	assert.Error(t, err)
}

func TestSeverity_String(t *testing.T) {
	assert.Equal(t, "critical", SeverityCritical.String())
	assert.Equal(t, "info", SeverityInfo.String())
}

func TestCategory_String(t *testing.T) {
	assert.Equal(t, "secret", CategorySecret.String())
	assert.Equal(t, "pinning_indicator", CategoryPinningIndicator.String())
}

func TestSensitivity_String(t *testing.T) {
	assert.Equal(t, "public", SensitivityPublic.String())
	assert.Equal(t, "secret", SensitivitySecret.String())
}

func TestVerdict_String(t *testing.T) {
	assert.Equal(t, "confirmed", VerdictConfirmed.String())
	assert.Equal(t, "likely_fp", VerdictLikelyFP.String())
}

func TestGenerateID_FieldCollision(t *testing.T) {
	// "a.java" + line 12 must differ from "a.java1" + line 2 (delimiter-less concat collided).
	id1 := GenerateID("semgrep", CategorySecret, "a.java", 12, "x")
	id2 := GenerateID("semgrep", CategorySecret, "a.java1", 2, "x")
	assert.NotEqual(t, id1, id2)
}

func TestGenerateID_ToolCategoryShift(t *testing.T) {
	id1 := GenerateID("gitleaks", CategorySecret, "f", 1, "s")
	id2 := GenerateID("gitleakss", CategorySecret, "f", 1, "s")
	assert.NotEqual(t, id1, id2)
}
