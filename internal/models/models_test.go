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

func TestPlatform_JSONRoundTrip(t *testing.T) {
	for _, p := range []Platform{PlatformAndroid, PlatformIOS, PlatformUnknown} {
		data, err := json.Marshal(p)
		require.NoError(t, err)
		var got Platform
		require.NoError(t, json.Unmarshal(data, &got))
		assert.Equal(t, p, got)
	}

	// Empty decodes as unknown rather than failing.
	var got Platform
	require.NoError(t, json.Unmarshal([]byte(`""`), &got))
	assert.Equal(t, PlatformUnknown, got)
}

func TestCategory_NewValuesRoundTrip(t *testing.T) {
	for _, c := range []Category{
		CategoryEntitlement, CategoryBinaryHardening,
		CategoryObfuscation, CategoryNativeCode, CategoryPrivacy,
	} {
		data, err := json.Marshal(c)
		require.NoError(t, err)
		var got Category
		require.NoError(t, json.Unmarshal(data, &got))
		assert.Equal(t, c, got)
	}

	var got Category
	require.Error(t, json.Unmarshal([]byte(`"nope"`), &got))
}

func TestFinding_StandardsFieldsRoundTrip(t *testing.T) {
	f := Finding{
		ID:          "a",
		SessionID:   "b",
		SourceTool:  "semgrep",
		Category:    CategorySecret,
		Title:       "t",
		Severity:    SeverityHigh,
		Sensitivity: SensitivitySecret,
		Platform:    PlatformIOS,
		RuleID:      "ios.ats.arbitrary-loads",
		MASVS:       []string{"MASVS-NETWORK-1"},
		MASTG:       []string{"MASTG-TEST-0064"},
		MASWE:       []string{"MASWE-0020"},
		CWE:         []string{"CWE-319"},
		Metadata:    map[string]string{"entitlement": "get-task-allow"},
	}
	data, err := json.Marshal(f)
	require.NoError(t, err)

	var got Finding
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, PlatformIOS, got.Platform)
	assert.Equal(t, "ios.ats.arbitrary-loads", got.RuleID)
	assert.Equal(t, []string{"MASVS-NETWORK-1"}, got.MASVS)
	assert.Equal(t, []string{"CWE-319"}, got.CWE)
	assert.Equal(t, "get-task-allow", got.Metadata["entitlement"])
}

func TestAppInventory_RoundTrip(t *testing.T) {
	app := AppInventory{
		BundleID:    "com.example.app",
		VersionName: "1.2.3",
		VersionCode: "45",
		MinOS:       "14.0",
		Debuggable:  true,
		Obfuscation: ObfuscationInfo{Android: true, Score: 0.7, Indicators: []string{"r8"}},
		NativeLibs:  []NativeLib{{Path: "lib/arm64-v8a/libfoo.so", Kind: "so", Archs: []string{"arm64"}}},
		Network: NetworkPolicy{
			Kind:               "network_security_config",
			CleartextPermitted: true,
			Exceptions:         []NetworkException{{Domain: "api.example.com", InsecureHTTPLoads: true}},
		},
		Permissions: []string{"android.permission.CAMERA"},
	}
	data, err := json.Marshal(app)
	require.NoError(t, err)

	var got AppInventory
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, app.BundleID, got.BundleID)
	assert.Equal(t, app.Obfuscation.Score, got.Obfuscation.Score)
	assert.Equal(t, app.NativeLibs[0].Path, got.NativeLibs[0].Path)
	assert.True(t, got.Network.Exceptions[0].InsecureHTTPLoads)
}
