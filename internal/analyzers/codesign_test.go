package analyzers

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildCodesignRaw marshals an entitlements map into the JSON shape
// CodeSign.Run produces.
func buildCodesignRaw(t *testing.T, entitlements map[string]interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]interface{}{"entitlements": entitlements})
	require.NoError(t, err)
	return raw
}

// TestConvertCodeSignFindings_Severities pins the severity, category,
// platform and session wiring for every entitlement rule.
func TestConvertCodeSignFindings_Severities(t *testing.T) {
	tests := []struct {
		name        string
		ent         map[string]interface{}
		wantTitle   string
		wantSev     string
		wantFinding bool
	}{
		{
			name:        "get-task-allow",
			ent:         map[string]interface{}{"get-task-allow": true},
			wantTitle:   "Debug entitlement: get-task-allow",
			wantSev:     "critical",
			wantFinding: true,
		},
		{
			name:        "task_for_pid-allow",
			ent:         map[string]interface{}{"task_for_pid-allow": true},
			wantTitle:   "Dangerous entitlement: task_for_pid-allow",
			wantSev:     "critical",
			wantFinding: true,
		},
		{
			name:        "disable-library-validation",
			ent:         map[string]interface{}{"com.apple.security.cs.disable-library-validation": true},
			wantTitle:   "Library validation disabled",
			wantSev:     "high",
			wantFinding: true,
		},
		{
			name:        "allow-dyld-environment-variables",
			ent:         map[string]interface{}{"com.apple.security.cs.allow-dyld-environment-variables": true},
			wantTitle:   "DYLD environment variables allowed",
			wantSev:     "high",
			wantFinding: true,
		},
		{
			name:        "private entitlement",
			ent:         map[string]interface{}{"com.apple.private.security.network": true},
			wantTitle:   "Private entitlement: com.apple.private.security.network",
			wantSev:     "high",
			wantFinding: true,
		},
		{
			name:        "aps-environment development",
			ent:         map[string]interface{}{"aps-environment": "development"},
			wantTitle:   "APNs environment is development",
			wantSev:     "low",
			wantFinding: true,
		},
		{
			name:        "keychain wildcard star",
			ent:         map[string]interface{}{"keychain-access-groups": []interface{}{"ABC123.com.example"}},
			wantFinding: false,
		},
		{
			name:        "benign entitlement produces nothing",
			ent:         map[string]interface{}{"application-identifier": "TEAM.com.example"},
			wantFinding: false,
		},
		{
			name:        "false boolean produces nothing",
			ent:         map[string]interface{}{"get-task-allow": false},
			wantFinding: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ConvertCodeSignFindings(buildCodesignRaw(t, tt.ent), "sess-7")
			if !tt.wantFinding {
				assert.Empty(t, findings)
				return
			}
			require.Len(t, findings, 1)
			f := findings[0]
			assert.Equal(t, tt.wantTitle, f.Title)
			assert.Equal(t, tt.wantSev, string(f.Severity))
			assert.Equal(t, "entitlement", string(f.Category))
			assert.Equal(t, "ios", string(f.Platform))
			assert.Equal(t, "codesign", f.SourceTool)
			assert.Equal(t, "sess-7", f.SessionID)
			assert.NotEmpty(t, f.ID)
			assert.NotZero(t, f.Confidence)
		})
	}
}

// TestConvertCodeSignFindings_KeychainWildcard covers the wildcard rules for
// keychain-access-groups: "*" and "*.suffix" are flagged, explicit group IDs
// are not.
func TestConvertCodeSignFindings_KeychainWildcard(t *testing.T) {
	tests := []struct {
		name  string
		group []interface{}
		want  int
	}{
		{"star alone", []interface{}{"*"}, 1},
		{"star suffix", []interface{}{"*.something"}, 1},
		{"star among explicit groups", []interface{}{"ABC123.com.app", "*", "*.x"}, 2},
		{"explicit groups only", []interface{}{"ABC123.com.app", "TEAMID.shared"}, 0},
		{"empty list", []interface{}{}, 0},
		{"non-string entries ignored", []interface{}{42, true}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := buildCodesignRaw(t, map[string]interface{}{"keychain-access-groups": tt.group})
			findings := ConvertCodeSignFindings(raw, "s")
			assert.Len(t, findings, tt.want)
			for _, f := range findings {
				assert.Equal(t, "Wildcard keychain access group", f.Title)
				assert.Equal(t, "high", string(f.Severity))
				assert.Equal(t, "entitlement", string(f.Category))
				assert.Equal(t, "ios", string(f.Platform))
				assert.Contains(t, f.Evidence, "keychain-access-groups=")
			}
		})
	}
}

func TestConvertCodeSignFindings_KeychainStringAndOddTypes(t *testing.T) {
	// A lone string value (defensive: some profiles store a single group).
	raw := buildCodesignRaw(t, map[string]interface{}{"keychain-access-groups": "*"})
	findings := ConvertCodeSignFindings(raw, "s")
	require.Len(t, findings, 1)
	assert.Equal(t, "high", string(findings[0].Severity))

	// Wrong types must be ignored without panicking.
	for _, v := range []interface{}{map[string]interface{}{"a": 1}, 3.5, nil, true} {
		raw := buildCodesignRaw(t, map[string]interface{}{"keychain-access-groups": v})
		assert.NotPanics(t, func() {
			ConvertCodeSignFindings(raw, "s")
		})
	}
}

// TestCodeSign_Run_KeychainWildcard exercises the full analyzer: an
// entitlements.plist on disk with a wildcard group must surface as a finding.
func TestCodeSign_Run_KeychainWildcard(t *testing.T) {
	workdir := t.TempDir()
	bundle := filepath.Join(IPAExtractArtifactPath(workdir), "Payload", "App.app")
	writePlist(t, filepath.Join(bundle, "Info.plist"), map[string]interface{}{
		"CFBundleExecutable": "App",
	})
	writePlist(t, filepath.Join(bundle, "entitlements.plist"), map[string]interface{}{
		"keychain-access-groups": []interface{}{"ABC123.com.example", "*"},
		"aps-environment":        "production",
	})

	c := NewCodeSign()
	res, err := c.Run(context.Background(), "", workdir)
	require.NoError(t, err)

	findings := ConvertCodeSignFindings(res.Output, "s")
	require.Len(t, findings, 1)
	assert.Equal(t, "Wildcard keychain access group", findings[0].Title)
	assert.Equal(t, "high", string(findings[0].Severity))
	assert.Equal(t, "entitlement", string(findings[0].Category))
	assert.Equal(t, "ios", string(findings[0].Platform))
}
