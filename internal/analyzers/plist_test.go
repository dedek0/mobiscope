package analyzers

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildPlistRaw marshals a plistOutput into the JSON shape PlistAnalyzer.Run
// produces.
func buildPlistRaw(t *testing.T, out plistOutput) []byte {
	t.Helper()
	raw, err := json.Marshal(out)
	require.NoError(t, err)
	return raw
}

// findingBySubstring returns the first finding whose title contains substr.
func findingBySubstring(findings []models.Finding, substr string) *models.Finding {
	for i := range findings {
		if strings.Contains(findings[i].Title, substr) {
			return &findings[i]
		}
	}
	return nil
}

// TestConvertPlistFindings_ATSMatrix walks the full NSAppTransportSecurity
// matrix from PENDING §1.4/§1.7 and pins severity per case.
func TestConvertPlistFindings_ATSMatrix(t *testing.T) {
	tests := []struct {
		name      string
		ats       map[string]interface{}
		wantTitle string // substring; empty = no finding expected
		wantSev   string
	}{
		{
			name:      "NSAllowsArbitraryLoads",
			ats:       map[string]interface{}{"NSAllowsArbitraryLoads": true},
			wantTitle: "arbitrary loads allowed",
			wantSev:   "high",
		},
		{
			name:      "NSAllowsArbitraryLoadsInWebContent",
			ats:       map[string]interface{}{"NSAllowsArbitraryLoadsInWebContent": true},
			wantTitle: "NSAllowsArbitraryLoadsInWebContent",
			wantSev:   "medium",
		},
		{
			name:      "NSAllowsArbitraryLoadsInMediaStreaming",
			ats:       map[string]interface{}{"NSAllowsArbitraryLoadsInMediaStreaming": true},
			wantTitle: "NSAllowsArbitraryLoadsInMediaStreaming",
			wantSev:   "medium",
		},
		{
			name:      "NSAllowsLocalNetworking",
			ats:       map[string]interface{}{"NSAllowsLocalNetworking": true},
			wantTitle: "local networking allowed",
			wantSev:   "low",
		},
		{
			name: "NSExceptionAllowsInsecureHTTPLoads",
			ats: map[string]interface{}{
				"NSExceptionDomains": map[string]interface{}{
					"api.example.com": map[string]interface{}{
						"NSExceptionAllowsInsecureHTTPLoads": true,
					},
				},
			},
			wantTitle: "api.example.com",
			wantSev:   "high",
		},
		{
			name: "NSTemporaryExceptionAllowsInsecureHTTPLoads",
			ats: map[string]interface{}{
				"NSExceptionDomains": map[string]interface{}{
					"legacy.example.com": map[string]interface{}{
						"NSTemporaryExceptionAllowsInsecureHTTPLoads": true,
					},
				},
			},
			wantTitle: "legacy.example.com",
			wantSev:   "high",
		},
		{
			name: "weak NSTemporaryExceptionMinimumTLSVersion is flagged",
			ats: map[string]interface{}{
				"NSExceptionDomains": map[string]interface{}{
					"tls.example.com": map[string]interface{}{
						"NSTemporaryExceptionMinimumTLSVersion": "1.0",
					},
				},
			},
			wantTitle: "tls.example.com",
			wantSev:   "medium",
		},
		{
			name: "strong NSExceptionMinimumTLSVersion=1.2 is not flagged",
			ats: map[string]interface{}{
				"NSExceptionDomains": map[string]interface{}{
					"modern.example.com": map[string]interface{}{
						"NSExceptionMinimumTLSVersion": "1.2",
					},
				},
			},
			wantTitle: "",
		},
		{
			name: "insecure HTTP with NSIncludesSubdomains=true is flagged",
			ats: map[string]interface{}{
				"NSExceptionDomains": map[string]interface{}{
					"sub.example.com": map[string]interface{}{
						"NSExceptionAllowsInsecureHTTPLoads": true,
						"NSIncludesSubdomains":               true,
					},
				},
			},
			wantTitle: "sub.example.com",
			wantSev:   "high",
		},
		{
			name: "NSIncludesSubdomains alone is not a finding",
			ats: map[string]interface{}{
				"NSExceptionDomains": map[string]interface{}{
					"ok.example.com": map[string]interface{}{
						"NSIncludesSubdomains": true,
					},
				},
			},
			wantTitle: "",
		},
		{
			name:      "empty ATS block",
			ats:       map[string]interface{}{},
			wantTitle: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := buildPlistRaw(t, plistOutput{ATS: tt.ats})
			findings := ConvertPlistFindings(raw, "sess-ats")

			if tt.wantTitle == "" {
				assert.Empty(t, findings)
				return
			}

			f := findingBySubstring(findings, tt.wantTitle)
			require.NotNil(t, f, "expected finding containing %q, got %v", tt.wantTitle, titlesOf(findings))
			assert.Equal(t, tt.wantSev, string(f.Severity))
			assert.Equal(t, "network_config", string(f.Category))
			assert.Equal(t, "ios", string(f.Platform))
			assert.Equal(t, "plist", f.SourceTool)
			assert.Equal(t, "Info.plist", f.Location.File)
			assert.Equal(t, "sess-ats", f.SessionID)
		})
	}
}

// titlesOf is a small helper for failure messages.
func titlesOf(findings []models.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Title)
	}
	return out
}

func TestConvertPlistFindings_ATSFalseAndWrongTypes(t *testing.T) {
	// Explicit false / wrong types must not fire.
	raw := buildPlistRaw(t, plistOutput{ATS: map[string]interface{}{
		"NSAllowsArbitraryLoads":             false,
		"NSAllowsLocalNetworking":            "yes",
		"NSAllowsArbitraryLoadsInWebContent": nil,
	}})
	assert.Empty(t, ConvertPlistFindings(raw, "s"))
}

func TestConvertPlistFindings_FileSharingAndURLSchemes(t *testing.T) {
	raw := buildPlistRaw(t, plistOutput{
		FileSharing: true,
		URLSchemes:  []string{"http", "myapp"},
	})
	findings := ConvertPlistFindings(raw, "s")
	require.Len(t, findings, 2)

	f := findingBySubstring(findings, "file sharing")
	require.NotNil(t, f)
	assert.Equal(t, "privacy", string(f.Category))
	assert.Equal(t, "medium", string(f.Severity))
	assert.Equal(t, "ios", string(f.Platform))

	f = findingBySubstring(findings, "http")
	require.NotNil(t, f)
	assert.Equal(t, "manifest_issue", string(f.Category))
	assert.Equal(t, "high", string(f.Severity))
}
