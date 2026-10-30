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

func TestMarkdownReporter_EnglishAndExecutiveSummary(t *testing.T) {
	session := testSession()
	session.LLMCostUSD = 0.012345
	session.Findings[0].LLMVerdict = models.VerdictConfirmed
	r := &MarkdownReporter{}

	var buf bytes.Buffer
	require.NoError(t, r.Render(session, &buf))
	output := buf.String()

	// Report is fully English (docs standard).
	assert.Contains(t, output, "# mobiscope — Analysis Report")
	assert.Contains(t, output, "## Executive summary")
	assert.Contains(t, output, "**Total findings:**")
	assert.Contains(t, output, "| Severity | Count |")
	assert.NotContains(t, output, "Relatório")
	assert.NotContains(t, output, "Severidade")

	// Executive summary carries cluster/category/triage/cost lines.
	assert.Contains(t, output, "in 1 cluster(s)")
	assert.Contains(t, output, "Top clusters:")
	assert.Contains(t, output, "Top categories:")
	assert.Contains(t, output, "LLM triage:")
	assert.Contains(t, output, "cost $0.012345")
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

func TestShortID_ShortDoesNotPanic(t *testing.T) {
	assert.Equal(t, "abc", shortID("abc"))
	assert.Equal(t, "12345678", shortID("12345678"))
	assert.Equal(t, "12345678", shortID("1234567890abcdef"))
}

func TestMarkdownReporter_OnlyRepresentatives(t *testing.T) {
	session := &models.AnalysisSession{
		ID:     "s",
		Status: models.StatusCompleted,
		Findings: []models.Finding{
			{
				ID: "rep1", Title: "Representative", Category: models.CategoryCodePattern,
				Severity: models.SeverityHigh, ClusterID: "cl-1", Representative: true,
				Location: models.Location{File: "A.java", Line: 1},
			},
			{
				ID: "mem1", Title: "Cluster member", Category: models.CategoryCodePattern,
				Severity: models.SeverityHigh, ClusterID: "cl-1", Representative: false,
				Location: models.Location{File: "B.java", Line: 2},
			},
		},
	}
	var buf bytes.Buffer
	require.NoError(t, (&MarkdownReporter{}).Render(session, &buf))
	out := buf.String()

	assert.Contains(t, out, "Representative")
	assert.NotContains(t, out, "Cluster member")
	assert.Contains(t, out, "and 1 more occurrence(s)")
}

func TestBuildMDData_UnknownSeverityGroup(t *testing.T) {
	session := &models.AnalysisSession{
		ID:     "s",
		Status: models.StatusCompleted,
		Findings: []models.Finding{
			{ID: "aaaaaaa1", Title: "A", Severity: models.SeverityCritical},
			{ID: "b", Title: "B", Severity: ""},
		},
	}
	data := buildMDData(session)
	sevs := make([]string, 0, len(data.Groups))
	for _, g := range data.Groups {
		sevs = append(sevs, g.Severity)
	}
	assert.Contains(t, sevs, "critical")
	assert.Contains(t, sevs, "")
	assert.Len(t, data.Groups, 2)
}

func TestMarkdownReporter_AttackSurface(t *testing.T) {
	session := testSession()
	session.App = models.AppInventory{
		BundleID:    "com.example.app",
		VersionName: "1.2.3",
		TargetSDK:   "35",
		Permissions: []string{"android.permission.CAMERA"},
		SDKs:        []models.SDK{{Name: "OkHttp", Version: "4.12.0"}},
		NativeLibs:  []models.NativeLib{{Path: "lib/arm64-v8a/libx.so", Archs: []string{"arm64-v8a"}}},
		Network:     models.NetworkPolicy{Kind: "network_security_config", CleartextPermitted: true, Pinned: true},
	}
	session.SignatureScheme = "v3"
	session.SigningCertFP = "dda7f0a5689c6e35c12ad5"

	var buf bytes.Buffer
	require.NoError(t, (&MarkdownReporter{}).Render(session, &buf))
	out := buf.String()
	assert.Contains(t, out, "## Attack surface")
	assert.Contains(t, out, "com.example.app")
	assert.Contains(t, out, "OkHttp 4.12.0")
	assert.Contains(t, out, "network_security_config, cleartext allowed, pinned")
	assert.Contains(t, out, "v3 (dda7f0a5689c6e35)")
	assert.Contains(t, out, "android.permission.CAMERA")
}
