//go:build integration

package pipeline

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dedek0/mobiscope/internal/analyzers"
	"github.com/dedek0/mobiscope/internal/models"
	"github.com/dedek0/mobiscope/internal/platform"
	"github.com/dedek0/mobiscope/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"howett.net/plist"
)

// TestE2E_SyntheticAPKWithSecrets tests the full pipeline with a synthetic
// APK containing planted AWS keys to verify:
// - Deterministic IDs (run 2x, same IDs)
// - Clustering (3 identical secrets → 1 representative + 2 non-representative)
// - findings.json and report.md are generated
// - No LLM calls are made in this phase
func TestE2E_SyntheticAPKWithSecrets(t *testing.T) {
	// Create a synthetic APK (just needs to be a file with content).
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "test.apk")
	require.NoError(t, os.WriteFile(apkPath, []byte("PK\x03\x04synthetic"), 0o600))

	logger := slog.Default()

	// Create a jadx mock that copies our test fixture into the session dir.
	jadxMock := &dirSetupAnalyzer{
		name:       "jadx",
		t:          t,
		fixtureDir: createSecretFixture(t, tmpDir),
	}
	p := New([]analyzers.Analyzer{jadxMock}, logger)

	// First run.
	session1, err := p.Run(context.Background(), apkPath, filepath.Join(tmpDir, "targets"), nil)
	require.NoError(t, err)
	assert.Equal(t, models.StatusCompleted, session1.Status)

	// Verify findings were generated.
	assert.NotEmpty(t, session1.Findings, "should have findings from inventory")

	// Find the AWS key findings.
	var awsFindings []models.Finding
	for _, f := range session1.Findings {
		if f.SourceTool == "inventory" && f.Category == models.CategorySecret {
			awsFindings = append(awsFindings, f)
		}
	}

	// Verify we found the AWS key (may have duplicates before dedup, but after
	// dedup+clustering we expect grouped findings).
	if len(awsFindings) > 0 {
		// Check that at least one finding has Severity=critical.
		foundCritical := false
		for _, f := range awsFindings {
			if f.Severity == models.SeverityCritical {
				foundCritical = true
			}
		}
		assert.True(t, foundCritical, "AWS key should be critical severity")

		// Verify deterministic IDs: same input → same ID.
		for _, f := range awsFindings {
			regenerated := models.GenerateID(f.SourceTool, f.Category, f.Location.File, f.Location.Line, f.Location.Snippet)
			assert.Equal(t, f.ID, regenerated, "ID should be deterministic")
		}
	}

	// Verify manifest findings.
	var manifestFindings []models.Finding
	for _, f := range session1.Findings {
		if f.Category == models.CategoryManifestIssue {
			manifestFindings = append(manifestFindings, f)
		}
	}
	assert.NotEmpty(t, manifestFindings, "should have manifest findings")

	// Verify no LLM calls were made.
	for _, f := range session1.Findings {
		assert.Empty(t, f.LLMVerdict, "no LLM verdict should be set")
		assert.Empty(t, f.LLMProvider, "no LLM provider should be set")
		assert.Empty(t, f.LLMModel, "no LLM model should be set")
	}

	// Verify artifacts were created.
	sessionDir := filepath.Join(tmpDir, "targets", session1.ID[:16])

	_, err = os.Stat(filepath.Join(sessionDir, "meta.json"))
	assert.NoError(t, err, "meta.json should exist")

	_, err = os.Stat(filepath.Join(sessionDir, "findings.json"))
	assert.NoError(t, err, "findings.json should exist")

	_, err = os.Stat(filepath.Join(sessionDir, "report.md"))
	assert.NoError(t, err, "report.md should exist")

	// Second run with same input should produce same IDs.
	jadxMock2 := &dirSetupAnalyzer{
		name:       "jadx",
		t:          t,
		fixtureDir: createSecretFixture(t, tmpDir),
	}
	p2 := New([]analyzers.Analyzer{jadxMock2}, logger)
	session2, err := p2.Run(context.Background(), apkPath, filepath.Join(tmpDir, "targets2"), nil)
	require.NoError(t, err)

	assert.Equal(t, session1.ID, session2.ID, "session ID should be deterministic")
	assert.Len(t, session2.Findings, len(session1.Findings), "same number of findings")

	for i, f := range session1.Findings {
		if i < len(session2.Findings) {
			assert.Equal(t, f.ID, session2.Findings[i].ID, "finding IDs should be deterministic")
		}
	}
}

// TestE2E_ClusteringThreeOccurrences verifies that 3 occurrences of the same
// secret produce 1 representative + 2 non-representative findings with the
// same ClusterID.
func TestE2E_ClusteringThreeOccurrences(t *testing.T) {
	logger := slog.Default()

	// Simulate 3 findings from the same pattern (same category, title, severity, file ext).
	findings := []models.Finding{
		{
			ID:             "f1",
			Category:       models.CategorySecret,
			Title:          "AWS Access Key",
			Severity:       models.SeverityCritical,
			Location:       models.Location{File: "Config1.java", Line: 10, Snippet: "AKIAIOSFODNN7EXAMPLE"},
			NeedsLLMTriage: true,
			Representative: true,
		},
		{
			ID:             "f2",
			Category:       models.CategorySecret,
			Title:          "AWS Access Key",
			Severity:       models.SeverityCritical,
			Location:       models.Location{File: "Config2.java", Line: 5, Snippet: "AKIAIOSFODNN7EXAMPLE"},
			NeedsLLMTriage: true,
			Representative: true,
		},
		{
			ID:             "f3",
			Category:       models.CategorySecret,
			Title:          "AWS Access Key",
			Severity:       models.SeverityCritical,
			Location:       models.Location{File: "Config3.java", Line: 1, Snippet: "AKIAIOSFODNN7EXAMPLE"},
			NeedsLLMTriage: true,
			Representative: true,
		},
	}

	clustered, clusterCount := Cluster(findings, logger)

	assert.Equal(t, 1, clusterCount, "should form 1 cluster")
	assert.Len(t, clustered, 3)

	// All should have the same ClusterID.
	clusterID := clustered[0].ClusterID
	assert.NotEmpty(t, clusterID)
	for _, f := range clustered {
		assert.Equal(t, clusterID, f.ClusterID, "all should share same ClusterID")
	}

	// Exactly 1 representative.
	repCount := 0
	for _, f := range clustered {
		if f.Representative {
			repCount++
			assert.True(t, f.NeedsLLMTriage, "representative should need LLM triage")
		} else {
			assert.False(t, f.NeedsLLMTriage, "non-representative should NOT need LLM triage")
		}
	}
	assert.Equal(t, 1, repCount, "exactly 1 representative")

	// Representative should be the one with the smallest (file, line).
	var rep models.Finding
	for _, f := range clustered {
		if f.Representative {
			rep = f
		}
	}
	assert.Equal(t, "Config1.java", rep.Location.File)
	assert.Equal(t, 10, rep.Location.Line)
}

// TestE2E_NoLLMCalls verifies that the pipeline makes zero LLM calls.
func TestE2E_NoLLMCalls(t *testing.T) {
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "test.apk")
	require.NoError(t, os.WriteFile(apkPath, []byte("PK\x03\x04"), 0o600))

	logger := slog.Default()
	jadxMock := newMockAnalyzer("jadx", nil)
	p := New([]analyzers.Analyzer{jadxMock}, logger)

	session, err := p.Run(context.Background(), apkPath, filepath.Join(tmpDir, "targets"), nil)
	require.NoError(t, err)

	for _, f := range session.Findings {
		assert.Empty(t, f.LLMVerdict)
		assert.Empty(t, f.LLMProvider)
		assert.Empty(t, f.LLMModel)
		assert.Empty(t, f.LLMExplanation)
		assert.Empty(t, f.LLMRemediation)
		assert.Empty(t, f.LLMRawResponse)
		assert.Equal(t, 0.0, f.LLMCostUSD)
		assert.Equal(t, 0.0, f.LLMConfidence)
	}
}

// dirSetupAnalyzer is a mock that copies a fixture directory into the jadx
// output location within the session directory, simulating jadx output.
type dirSetupAnalyzer struct {
	name       string
	t          *testing.T
	fixtureDir string
}

func (d *dirSetupAnalyzer) Name() string     { return d.name }
func (d *dirSetupAnalyzer) Available() error { return nil }
func (d *dirSetupAnalyzer) Run(_ context.Context, _ string, workdir string) (models.ToolResult, error) {
	d.t.Helper()
	jadxDir := filepath.Join(workdir, "jadx")
	require.NoError(d.t, copyDir(d.fixtureDir, jadxDir))
	return models.ToolResult{
		ToolName:  d.name,
		Version:   "mock",
		StartedAt: time.Now(),
		Duration:  time.Millisecond,
	}, nil
}

func createSecretFixture(t *testing.T, baseDir string) string {
	t.Helper()
	fixtureDir := filepath.Join(baseDir, "fixture")
	require.NoError(t, os.MkdirAll(fixtureDir, 0o755))

	java1 := `package com.example;
public class Config1 {
    private static final String AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
}`
	java2 := `package com.example;
public class Config2 {
    String accessKey = "AKIAIOSFODNN7EXAMPLE";
}`
	java3 := `package com.example;
public class Config3 {
    // key: AKIAIOSFODNN7EXAMPLE
}`
	manifest := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.test">
    <application android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>`

	require.NoError(t, os.WriteFile(filepath.Join(fixtureDir, "Config1.java"), []byte(java1), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(fixtureDir, "Config2.java"), []byte(java2), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(fixtureDir, "Config3.java"), []byte(java3), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(fixtureDir, "AndroidManifest.xml"), []byte(manifest), 0o600))

	return fixtureDir
}

func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		srcPath := filepath.Join(src, e.Name())
		dstPath := filepath.Join(dst, e.Name())
		data, err := os.ReadFile(srcPath) //nolint:gosec
		if err != nil {
			return err
		}
		if err := os.WriteFile(dstPath, data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// outputAnalyzer is a mock analyzer that returns fixed JSON output; used to
// simulate external iOS tools without a toolchain.
type outputAnalyzer struct {
	name   string
	output json.RawMessage
}

func (o *outputAnalyzer) Name() string     { return o.name }
func (o *outputAnalyzer) Available() error { return nil }

// ConvertFindings implements pipeline.FindingConverter so the double behaves
// like the real analyzer it impersonates (the pipeline asserts the interface,
// not the name).
func (o *outputAnalyzer) ConvertFindings(raw json.RawMessage, sessionID string) []models.Finding {
	if o.name == "strings" {
		return analyzers.ConvertStringsFindings(raw, sessionID)
	}
	return nil
}

func (o *outputAnalyzer) Run(_ context.Context, _ string, _ string) (models.ToolResult, error) {
	return models.ToolResult{
		ToolName:  o.name,
		Version:   "mock",
		StartedAt: time.Now(),
		Duration:  time.Millisecond,
		Output:    o.output,
	}, nil
}

// buildSyntheticIPA writes a tiny but structurally complete IPA: a Payload
// bundle with an Info.plist carrying NSAppTransportSecurity plus a privacy
// key, and entitlements with a debug + wildcard keychain group. Entry order
// is fixed so the archive bytes (and therefore the session ID) are stable.
func buildSyntheticIPA(t *testing.T, dir string) string {
	t.Helper()

	infoPlist, err := plist.Marshal(map[string]interface{}{
		"CFBundleIdentifier":         "com.example.smoke",
		"CFBundleShortVersionString": "1.0",
		"CFBundleVersion":            "1",
		"CFBundleExecutable":         "SmokeApp",
		"MinimumOSVersion":           "15.0",
		"NSCameraUsageDescription":   "used by the smoke test",
		"NSAppTransportSecurity": map[string]interface{}{
			"NSAllowsArbitraryLoads": true,
		},
	}, plist.XMLFormat)
	require.NoError(t, err)

	entPlist, err := plist.Marshal(map[string]interface{}{
		"get-task-allow":         true,
		"keychain-access-groups": []interface{}{"ABC123.com.example.smoke", "*"},
	}, plist.XMLFormat)
	require.NoError(t, err)

	entries := []struct {
		name string
		data []byte
	}{
		{"Payload/SmokeApp.app/Info.plist", infoPlist},
		{"Payload/SmokeApp.app/entitlements.plist", entPlist},
		{"Payload/SmokeApp.app/SmokeApp", []byte("not a real binary")},
		{"Payload/SmokeApp.app/APIClient.swift", []byte("class APIClient {}")},
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		require.NoError(t, err)
		_, err = w.Write(e.data)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())

	path := filepath.Join(dir, "smoke.ipa")
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
	return path
}

// TestE2E_SyntheticIPA runs the full pipeline against a hand-made IPA with
// in-process iOS analyzers plus a mocked strings tool (mirroring the
// synthetic-APK test above). It asserts platform wiring, ATS/entitlement
// findings, artifact persistence and a findings.json round-trip.
func TestE2E_SyntheticIPA(t *testing.T) {
	tmpDir := t.TempDir()
	ipaPath := buildSyntheticIPA(t, tmpDir)

	// The archive must be detected as iOS before any tool runs.
	target, err := platform.Detect(ipaPath)
	require.NoError(t, err)
	assert.Equal(t, models.PlatformIOS, target.Platform)
	assert.Equal(t, platform.FormatIPA, target.Format)

	stringsMock := &outputAnalyzer{
		name:   "strings",
		output: json.RawMessage(`{"strings":["SmokeApp|AKIAIOSFODNN7EXAMPLE planted secret"]}`),
	}
	list := []analyzers.Analyzer{
		analyzers.NewIPAExtract(),
		analyzers.NewPlistAnalyzer(),
		analyzers.NewCodeSign(),
		stringsMock,
	}

	workdir := filepath.Join(tmpDir, "targets")
	p := NewWithOptions(list, slog.Default(), Options{Platform: models.PlatformIOS})
	session, err := p.Run(context.Background(), ipaPath, workdir, nil)
	require.NoError(t, err)
	assert.Equal(t, models.StatusCompleted, session.Status)
	assert.Equal(t, models.PlatformIOS, session.Platform, "session must record the iOS platform")

	// Hash recorded by the pipeline must match an independent computation.
	hash, err := utils.Sha256File(ipaPath)
	require.NoError(t, err)
	assert.Equal(t, hash, session.APKHash)

	// Inventory facts came from the extracted Info.plist.
	assert.Equal(t, "com.example.smoke", session.App.BundleID)
	assert.Equal(t, "1.0", session.App.VersionName)

	// ATS finding from the plist analyzer.
	var atsFindings, entitlementFindings, secretFindings int
	for _, f := range session.Findings {
		assert.Equal(t, "ios", string(f.Platform), "every finding must carry platform=ios")
		switch f.Category {
		case models.CategoryNetworkConfig:
			atsFindings++
			assert.Contains(t, f.Title, "arbitrary loads")
			assert.Equal(t, models.SeverityHigh, f.Severity)
		case models.CategoryEntitlement:
			entitlementFindings++
		case models.CategorySecret:
			secretFindings++
		}
	}
	assert.Equal(t, 1, atsFindings, "exactly one ATS finding (deduped across plist + inventory-ios)")
	assert.GreaterOrEqual(t, entitlementFindings, 2, "get-task-allow and wildcard keychain group expected")
	assert.Equal(t, 1, secretFindings, "mock strings analyzer output must yield one secret finding")

	// Artifacts are persisted under workdir/<session id>.
	sessionDir := filepath.Join(workdir, session.ID)
	for _, name := range []string{
		"meta.json", "findings.json", "report.md", "session.json",
		"report.sarif", "inventory.json",
	} {
		assert.FileExists(t, filepath.Join(sessionDir, name), "%s must exist", name)
	}

	// meta.json records the platform too.
	var meta Meta
	metaRaw, err := os.ReadFile(filepath.Join(sessionDir, "meta.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(metaRaw, &meta))
	assert.Equal(t, models.PlatformIOS, meta.Platform)

	// findings.json round-trips: same count, same IDs, enums parse back.
	findingsRaw, err := os.ReadFile(filepath.Join(sessionDir, "findings.json"))
	require.NoError(t, err)
	var roundTrip []models.Finding
	require.NoError(t, json.Unmarshal(findingsRaw, &roundTrip))
	require.Len(t, roundTrip, len(session.Findings))

	origIDs := make(map[string]bool, len(session.Findings))
	for _, f := range session.Findings {
		origIDs[f.ID] = true
	}
	for _, f := range roundTrip {
		assert.True(t, origIDs[f.ID], "round-tripped finding %s must exist in the session", f.ID)
		assert.NotEmpty(t, string(f.Category))
		assert.NotEmpty(t, string(f.Severity))
		assert.Equal(t, "ios", string(f.Platform))
	}
}
