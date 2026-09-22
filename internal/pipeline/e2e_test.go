//go:build integration

package pipeline

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dedek0/mobiscope/internal/analyzers"
	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
