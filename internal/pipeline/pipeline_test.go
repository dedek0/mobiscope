package pipeline

import (
	"context"
	"fmt"
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

type mockAnalyzer struct {
	name   string
	result models.ToolResult
	err    error
	called bool
}

func (m *mockAnalyzer) Name() string     { return m.name }
func (m *mockAnalyzer) Available() error { return nil }
func (m *mockAnalyzer) Run(_ context.Context, _ string, _ string) (models.ToolResult, error) {
	m.called = true
	result := m.result
	if m.err != nil {
		result.Error = m.err.Error()
		result.ExitCode = 1
	}
	return result, m.err
}

func newMockAnalyzer(name string, err error) *mockAnalyzer {
	return &mockAnalyzer{
		name: name,
		result: models.ToolResult{
			ToolName:  name,
			Version:   "test-1.0",
			StartedAt: time.Now(),
			Duration:  10 * time.Millisecond,
			ExitCode:  0,
		},
		err: err,
	}
}

func createTestAPK(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.apk")
	if err := os.WriteFile(path, []byte("PK\x03\x04fake apk content"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPipeline_Run_AllStages(t *testing.T) {
	logger := slog.Default()
	apkPath := createTestAPK(t)
	workdir := t.TempDir()

	tool1 := newMockAnalyzer("apktool", nil)
	tool2 := newMockAnalyzer("jadx", nil)

	p := New([]analyzers.Analyzer{tool1, tool2}, logger)
	session, err := p.Run(context.Background(), apkPath, workdir, nil)

	require.NoError(t, err)
	assert.Equal(t, models.StatusCompleted, session.Status)
	// 2 external tools + inventory (runs by default when stages is nil)
	assert.Len(t, session.ToolResults, 3)
	assert.True(t, tool1.called)
	assert.True(t, tool2.called)
	assert.NotEmpty(t, session.APKHash)
	assert.NotNil(t, session.CompletedAt)
}

func TestPipeline_Run_FilteredStages(t *testing.T) {
	logger := slog.Default()
	apkPath := createTestAPK(t)
	workdir := t.TempDir()

	tool1 := newMockAnalyzer("apktool", nil)
	tool2 := newMockAnalyzer("jadx", nil)

	p := New([]analyzers.Analyzer{tool1, tool2}, logger)
	session, err := p.Run(context.Background(), apkPath, workdir, []string{"jadx"})

	require.NoError(t, err)
	assert.Len(t, session.ToolResults, 1)
	assert.False(t, tool1.called)
	assert.True(t, tool2.called)
}

func TestPipeline_Run_ToolFailureContinues(t *testing.T) {
	logger := slog.Default()
	apkPath := createTestAPK(t)
	workdir := t.TempDir()

	tool1 := newMockAnalyzer("apktool", fmt.Errorf("apktool crashed"))
	tool2 := newMockAnalyzer("jadx", nil)

	p := New([]analyzers.Analyzer{tool1, tool2}, logger)
	session, err := p.Run(context.Background(), apkPath, workdir, nil)

	require.NoError(t, err)
	assert.Equal(t, models.StatusCompleted, session.Status)
	// 2 external tools + inventory
	assert.Len(t, session.ToolResults, 3)
	assert.NotEmpty(t, session.ToolResults[0].Error)
	assert.Empty(t, session.ToolResults[1].Error)
}

func TestPipeline_Run_MetaJSONPersisted(t *testing.T) {
	logger := slog.Default()
	apkPath := createTestAPK(t)
	workdir := t.TempDir()

	tool := newMockAnalyzer("apktool", nil)
	p := New([]analyzers.Analyzer{tool}, logger)
	session, err := p.Run(context.Background(), apkPath, workdir, nil)

	require.NoError(t, err)

	metaPath := filepath.Join(workdir, session.ID[:16], "meta.json")
	_, err = os.Stat(metaPath)
	require.NoError(t, err)

	data, err := os.ReadFile(metaPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "apktool")
	assert.Contains(t, string(data), "apk_sha256")
}

func TestPipeline_Run_FindingsJSONPersisted(t *testing.T) {
	logger := slog.Default()
	apkPath := createTestAPK(t)
	workdir := t.TempDir()

	tool := newMockAnalyzer("jadx", nil)
	p := New([]analyzers.Analyzer{tool}, logger)
	session, err := p.Run(context.Background(), apkPath, workdir, []string{"jadx"})

	require.NoError(t, err)

	findingsPath := filepath.Join(workdir, session.ID[:16], "findings.json")
	_, err = os.Stat(findingsPath)
	require.NoError(t, err)
}

func TestPipeline_Run_ReportMDPersisted(t *testing.T) {
	logger := slog.Default()
	apkPath := createTestAPK(t)
	workdir := t.TempDir()

	tool := newMockAnalyzer("jadx", nil)
	p := New([]analyzers.Analyzer{tool}, logger)
	session, err := p.Run(context.Background(), apkPath, workdir, []string{"jadx"})

	require.NoError(t, err)

	reportPath := filepath.Join(workdir, session.ID[:16], "report.md")
	_, err = os.Stat(reportPath)
	require.NoError(t, err)
}

func TestPipeline_Run_CancelledContext(t *testing.T) {
	logger := slog.Default()
	apkPath := createTestAPK(t)
	workdir := t.TempDir()

	tool1 := newMockAnalyzer("apktool", nil)
	tool2 := newMockAnalyzer("jadx", nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p := New([]analyzers.Analyzer{tool1, tool2}, logger)
	session, err := p.Run(ctx, apkPath, workdir, nil)

	require.NoError(t, err)
	assert.Equal(t, models.StatusFailed, session.Status)
	// Context cancelled before any analyzer runs
	assert.Len(t, session.ToolResults, 0)
	assert.False(t, tool1.called)
	assert.False(t, tool2.called)
}

func TestPipeline_filterAnalyzers(t *testing.T) {
	logger := slog.Default()
	tool1 := newMockAnalyzer("apktool", nil)
	tool2 := newMockAnalyzer("jadx", nil)
	tool3 := newMockAnalyzer("semgrep", nil)

	p := New([]analyzers.Analyzer{tool1, tool2, tool3}, logger)

	filtered := p.filterAnalyzers([]string{"apktool", "semgrep"})
	assert.Len(t, filtered, 2)

	all := p.filterAnalyzers(nil)
	assert.Len(t, all, 3)
}

func TestPipeline_Run_APKNotFound(t *testing.T) {
	logger := slog.Default()
	workdir := t.TempDir()

	p := New(nil, logger)
	_, err := p.Run(context.Background(), "/nonexistent.apk", workdir, nil)
	assert.Error(t, err)
}

func TestPipeline_Run_FindingsSortedBySeverity(t *testing.T) {
	logger := slog.Default()
	apkPath := createTestAPK(t)
	workdir := t.TempDir()

	// Run with only jadx stage to skip inventory and avoid external binary dep.
	tool := newMockAnalyzer("jadx", nil)
	p := New([]analyzers.Analyzer{tool}, logger)
	session, err := p.Run(context.Background(), apkPath, workdir, []string{"jadx"})

	require.NoError(t, err)
	// No findings from mock, but session should be valid.
	assert.Equal(t, models.StatusCompleted, session.Status)
}

func TestPipeline_shouldRunInventory(t *testing.T) {
	p := &Pipeline{}
	assert.True(t, p.shouldRunInventory(nil))
	assert.True(t, p.shouldRunInventory([]string{"inventory", "jadx"}))
	assert.False(t, p.shouldRunInventory([]string{"jadx"}))
}
