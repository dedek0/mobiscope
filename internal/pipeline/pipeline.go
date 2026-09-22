package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/analyzers"
	"github.com/dedek0/mobiscope/internal/models"
	"github.com/dedek0/mobiscope/internal/report"
	"github.com/dedek0/mobiscope/internal/utils"
)

// Meta represents the metadata persisted alongside analysis artifacts.
type Meta struct {
	APKPath   string     `json:"apk_path"`
	APKSHA256 string     `json:"apk_sha256"`
	StartedAt time.Time  `json:"started_at"`
	Tools     []ToolMeta `json:"tools"`
}

// ToolMeta holds per-tool execution metadata.
type ToolMeta struct {
	Name      string        `json:"name"`
	Version   string        `json:"version"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration"`
	ExitCode  int           `json:"exit_code"`
	Error     string        `json:"error,omitempty"`
}

// FindingCollector is an Analyzer that also produces Findings directly.
type FindingCollector interface {
	analyzers.Analyzer
	Analyze(workdir string, sessionID string) []models.Finding
}

// Pipeline orchestrates a sequence of Analyzer stages.
type Pipeline struct {
	analyzers []analyzers.Analyzer
	logger    *slog.Logger
}

// New creates a Pipeline with the given analyzers.
func New(analyzers []analyzers.Analyzer, logger *slog.Logger) *Pipeline {
	return &Pipeline{
		analyzers: analyzers,
		logger:    logger,
	}
}

// Run executes the configured analyzers against the APK.
func (p *Pipeline) Run(ctx context.Context, apkPath string, workdir string, stages []string) (*models.AnalysisSession, error) {
	sha256, err := utils.Sha256File(apkPath)
	if err != nil {
		return nil, fmt.Errorf("computing APK hash: %w", err)
	}

	sessionDir := filepath.Join(workdir, sha256[:16])
	if err := utils.EnsureDir(sessionDir); err != nil {
		return nil, fmt.Errorf("creating session directory: %w", err)
	}

	session := &models.AnalysisSession{
		ID:        sha256[:16],
		APKPath:   apkPath,
		APKHash:   sha256,
		StartedAt: time.Now(),
		Status:    models.StatusRunning,
	}

	meta := Meta{
		APKPath:   apkPath,
		APKSHA256: sha256,
		StartedAt: session.StartedAt,
	}

	filtered := p.filterAnalyzers(stages)

	// Phase 1: run external tool analyzers (apktool, jadx, gitleaks, semgrep).
	for _, a := range filtered {
		if err := ctx.Err(); err != nil {
			p.logger.Warn("pipeline cancelled", "tool", a.Name(), "error", err)
			session.Status = models.StatusFailed
			break
		}

		p.logger.Info("running analyzer", "tool", a.Name())

		toolResult, err := a.Run(ctx, apkPath, sessionDir)
		session.ToolResults = append(session.ToolResults, toolResult)

		meta.Tools = append(meta.Tools, ToolMeta{
			Name:      toolResult.ToolName,
			Version:   toolResult.Version,
			StartedAt: toolResult.StartedAt,
			Duration:  toolResult.Duration,
			ExitCode:  toolResult.ExitCode,
			Error:     toolResult.Error,
		})

		if err != nil {
			p.logger.Error("analyzer failed", "tool", a.Name(), "error", err)
			continue
		}

		// Convert tool output to findings if applicable.
		findings := p.convertFindings(a, toolResult, session.ID)
		session.Findings = append(session.Findings, findings...)

		p.logger.Info("analyzer completed",
			"tool", a.Name(),
			"duration", toolResult.Duration.String(),
		)
	}

	// Phase 2: run inventory analyzer (no external binary).
	if ctx.Err() == nil && p.shouldRunInventory(stages) {
		inv := analyzers.NewInventory()
		invFindings := inv.Analyze(sessionDir, session.ID)
		session.Findings = append(session.Findings, invFindings...)
		p.logger.Info("inventory analysis complete", "findings", len(invFindings))

		invResult := models.ToolResult{
			ToolName:  "inventory",
			Version:   "1.0.0",
			StartedAt: time.Now(),
			Duration:  time.Since(session.StartedAt),
		}
		session.ToolResults = append(session.ToolResults, invResult)
		meta.Tools = append(meta.Tools, ToolMeta{Name: "inventory", Version: "1.0.0"})
	}

	// Phase 3: dedup.
	session.Findings = Dedup(session.Findings)
	p.logger.Info("dedup complete", "findings", len(session.Findings))

	// Phase 4: clustering (NO LLM calls in this phase).
	clustered, clusterCount := Cluster(session.Findings, p.logger)
	session.Findings = clustered
	p.logger.Info("clustering complete", "clusters", clusterCount)

	// Phase 5: sort by severity.
	report.SortFindingsBySeverity(session.Findings)

	// Phase 6: persist artifacts.
	now := time.Now()
	session.CompletedAt = &now
	if session.Status == models.StatusRunning {
		session.Status = models.StatusCompleted
	}

	metaPath := filepath.Join(sessionDir, "meta.json")
	if err := persistMeta(metaPath, &meta); err != nil {
		p.logger.Error("failed to persist meta.json", "error", err)
	}

	findingsPath := filepath.Join(sessionDir, "findings.json")
	if err := persistFindings(findingsPath, session); err != nil {
		p.logger.Error("failed to persist findings.json", "error", err)
	}

	reportPath := filepath.Join(sessionDir, "report.md")
	if err := persistReport(reportPath, session); err != nil {
		p.logger.Error("failed to persist report.md", "error", err)
	}

	return session, nil
}

func (p *Pipeline) convertFindings(a analyzers.Analyzer, result models.ToolResult, sessionID string) []models.Finding {
	if result.Output == nil {
		return nil
	}

	switch a.Name() {
	case "gitleaks":
		return analyzers.ConvertGitleaksFindings(result.Output, sessionID)
	case "semgrep":
		return analyzers.ConvertSemgrepFindings(result.Output, sessionID)
	}

	return nil
}

func (p *Pipeline) shouldRunInventory(stages []string) bool {
	if len(stages) == 0 {
		return true
	}
	for _, s := range stages {
		if s == "inventory" {
			return true
		}
	}
	return false
}

func (p *Pipeline) filterAnalyzers(stages []string) []analyzers.Analyzer {
	if len(stages) == 0 {
		return p.analyzers
	}

	stageSet := make(map[string]bool, len(stages))
	for _, s := range stages {
		stageSet[s] = true
	}

	var filtered []analyzers.Analyzer
	for _, a := range p.analyzers {
		if stageSet[a.Name()] {
			filtered = append(filtered, a)
		}
	}
	return filtered
}

func persistMeta(path string, meta *Meta) error {
	return writeJSONFile(path, meta)
}

func persistFindings(path string, session *models.AnalysisSession) error {
	jr := &report.FindingsJSON{}
	var buf strings.Builder
	if err := jr.Render(session, &buf); err != nil {
		return err
	}
	return utils.WriteFile(path, []byte(buf.String()))
}

func persistReport(path string, session *models.AnalysisSession) error {
	mr := &report.MarkdownReporter{}
	var buf strings.Builder
	if err := mr.Render(session, &buf); err != nil {
		return err
	}
	return utils.WriteFile(path, []byte(buf.String()))
}

func writeJSONFile(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return utils.WriteFile(path, data)
}
