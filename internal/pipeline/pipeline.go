package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dedek0/mobiscope/internal/analyzers"
	"github.com/dedek0/mobiscope/internal/models"
	"github.com/dedek0/mobiscope/internal/report"
	"github.com/dedek0/mobiscope/internal/utils"
	"golang.org/x/sync/errgroup"
)

// Meta represents the metadata persisted alongside analysis artifacts.
type Meta struct {
	APKPath   string          `json:"apk_path"`
	APKSHA256 string          `json:"apk_sha256"`
	Platform  models.Platform `json:"platform"`
	StartedAt time.Time       `json:"started_at"`
	Tools     []ToolMeta      `json:"tools"`
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

// Options controls pipeline execution.
type Options struct {
	// MaxConcurrency bounds how many external tools run at once (default 4).
	MaxConcurrency int
	// FailFast aborts on the first analyzer error instead of continuing.
	FailFast bool
	// DryRun lists the stages that would run without executing anything.
	DryRun bool
	// Platform is the detected target platform (android/ios).
	Platform models.Platform
}

// Pipeline orchestrates a sequence of Analyzer stages.
type Pipeline struct {
	analyzers []analyzers.Analyzer
	logger    *slog.Logger
	opts      Options
}

// New creates a Pipeline with the given analyzers and default options.
func New(analyzers []analyzers.Analyzer, logger *slog.Logger) *Pipeline {
	return NewWithOptions(analyzers, logger, Options{})
}

// NewWithOptions creates a Pipeline with explicit execution options.
func NewWithOptions(analyzers []analyzers.Analyzer, logger *slog.Logger, opts Options) *Pipeline {
	if opts.MaxConcurrency <= 0 {
		opts.MaxConcurrency = 4
	}
	return &Pipeline{
		analyzers: analyzers,
		logger:    logger,
		opts:      opts,
	}
}

// analyzerRun records one analyzer's outcome for thread-safe collection.
type analyzerRun struct {
	tool     models.ToolResult
	meta     ToolMeta
	findings []models.Finding
	err      error
}

// Run executes the configured analyzers against the APK.
//
// Independent analyzers run concurrently (decompilers first, then scanners
// that read decompiler output). Results are collected in the order the
// analyzers were registered so reports stay deterministic.
func (p *Pipeline) Run(ctx context.Context, apkPath string, workdir string, stages []string) (*models.AnalysisSession, error) {
	sha256, err := utils.Sha256File(apkPath)
	if err != nil {
		return nil, fmt.Errorf("computing APK hash: %w", err)
	}

	sessionDir := filepath.Join(workdir, sha256[:16])

	if p.opts.DryRun {
		return p.dryRun(apkPath, sha256, stages), nil
	}

	if err := utils.EnsureDir(sessionDir); err != nil {
		return nil, fmt.Errorf("creating session directory: %w", err)
	}

	plat := p.opts.Platform
	if plat == "" {
		plat = models.PlatformUnknown
	}

	session := &models.AnalysisSession{
		ID:        sha256[:16],
		APKPath:   apkPath,
		APKHash:   sha256,
		Platform:  plat,
		StartedAt: time.Now(),
		Status:    models.StatusRunning,
	}

	meta := Meta{
		APKPath:   apkPath,
		APKSHA256: sha256,
		Platform:  plat,
		StartedAt: session.StartedAt,
	}

	filtered := p.filterAnalyzers(stages)

	// Phase 1: extractors/decompilers (independent of each other).
	decompilers := selectByName(filtered, "apktool", "jadx", "ipa-extract")
	// Phase 2: scanners (read extractor output).
	scanners := selectByName(filtered, "gitleaks", "semgrep", "plist", "macho", "codesign", "strings")

	runs := make([]analyzerRun, len(filtered))
	idx := make(map[string]int, len(filtered))
	for i, a := range filtered {
		idx[a.Name()] = i
	}

	runGroup := func(group []analyzers.Analyzer) {
		var mu sync.Mutex
		g := errgroup.Group{}
		g.SetLimit(p.opts.MaxConcurrency)

		for _, a := range group {
			a := a
			g.Go(func() error {
				if err := ctx.Err(); err != nil {
					return err
				}

				p.logger.Info("running analyzer", "tool", a.Name())
				toolResult, err := a.Run(ctx, apkPath, sessionDir)

				findings := []models.Finding{}
				if err == nil {
					findings = p.convertFindings(a, toolResult, session.ID)
				} else {
					p.logger.Error("analyzer failed", "tool", a.Name(), "error", err)
				}

				mu.Lock()
				runs[idx[a.Name()]] = analyzerRun{
					tool: toolResult,
					meta: ToolMeta{
						Name:      toolResult.ToolName,
						Version:   toolResult.Version,
						StartedAt: toolResult.StartedAt,
						Duration:  toolResult.Duration,
						ExitCode:  toolResult.ExitCode,
						Error:     toolResult.Error,
					},
					findings: findings,
					err:      err,
				}
				mu.Unlock()

				if err != nil && p.opts.FailFast {
					return err
				}
				return nil
			})
		}
		_ = g.Wait()
	}

	runGroup(decompilers)
	if ctx.Err() == nil {
		runGroup(scanners)
	}

	// Collect in registration order for deterministic output.
	var firstErr error
	for _, r := range runs {
		if r.meta.Name == "" {
			continue
		}
		session.ToolResults = append(session.ToolResults, r.tool)
		meta.Tools = append(meta.Tools, r.meta)
		session.Findings = append(session.Findings, r.findings...)
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
	}

	if ctx.Err() != nil {
		session.Status = models.StatusFailed
	}

	// Phase 3: inventory analyzer (no external binary).
	if ctx.Err() == nil && p.shouldRunInventory(stages) {
		invStart := time.Now()
		invFindings := p.runInventory(sessionDir, session.ID)
		session.Findings = append(session.Findings, invFindings...)
		invDur := time.Since(invStart)
		p.logger.Info("inventory analysis complete", "findings", len(invFindings))

		invName := analyzers.NameInventory
		if p.opts.Platform == models.PlatformIOS {
			invName = "inventory-ios"
		}
		invResult := models.ToolResult{
			ToolName:  invName,
			Version:   "1.0.0",
			StartedAt: invStart,
			Duration:  invDur,
		}
		session.ToolResults = append(session.ToolResults, invResult)
		meta.Tools = append(meta.Tools, ToolMeta{
			Name: invName, Version: "1.0.0",
			StartedAt: invStart, Duration: invDur,
		})
	}

	// Phase 4: dedup.
	session.Findings = Dedup(session.Findings)
	p.logger.Info("dedup complete", "findings", len(session.Findings))

	// Phase 5: clustering (NO LLM calls in this phase).
	clustered, clusterCount := Cluster(session.Findings, p.logger)
	session.Findings = clustered
	p.logger.Info("clustering complete", "clusters", clusterCount)

	// Phase 6: sort by severity.
	report.SortFindingsBySeverity(session.Findings)

	// Phase 3b: inventory.json with structured app facts.
	session.App = p.collectAppInventory(sessionDir)
	if fp, scheme := p.collectSigning(apkPath); fp != "" || scheme != "" {
		session.SigningCertFP = fp
		session.SignatureScheme = scheme
	}
	if err := writeJSONFile(filepath.Join(sessionDir, "inventory.json"), session.App); err != nil {
		p.logger.Error("failed to persist inventory.json", "error", err)
	}

	// Phase 7: persist artifacts.
	now := time.Now()
	session.CompletedAt = &now
	if session.Status == models.StatusRunning {
		if firstErr != nil && p.opts.FailFast {
			session.Status = models.StatusFailed
		} else {
			session.Status = models.StatusCompleted
		}
	}

	metaPath := filepath.Join(sessionDir, "meta.json")
	if err := persistMeta(metaPath, &meta); err != nil {
		p.logger.Error("failed to persist meta.json", "error", err)
	}

	if err := PersistArtifacts(sessionDir, session); err != nil {
		p.logger.Error("failed to persist session artifacts", "error", err)
	}

	if firstErr != nil && p.opts.FailFast {
		return session, fmt.Errorf("pipeline aborted (fail-fast): %w", firstErr)
	}
	return session, nil
}

// dryRun reports what would run without executing anything.
func (p *Pipeline) dryRun(apkPath, sha256 string, stages []string) *models.AnalysisSession {
	plat := p.opts.Platform
	if plat == "" {
		plat = models.PlatformUnknown
	}
	session := &models.AnalysisSession{
		ID:        sha256[:16],
		APKPath:   apkPath,
		APKHash:   sha256,
		Platform:  plat,
		StartedAt: time.Now(),
		Status:    models.StatusPending,
	}

	filtered := p.filterAnalyzers(stages)
	for _, a := range filtered {
		avail := ""
		if err := a.Available(); err != nil {
			avail = " (unavailable: " + err.Error() + ")"
		}
		p.logger.Info("dry-run stage", "tool", a.Name(), "status", "would run"+avail)
		session.ToolResults = append(session.ToolResults, models.ToolResult{
			ToolName: a.Name(),
			Error:    avail,
		})
	}
	if p.shouldRunInventory(stages) {
		p.logger.Info("dry-run stage", "tool", analyzers.NameInventory, "status", "would run")
		session.ToolResults = append(session.ToolResults, models.ToolResult{ToolName: analyzers.NameInventory})
	}
	return session
}

// PersistArtifacts writes findings.json, report.md and session.json into
// sessionDir. Call again after mutating the session (e.g. post-LLM-triage)
// so enrichment is not lost.
func PersistArtifacts(sessionDir string, session *models.AnalysisSession) error {
	findingsPath := filepath.Join(sessionDir, "findings.json")
	if err := persistFindings(findingsPath, session); err != nil {
		return fmt.Errorf("writing findings.json: %w", err)
	}

	reportPath := filepath.Join(sessionDir, "report.md")
	if err := persistReport(reportPath, session); err != nil {
		return fmt.Errorf("writing report.md: %w", err)
	}

	sessionPath := filepath.Join(sessionDir, "session.json")
	if err := writeJSONFile(sessionPath, session); err != nil {
		return fmt.Errorf("writing session.json: %w", err)
	}

	return nil
}

// collectAppInventory gathers structured app facts for inventory.json.
func (p *Pipeline) collectAppInventory(sessionDir string) models.AppInventory {
	if p.opts.Platform == models.PlatformIOS {
		return analyzers.IOSAppInfo(sessionDir)
	}
	return analyzers.AndroidManifestInfo(sessionDir)
}

// collectSigning records the APK signing identity when apksigner ran.
func (p *Pipeline) collectSigning(apkPath string) (string, string) {
	if p.opts.Platform == models.PlatformIOS {
		return "", ""
	}
	return analyzers.SigningIdentity(apkPath)
}

// runInventory dispatches to the platform-appropriate inventory analyzer.
func (p *Pipeline) runInventory(sessionDir, sessionID string) []models.Finding {
	if p.opts.Platform == models.PlatformIOS {
		return analyzers.NewInventoryIOS().Analyze(sessionDir, sessionID)
	}
	return analyzers.NewInventory().Analyze(sessionDir, sessionID)
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
	case "ipa-extract":
		return analyzers.ConvertIPAExtractFindings(result.Output, sessionID)
	case "plist":
		return analyzers.ConvertPlistFindings(result.Output, sessionID)
	case "macho":
		return analyzers.ConvertMachOFindings(result.Output, sessionID)
	case "codesign":
		return analyzers.ConvertCodeSignFindings(result.Output, sessionID)
	case "strings":
		return analyzers.ConvertStringsFindings(result.Output, sessionID)
	}

	return nil
}

func (p *Pipeline) shouldRunInventory(stages []string) bool {
	if len(stages) == 0 {
		return true
	}
	for _, s := range stages {
		if s == analyzers.NameInventory {
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

// selectByName returns the subset of analyzers whose Name() is in names.
func selectByName(list []analyzers.Analyzer, names ...string) []analyzers.Analyzer {
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[n] = true
	}
	var out []analyzers.Analyzer
	for _, a := range list {
		if want[a.Name()] {
			out = append(out, a)
		}
	}
	return out
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
