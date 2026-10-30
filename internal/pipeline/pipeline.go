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
	"github.com/dedek0/mobiscope/internal/metrics"
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

// FindingConverter is an Analyzer that can convert its own ToolResult.Output
// into Findings. The pipeline asserts this interface at the call site instead
// of growing a switch over analyzer names.
type FindingConverter interface {
	ConvertFindings(raw json.RawMessage, sessionID string) []models.Finding
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
	// Strict makes a run with failed tools return an error even when
	// FailFast is off.
	Strict bool
	// OnStage is called when a stage starts and when it finishes. It is used
	// by the CLI to render live progress.
	OnStage func(stage StageEvent)
}

// StageEvent describes the lifecycle of a single pipeline stage.
type StageEvent struct {
	// Name is the analyzer name.
	Name string
	// Phase is "decompiler" or "scanner".
	Phase string
	// State is "start", "done" or "error".
	State string
	// Duration is set when State is "done" or "error".
	Duration time.Duration
	// Err is set when State is "error".
	Err error
	// Findings is the number of findings the stage produced.
	Findings int
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
	analyzer analyzers.Analyzer
	tool     models.ToolResult
	meta     ToolMeta
	findings []models.Finding
	err      error
}

// stageSlot pairs an analyzer with the index it owns in the results slice, so
// two analyzers that happen to share a name never overwrite each other.
type stageSlot struct {
	analyzer analyzers.Analyzer
	slot     int
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

	// Phase split is by role, not by a hardcoded name list: an analyzer that
	// does not declare a phase is treated as a scanner, so a new stage is
	// never silently dropped from the run.
	var decompilers, scanners []stageSlot
	for i, a := range filtered {
		slot := stageSlot{analyzer: a, slot: i}
		if analyzers.PhaseOf(a) == analyzers.PhaseScanner {
			scanners = append(scanners, slot)
			continue
		}
		decompilers = append(decompilers, slot)
	}

	runs := make([]analyzerRun, len(filtered))

	// runGroup executes one phase. It returns the first error observed in
	// registration order; with FailFast the shared context is cancelled so
	// the remaining tools stop instead of running to completion.
	runGroup := func(group []stageSlot) error {
		var mu sync.Mutex
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(p.opts.MaxConcurrency)

		for _, s := range group {
			s := s
			g.Go(func() error {
				if err := gctx.Err(); err != nil {
					return err
				}

				name := s.analyzer.Name()
				p.emitStage(StageEvent{Name: name, Phase: phaseLabel(s.analyzer), State: "start"})
				p.logger.Info("running analyzer", "tool", name)

				toolResult, err := runAnalyzer(gctx, s.analyzer, apkPath, sessionDir)

				// Convert findings even when the tool failed: a tool that
				// wrote a usable report before exiting non-zero still
				// produced evidence.
				findings := p.convertFindings(s.analyzer, toolResult, session.ID)
				if err != nil {
					p.logger.Error("analyzer failed", "tool", name, "error", err)
				}

				mu.Lock()
				runs[s.slot] = analyzerRun{
					analyzer: s.analyzer,
					tool:     toolResult,
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

				state := "done"
				if err != nil {
					state = "error"
				}
				p.emitStage(StageEvent{
					Name: name, Phase: phaseLabel(s.analyzer), State: state,
					Duration: toolResult.Duration, Err: err, Findings: len(findings),
				})

				if err != nil && p.opts.FailFast {
					return err
				}
				return nil
			})
		}
		return g.Wait()
	}

	decompilersErr := runGroup(decompilers)
	var scannersErr error
	if ctx.Err() == nil {
		scannersErr = runGroup(scanners)
	}

	// Collect in registration order for deterministic output.
	var firstErr error
	for _, r := range runs {
		if r.meta.Name == "" {
			continue
		}
		session.ToolResults = append(session.ToolResults, r.tool)
		meta.Tools = append(meta.Tools, r.meta)

		findings := r.findings
		if r.analyzer != nil && r.meta.Name == analyzers.NameRepack {
			// The repackaging summary gained the certificate fingerprint
			// after the stage ran, so its findings are recomputed.
			findings = p.convertFindings(r.analyzer, r.tool, session.ID)
		}
		session.Findings = append(session.Findings, findings...)

		if r.err != nil {
			session.FailedTools = append(session.FailedTools, r.meta.Name)
			if firstErr == nil {
				firstErr = r.err
			}
		}
	}
	if decompilersErr != nil && firstErr == nil {
		firstErr = decompilersErr
	}
	if scannersErr != nil && firstErr == nil {
		firstErr = scannersErr
	}

	// The repackaging stage needs the certificate the apksigner stage
	// found, so the comparison against the expected fingerprint happens
	// once both stages have run.
	if plat != models.PlatformIOS {
		p.attachSigningIdentity(&runs)
	}

	if ctx.Err() != nil {
		session.Status = models.StatusFailed
	}

	// Phase 3: inventory analyzer (no external binary).
	var scanAgg analyzers.ScanAggregate
	if ctx.Err() == nil && p.shouldRunInventory(stages) {
		invStart := time.Now()
		invFindings, agg := p.runInventory(plat, sessionDir, session.ID)
		scanAgg = agg
		session.Findings = append(session.Findings, invFindings...)
		invDur := time.Since(invStart)
		p.logger.Info("inventory analysis complete", "findings", len(invFindings))

		invName := analyzers.NameInventory
		if plat == models.PlatformIOS {
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
	session.App = p.collectAppInventory(plat, sessionDir, runs)
	session.App.URLCount = scanAgg.URLs.Count
	session.App.URLs = scanAgg.URLs.URLs
	session.App.IPCount = scanAgg.IPCount
	session.App.IPs = scanAgg.IPs
	session.App.EmailCount = scanAgg.EmailCount
	session.App.Emails = scanAgg.Emails
	session.App.PinningIndicators = scanAgg.Pinning
	session.App.PinningCount = scanAgg.PinningCount
	if session.App.BundleID != "" {
		session.PackageName = session.App.BundleID
		session.VersionName = session.App.VersionName
	}
	if fp, scheme := p.collectSigning(plat, apkPath, runs); fp != "" || scheme != "" {
		session.SigningCertFP = fp
		session.SignatureScheme = scheme
	}
	if err := writeJSONFile(filepath.Join(sessionDir, "inventory.json"), session.App); err != nil {
		p.logger.Error("failed to persist inventory.json", "error", err)
	}

	p.recordMetrics(session, meta)

	// Phase 7: persist artifacts.
	now := time.Now()
	session.CompletedAt = &now
	if session.Status == models.StatusRunning {
		switch {
		case firstErr != nil && p.opts.FailFast:
			session.Status = models.StatusFailed
		case len(session.FailedTools) > 0:
			// The run finished but at least one tool failed: the report is
			// usable but incomplete, and the status says so.
			session.Status = models.StatusPartial
		default:
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

	if ctxErr := ctx.Err(); ctxErr != nil {
		return session, fmt.Errorf("pipeline cancelled: %w", ctxErr)
	}
	if firstErr != nil && p.opts.FailFast {
		return session, fmt.Errorf("pipeline aborted (fail-fast): %w", firstErr)
	}
	if firstErr != nil && p.opts.Strict {
		return session, fmt.Errorf("pipeline completed with failed tools: %w", firstErr)
	}
	return session, nil
}

// runAnalyzer executes one analyzer, converting a panic into an error so a
// hostile artifact that trips a parser bug cannot take down the process.
func runAnalyzer(ctx context.Context, a analyzers.Analyzer, target, workdir string) (result models.ToolResult, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("analyzer %s panicked: %v", a.Name(), rec)
			result.ToolName = a.Name()
			result.Error = err.Error()
			result.ExitCode = -1
		}
	}()
	return a.Run(ctx, target, workdir)
}

// phaseLabel returns a human-readable phase name for an analyzer.
func phaseLabel(a analyzers.Analyzer) string {
	switch analyzers.PhaseOf(a) {
	case analyzers.PhaseDecompiler:
		return "decompiler"
	case analyzers.PhaseIndependent:
		return "independent"
	default:
		return "scanner"
	}
}

// emitStage notifies the progress listener, if one is configured.
func (p *Pipeline) emitStage(ev StageEvent) {
	if p.opts.OnStage != nil {
		p.opts.OnStage(ev)
	}
}

// attachSigningIdentity copies the certificate fingerprint found by the
// apksigner stage into the repackaging stage output, so the comparison
// against the expected fingerprint can happen.
func (p *Pipeline) attachSigningIdentity(runs *[]analyzerRun) {
	actual := ""
	for _, r := range *runs {
		if r.meta.Name != "apksigner" || len(r.tool.Output) == 0 {
			continue
		}
		var out struct {
			CertFP string `json:"signing_cert_fp"`
		}
		if err := json.Unmarshal(r.tool.Output, &out); err == nil {
			actual = out.CertFP
		}
	}
	if actual == "" {
		return
	}

	for i := range *runs {
		if (*runs)[i].meta.Name != "repack" || len((*runs)[i].tool.Output) == 0 {
			continue
		}
		var summary map[string]interface{}
		if err := json.Unmarshal((*runs)[i].tool.Output, &summary); err != nil {
			continue
		}
		summary["actual_cert"] = actual
		summary["cert_matches"] = false
		if expected, ok := summary["expected_cert"].(string); ok && expected != "" {
			summary["cert_matches"] = certFingerprintsEqual(expected, actual)
		}
		if raw, err := json.Marshal(summary); err == nil {
			(*runs)[i].tool.Output = raw
		}
	}
}

// certFingerprintsEqual compares two certificate fingerprints, ignoring case
// and the separators people paste them with.
func certFingerprintsEqual(a, b string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.ReplaceAll(s, ":", "")
		s = strings.ReplaceAll(s, " ", "")
		return s
	}
	return norm(a) != "" && norm(a) == norm(b)
}

// recordMetrics feeds the process-wide metrics registry so /metrics can
// expose analyzer durations, failure counts and findings by label.
func (p *Pipeline) recordMetrics(session *models.AnalysisSession, meta Meta) {
	metrics.RecordAnalysis()
	for _, t := range meta.Tools {
		metrics.RecordAnalyzer(t.Name, t.Duration, t.Error != "")
	}
	for _, f := range session.Findings {
		metrics.RecordFindings(string(f.Severity), string(f.Category))
	}
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

	sarifPath := filepath.Join(sessionDir, "report.sarif")
	if err := persistSarif(sarifPath, session); err != nil {
		return fmt.Errorf("writing report.sarif: %w", err)
	}

	return nil
}

func persistSarif(path string, session *models.AnalysisSession) error {
	sr := &report.SARIFReporter{}
	var buf strings.Builder
	if err := sr.Render(session, &buf); err != nil {
		return err
	}
	return utils.WriteFile(path, []byte(buf.String()))
}

// collectAppInventory gathers structured app facts for inventory.json.
func (p *Pipeline) collectAppInventory(plat models.Platform, sessionDir string, runs []analyzerRun) models.AppInventory {
	if plat == models.PlatformIOS {
		return analyzers.IOSAppInfo(sessionDir)
	}
	inv := analyzers.AndroidManifestInfo(sessionDir)
	var toolResults []models.ToolResult
	for _, r := range runs {
		toolResults = append(toolResults, r.tool)
	}
	inv.NativeLibs = analyzers.NativeLibsFromRuns(toolResults)
	inv.SDKs = analyzers.SDKsFromRuns(toolResults)
	inv.Obfuscation = analyzers.ObfuscationFromRuns(toolResults)
	return inv
}

// collectSigning records the APK signing identity. It reuses the apksigner
// stage output when the stage ran, and only falls back to the standalone
// probe when it did not (for example under an explicit --stages filter).
func (p *Pipeline) collectSigning(plat models.Platform, apkPath string, runs []analyzerRun) (string, string) {
	if plat == models.PlatformIOS {
		return "", ""
	}
	for _, r := range runs {
		if r.meta.Name != "apksigner" || len(r.tool.Output) == 0 {
			continue
		}
		var out struct {
			Scheme string `json:"signature_scheme"`
			CertFP string `json:"signing_cert_fp"`
		}
		if err := json.Unmarshal(r.tool.Output, &out); err == nil {
			return out.CertFP, out.Scheme
		}
	}
	return analyzers.SigningIdentity(apkPath)
}

// runInventory dispatches to the platform-appropriate inventory analyzer and
// returns its findings plus the Android scan aggregate (zero on iOS).
func (p *Pipeline) runInventory(plat models.Platform, sessionDir, sessionID string) ([]models.Finding, analyzers.ScanAggregate) {
	if plat == models.PlatformIOS {
		return analyzers.NewInventoryIOS().Analyze(sessionDir, sessionID), analyzers.ScanAggregate{}
	}
	inv := analyzers.NewInventory()
	findings := inv.Analyze(sessionDir, sessionID)
	return findings, inv.Aggregate()
}

func (p *Pipeline) convertFindings(a analyzers.Analyzer, result models.ToolResult, sessionID string) []models.Finding {
	if result.Output == nil {
		return nil
	}
	if c, ok := a.(FindingConverter); ok {
		return c.ConvertFindings(result.Output, sessionID)
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
		stageSet[normalizeStageName(s)] = true
	}

	var filtered []analyzers.Analyzer
	for _, a := range p.analyzers {
		if stageSet[normalizeStageName(a.Name())] {
			filtered = append(filtered, a)
		}
	}
	return filtered
}

// normalizeStageName makes stage selection tolerant to the hyphen/underscore
// difference between the CLI spelling (`anti-analysis`) and the analyzer
// identifier (`anti_analysis`).
func normalizeStageName(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "-", "_")
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
