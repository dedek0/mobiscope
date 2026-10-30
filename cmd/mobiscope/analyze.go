package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dedek0/mobiscope/internal/analyzers"
	"github.com/dedek0/mobiscope/internal/config"
	"github.com/dedek0/mobiscope/internal/llm"
	"github.com/dedek0/mobiscope/internal/models"
	"github.com/dedek0/mobiscope/internal/pipeline"
	"github.com/dedek0/mobiscope/internal/platform"
	"github.com/dedek0/mobiscope/internal/rules"
	"github.com/dedek0/mobiscope/internal/utils"
	"github.com/spf13/cobra"
)

func newAnalyzeCmd() *cobra.Command {
	var (
		workdir        string
		stages         string
		verbose        bool
		quiet          bool
		noRes          bool
		triage         bool
		triageProvider string
		failFast       bool
		dryRun         bool
		maxConc        int
		expectSHA      string
		strict         bool
		quick          bool
		noSecrets      bool
		rulesPath      string
		decompiler     string
		expectCert     string
		osvLookup      bool
		writeSBOM      bool
		failOn         string
		baseline       string
		mapping        string
		allowlist      string
		reuse          bool
	)

	cmd := &cobra.Command{
		Use:   "analyze <app> [more apps...]",
		Short: "Run static analysis on an Android APK or iOS IPA",
		Long:  "Orchestrates decompilation and analysis tools against one or more target APK/IPA files. Each target gets its own session directory under --workdir.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			// The embedded semgrep packs are extracted to a temp directory
			// on first use; remove it when the command finishes.
			defer rules.Cleanup()

			level := slog.LevelInfo
			if verbose {
				level = slog.LevelDebug
			}
			if quiet {
				level = slog.LevelError
			}
			logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

			ctx, stop := signal.NotifyContext(c.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			var stageFilter []string
			if stages != "" {
				for _, s := range strings.Split(stages, ",") {
					s = strings.TrimSpace(s)
					if s != "" {
						stageFilter = append(stageFilter, s)
					}
				}
			}

			opts := pipeline.Options{
				MaxConcurrency: maxConc,
				FailFast:       failFast,
				DryRun:         dryRun,
				Strict:         strict,
			}
			if maxConc <= 0 {
				cfg, err := loadConfigWithFlags(c)
				if err != nil {
					return fmt.Errorf("loading config: %w", err)
				}
				opts.MaxConcurrency = cfg.Pipeline.MaxConcurrency
				if !failFast {
					opts.FailFast = cfg.Pipeline.FailFast
				}
			}

			results := make([]targetResult, 0, len(args))
			for _, apkPath := range args {
				if ctx.Err() != nil {
					break
				}
				res := targetResult{path: apkPath}
				res.session, res.err = analyzeOne(c, apkPath, workdir, stageFilter, &opts, targetFlags{
					noRes:          noRes,
					triage:         triage,
					triageProvider: triageProvider,
					dryRun:         dryRun,
					expectSHA:      expectSHA,
					quick:          quick,
					noSecrets:      noSecrets,
					rulesPath:      rulesPath,
					decompiler:     decompiler,
					expectCert:     expectCert,
					osvLookup:      osvLookup,
					writeSBOM:      writeSBOM,
					failOn:         failOn,
					baseline:       baseline,
					mapping:        mapping,
					allowlist:      allowlist,
					reuse:          reuse,
					logger:         logger,
					ctx:            ctx,
				})
				results = append(results, res)
				if res.err != nil && failFast {
					break
				}
			}

			if len(results) > 1 {
				printTargetSummary(results)
			}

			var failed int
			var firstErr error
			for _, r := range results {
				if r.err != nil {
					failed++
					if firstErr == nil {
						if len(args) > 1 {
							firstErr = fmt.Errorf("%s: %w", r.path, r.err)
						} else {
							firstErr = r.err
						}
					}
				}
			}
			switch {
			case failed == 0:
				return nil
			case failed == 1 && len(args) == 1:
				return firstErr
			default:
				return fmt.Errorf("%d of %d target(s) failed: %w", failed, len(args), firstErr)
			}
		},
	}

	cmd.Flags().StringVar(&workdir, "workdir", "targets", "Output base directory")
	cmd.Flags().StringVar(&stages, "stages", "", "Comma-separated stages (Android: apktool,jadx,elf,anti-analysis,repack,sdk,gitleaks,semgrep,inventory; iOS: ipa-extract,plist,macho,codesign,classdump,strings)")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Enable debug logging")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "Only log errors")
	cmd.Flags().BoolVar(&noRes, "no-res", false, "Skip resource decoding")
	cmd.Flags().BoolVar(&triage, "triage", false, "Run LLM triage on findings")
	cmd.Flags().StringVar(&triageProvider, "triage-provider", "", "Override provider for triage")
	cmd.Flags().BoolVar(&failFast, "fail-fast", false, "Abort on the first analyzer error")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "List the stages that would run without executing")
	cmd.Flags().IntVar(&maxConc, "max-concurrency", 0, "Max external tools running at once (default from config)")
	cmd.Flags().StringVar(&expectSHA, "expect-sha256", "", "Expected SHA-256 of each target (hex); analysis aborts before any tool runs on mismatch")
	cmd.Flags().BoolVar(&strict, "strict", false, "Exit non-zero when any analyzer fails (the report is marked partial)")
	cmd.Flags().BoolVar(&quick, "quick", false, "Skip the optional scanners (gitleaks, semgrep) for a faster pass")
	cmd.Flags().BoolVar(&noSecrets, "no-secrets", false, "Skip the gitleaks secret scanner")
	cmd.Flags().StringVar(&rulesPath, "rules", "", "Path to a custom semgrep rule pack (default: the embedded MASTG pack)")
	cmd.Flags().StringVar(&decompiler, "decompiler", "jadx", "Decompiler(s): apktool, jadx, dexdc, both, or a comma-separated list")
	cmd.Flags().StringVar(&expectCert, "expect-cert", "", "Expected signing certificate fingerprint (hex); a mismatch is reported as a repackaging signal")
	cmd.Flags().BoolVar(&osvLookup, "osv", false, "Look the detected libraries up in the OSV vulnerability database (reaches the network)")
	cmd.Flags().BoolVar(&writeSBOM, "sbom", false, "Write a CycloneDX software bill of materials next to the report")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "Exit with code 2 when a finding at or above this severity exists (critical|high|medium|low|info; off disables)")
	cmd.Flags().StringVar(&baseline, "baseline", "", "Suppress findings that match a previous findings.json or session.json")
	cmd.Flags().StringVar(&mapping, "mapping", "", "R8/ProGuard mapping.txt used to deobfuscate finding locations")
	cmd.Flags().StringVar(&allowlist, "allowlist", "", "YAML allowlist of documented findings to suppress")
	cmd.Flags().BoolVar(&reuse, "reuse", false, "Reuse an existing decompiled tree in the session directory")

	return cmd
}

// targetResult is one entry of the batch summary (see analyze).
type targetResult struct {
	path    string
	session *models.AnalysisSession
	err     error
}

// targetFlags carries the per-command options into analyzeOne.
type targetFlags struct {
	noRes          bool
	triage         bool
	dryRun         bool
	triageProvider string
	expectSHA      string
	quick          bool
	noSecrets      bool
	rulesPath      string
	decompiler     string
	expectCert     string
	osvLookup      bool
	writeSBOM      bool
	failOn         string
	baseline       string
	mapping        string
	allowlist      string
	reuse          bool
	logger         *slog.Logger
	ctx            context.Context
}

// analyzeOne runs detection, the hash gate, the pipeline and optional triage
// for a single target and returns its session.
func analyzeOne(c *cobra.Command, apkPath, workdir string, stageFilter []string, opts *pipeline.Options, tf targetFlags) (*models.AnalysisSession, error) {
	if err := platform.MustExist(apkPath); err != nil {
		return nil, err
	}
	target, err := platform.Detect(apkPath)
	if err != nil {
		return nil, fmt.Errorf("detecting platform: %w", err)
	}
	tf.logger.Info("target detected",
		"path", target.Path,
		"platform", string(target.Platform),
		"format", target.Format,
	)

	if err := validateStages(stageFilter, target.Platform); err != nil {
		return nil, err
	}
	if err := validateDecompiler(tf.decompiler); err != nil {
		return nil, err
	}
	// An explicit --decompiler is a request to run that backend even when
	// --stages names only the scanners. Only extend a non-empty stage list:
	// appending to the empty list would suppress the default in-process
	// stages.
	if c.Flags().Changed("decompiler") && len(stageFilter) > 0 {
		stageFilter = includeDecompilers(stageFilter, tf.decompiler)
	}

	failThreshold, gateEnabled, err := parseFailOn(tf.failOn)
	if err != nil {
		return nil, err
	}

	// Chain-of-custody gate: verify the expected hash before any tool runs.
	if tf.expectSHA != "" {
		got, err := utils.Sha256File(apkPath)
		if err != nil {
			return nil, fmt.Errorf("hashing target: %w", err)
		}
		if !strings.EqualFold(got, tf.expectSHA) {
			return nil, fmt.Errorf("SHA-256 mismatch: expected %s, got %s", tf.expectSHA, got)
		}
		tf.logger.Info("sha256 verified", "sha256", got)
	}

	targetOpts := *opts
	targetOpts.Platform = target.Platform

	reuseDir := ""
	if tf.reuse {
		sum, err := utils.Sha256File(apkPath)
		if err != nil {
			return nil, fmt.Errorf("hashing target for reuse: %w", err)
		}
		reuseDir = filepath.Join(workdir, sum[:16])
		tf.logger.Info("reuse enabled", "session", sum[:16])
	}

	analyzersList := buildAnalyzers(stageOptions{
		stages:        stageFilter,
		noRes:         tf.noRes,
		quick:         tf.quick,
		noSecrets:     tf.noSecrets,
		rules:         tf.rulesPath,
		decompiler:    tf.decompiler,
		decompilerSet: c.Flags().Changed("decompiler"),
		reuse:         tf.reuse,
		sessionDir:    reuseDir,
		expectCert:    tf.expectCert,
	}, target)
	p := pipeline.NewWithOptions(analyzersList, tf.logger, targetOpts)

	session, err := p.Run(tf.ctx, apkPath, workdir, stageFilter)
	if err != nil {
		return session, fmt.Errorf("pipeline failed: %w", err)
	}

	if tf.dryRun {
		fmt.Fprintf(os.Stderr, "Dry run: %d stage(s) would execute\n", len(session.ToolResults))
		for _, tr := range session.ToolResults {
			fmt.Fprintf(os.Stderr, "  - %s%s\n", tr.ToolName, tr.Error)
		}
		return session, nil
	}

	sessionDir := filepath.Join(workdir, session.ID)

	// Deobfuscate locations before the baseline/triage passes so all later
	// matching uses the original class names.
	if tf.mapping != "" {
		if err := applyMapping(session, tf.mapping, tf.logger); err != nil {
			return session, fmt.Errorf("applying mapping: %w", err)
		}
		if session.FindingsMapped > 0 {
			if err := pipeline.PersistArtifacts(sessionDir, session); err != nil {
				return session, fmt.Errorf("persisting mapped findings: %w", err)
			}
		}
	}

	// Documented exceptions are applied before the baseline so a finding can
	// be accepted for a reason rather than silently matched by fingerprint.
	if tf.allowlist != "" {
		if err := applyAllowlist(session, tf.allowlist, tf.logger); err != nil {
			return session, fmt.Errorf("applying allowlist: %w", err)
		}
		if session.AllowlistSuppressed > 0 {
			if err := pipeline.PersistArtifacts(sessionDir, session); err != nil {
				return session, fmt.Errorf("persisting allowlist results: %w", err)
			}
		}
	}

	// The baseline is applied before triage so known findings do not consume
	// LLM budget.
	if tf.baseline != "" {
		if err := applyBaseline(session, tf.baseline, tf.logger); err != nil {
			return session, fmt.Errorf("applying baseline: %w", err)
		}
		if session.BaselineSuppressed > 0 {
			if err := pipeline.PersistArtifacts(sessionDir, session); err != nil {
				return session, fmt.Errorf("persisting baseline results: %w", err)
			}
		}
	}

	if tf.triage {
		if err := runTriage(c, session, workdir, tf.logger, tf.triageProvider); err != nil {
			return session, fmt.Errorf("triage failed: %w", err)
		}
		if err := pipeline.PersistArtifacts(sessionDir, session); err != nil {
			return session, fmt.Errorf("persisting triage results: %w", err)
		}
	}

	if tf.osvLookup {
		vulns, err := lookupOSV(c.Context(), session, tf.logger)
		if err != nil {
			// A failed lookup must not lose the analysis that already
			// succeeded.
			tf.logger.Warn("OSV lookup failed", "error", err)
		} else {
			session.App.Vulnerabilities = vulns
			session.Findings = append(session.Findings, vulnerabilityFindings(session, vulns)...)
			if err := pipeline.PersistArtifacts(sessionDir, session); err != nil {
				return session, fmt.Errorf("persisting vulnerability results: %w", err)
			}
		}
	}

	if tf.writeSBOM {
		if err := writeSBOMFile(sessionDir, session); err != nil {
			return session, fmt.Errorf("writing SBOM: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "Analysis complete: %s (status: %s)\n", session.ID, session.Status)
	fmt.Fprintf(os.Stderr, "Findings: %d\n", len(session.Findings))
	if len(session.FailedTools) > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %d stage(s) failed (%s) — the report is partial\n",
			len(session.FailedTools), strings.Join(session.FailedTools, ", "))
	}
	if tf.triage {
		fmt.Fprintf(os.Stderr, "Triaged: %d\n", countTriaged(session.Findings))
	}
	if session.FindingsMapped > 0 {
		fmt.Fprintf(os.Stderr, "Mapped findings: %d\n", session.FindingsMapped)
	}
	if session.AllowlistSuppressed > 0 {
		fmt.Fprintf(os.Stderr, "Allowlist suppressed: %d\n", session.AllowlistSuppressed)
	}
	if session.BaselineSuppressed > 0 {
		fmt.Fprintf(os.Stderr, "Baseline suppressed: %d\n", session.BaselineSuppressed)
	}
	fmt.Fprintf(os.Stderr, "Artifacts: %s/%s/\n", workdir, session.ID)

	if gateEnabled {
		if n := countAtOrAbove(session.Findings, failThreshold); n > 0 {
			return session, fmt.Errorf("%w: %d finding(s) at %s or higher", ErrFindingsAboveThreshold, n, failThreshold)
		}
	}
	return session, nil
}

// printTargetSummary prints a compact per-target table for batch runs.
func printTargetSummary(results []targetResult) {
	fmt.Fprintf(os.Stderr, "\n%-40s %-18s %-10s %s\n", "TARGET", "SESSION", "STATUS", "FINDINGS")
	for _, r := range results {
		id, status, findings := "-", "-", "-"
		if r.session != nil {
			id = r.session.ID
			status = string(r.session.Status)
			findings = strconv.Itoa(len(r.session.Findings))
		}
		if r.err != nil {
			status = "failed"
		}
		fmt.Fprintf(os.Stderr, "%-40s %-18s %-10s %s\n", filepath.Base(r.path), id, status, findings)
	}
}

func runTriage(c *cobra.Command, session *models.AnalysisSession, workdir string, logger *slog.Logger, triageProvider string) error {
	cfg, err := loadConfigWithFlags(c)
	if err != nil {
		return err
	}

	if triageProvider != "" {
		if cfg.LLM.Tasks == nil {
			cfg.LLM.Tasks = make(map[string]config.Task)
		}
		task := cfg.LLM.Tasks["triage"]
		task.Provider = triageProvider
		cfg.LLM.Tasks["triage"] = task
	}

	factory := llm.NewFactory(logger)
	providers, err := factory.CreateAll(cfg.LLM.Providers)
	if err != nil {
		return fmt.Errorf("creating providers: %w", err)
	}

	router := llm.NewRouter(providers, cfg.LLM, logger)

	cache, cacheErr := llm.NewCache(0)
	if cacheErr != nil {
		logger.Warn("cache unavailable", "error", cacheErr)
	}

	cost := llm.NewCostAccumulator(logger)
	retry := llm.RetryConfig{
		MaxRetries: cfg.LLM.MaxRetries,
		BaseDelay:  time.Duration(cfg.LLM.RetryBaseDelayMS) * time.Millisecond,
		MaxDelay:   8 * time.Second,
	}
	timeout := time.Duration(cfg.LLM.TimeoutSeconds) * time.Second

	sessionDir := filepath.Join(workdir, session.ID)
	codeCtx, triageCfg := pipeline.TriageConfigFor(sessionDir, session.Platform, session.Findings)

	triageEngine := llm.NewTriageEngineWithRetry(router, cache, cost, triageCfg, retry, timeout, logger)

	if _, err = triageEngine.Triage(c.Context(), session.Findings, codeCtx); err != nil {
		return err
	}
	session.LLMCostUSD = cost.Total()
	pipeline.PropagateClusterVerdicts(session.Findings)
	return nil
}

func countTriaged(findings []models.Finding) int {
	count := 0
	for _, f := range findings {
		if f.LLMVerdict == models.VerdictConfirmed || f.LLMVerdict == models.VerdictLikelyFP {
			count++
		}
	}
	return count
}

// stageOptions controls which stages run and how the toolchain is configured.
type stageOptions struct {
	// stages is the explicit stage filter; empty means "use the defaults".
	stages []string
	// noRes skips resource decoding in the decompilers.
	noRes bool
	// quick disables the optional scanners (gitleaks and semgrep).
	quick bool
	// noSecrets disables only the gitleaks secret scanner.
	noSecrets bool
	// rules overrides the embedded semgrep rule pack.
	rules string
	// decompiler selects which decompiler(s) run: apktool, jadx or both.
	decompiler string
	// decompilerSet records whether --decompiler was passed explicitly.
	decompilerSet bool
	// reuse skips a decompiler whose output already exists in sessionDir.
	reuse      bool
	sessionDir string
	// expectCert is the signing certificate fingerprint the artifact is
	// expected to carry.
	expectCert string
}

const (
	stageGitleaks = "gitleaks"
	stageSemgrep  = "semgrep"
	stageAPKTool  = "apktool"
	stageJADX     = "jadx"
	stageDEXDC    = "dexdc"
)

// optInStages are the optional scanners. They never run on a default pass:
// the operator has to name them in --stages.
var optInStages = map[string]bool{
	stageGitleaks: true,
	stageSemgrep:  true,
}

// androidStages and iosStages are the names accepted by --stages. The list is
// deliberately explicit: a typo must fail instead of silently producing a
// report that skipped a check.
var (
	androidStages = []string{
		stageAPKTool, stageJADX, stageDEXDC, "apksigner", "elf", "anti-analysis",
		"repack", "sdk", stageGitleaks, stageSemgrep, "inventory",
	}
	iosStages = []string{
		"ipa-extract", "plist", "macho", "codesign", "classdump", "strings",
		stageGitleaks, stageSemgrep, "inventory",
	}
)

// validateStages rejects unknown --stages entries and lists the valid names
// for the detected platform.
func validateStages(stages []string, plat models.Platform) error {
	valid := androidStages
	if plat == models.PlatformIOS {
		valid = iosStages
	}
	known := make(map[string]bool, len(valid))
	for _, name := range valid {
		known[stageKey(name)] = true
	}
	var unknown []string
	for _, name := range stages {
		if !known[stageKey(name)] {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	return fmt.Errorf("unknown stage(s) for %s: %s (valid: %s)",
		plat, strings.Join(unknown, ", "), strings.Join(valid, ", "))
}

// stageEnabled reports whether a stage runs, honouring the explicit filter
// and the quick/no-secrets switches. The scanners are opt-in; every other
// stage runs by default or when named. apksigner is implicit for Android and
// cannot be disabled.
func (o stageOptions) stageEnabled(name string) bool {
	if o.quick && optInStages[name] {
		return false
	}
	if o.noSecrets && name == stageGitleaks {
		return false
	}
	if name == "apksigner" {
		return true
	}
	named := false
	for _, s := range o.stages {
		if stageKey(s) == stageKey(name) {
			named = true
			break
		}
	}
	if optInStages[name] {
		return named
	}
	return len(o.stages) == 0 || named
}

// cachedTree reports whether a previous decompiler run left a usable tree.
func cachedTree(sessionDir, name string) bool {
	_, err := os.Stat(filepath.Join(sessionDir, name, "AndroidManifest.xml"))
	return err == nil
}

// includeDecompilers adds the explicitly selected backends to a --stages
// list without duplicating entries.
func includeDecompilers(stages []string, decompiler string) []string {
	out := append([]string(nil), stages...)
	for _, name := range selectedDecompilers(stageOptions{decompiler: decompiler, decompilerSet: true}) {
		if !stageNamed(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// validateDecompiler rejects unknown --decompiler values.
func validateDecompiler(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || value == "both" {
		return nil
	}
	for _, part := range strings.Split(value, ",") {
		switch strings.TrimSpace(part) {
		case stageAPKTool, stageJADX, stageDEXDC:
		default:
			return fmt.Errorf("invalid --decompiler value %q (use apktool, jadx, dexdc, both or a comma-separated list)", value)
		}
	}
	return nil
}

// stageNamed reports whether an explicit --stages list names a stage.
func stageNamed(stages []string, name string) bool {
	for _, s := range stages {
		if stageKey(s) == stageKey(name) {
			return true
		}
	}
	return false
}

// stageKey makes `--stages` tolerant to the hyphen/underscore difference
// between the CLI spelling (`anti-analysis`) and the analyzer identifier
// (`anti_analysis`).
func stageKey(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "-", "_")
}

// rulePackPath resolves the semgrep rule pack: the explicit override when
// given, otherwise the copy embedded in the binary.
func rulePackPath(override string, pack rules.Pack) string {
	if override != "" {
		return override
	}
	path, err := rules.Materialize(pack)
	if err != nil {
		return ""
	}
	return path
}

// selectedDecompilers resolves --decompiler/--stages into backend names.
func selectedDecompilers(opts stageOptions) []string {
	if opts.decompilerSet {
		raw := strings.TrimSpace(opts.decompiler)
		if raw == "both" {
			return []string{stageAPKTool, stageJADX}
		}
		var out []string
		for _, part := range strings.Split(raw, ",") {
			switch strings.TrimSpace(part) {
			case stageAPKTool, stageJADX, stageDEXDC:
				out = append(out, strings.TrimSpace(part))
			}
		}
		return out
	}
	var out []string
	for _, name := range []string{stageAPKTool, stageJADX, stageDEXDC} {
		if stageNamed(opts.stages, name) {
			out = append(out, name)
		}
	}
	if len(opts.stages) == 0 {
		return []string{stageJADX}
	}
	return out
}

// jadxThreadsFromEnv lets an evaluation run cap jadx parallelism without a
// dedicated flag. Zero keeps the analyzer default (runtime.NumCPU()).
func jadxThreadsFromEnv() int {
	raw := strings.TrimSpace(os.Getenv("MOBISCOPE_JADX_THREADS"))
	if raw == "" {
		return 0
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}

// cachedDEXDC reports whether a previous dexdc run left a non-empty tree.
func cachedDEXDC(sessionDir string) bool {
	entries, err := os.ReadDir(filepath.Join(sessionDir, "dexdc"))
	return err == nil && len(entries) > 0
}

func buildAnalyzers(opts stageOptions, target *platform.Target) []analyzers.Analyzer {
	var list []analyzers.Analyzer

	if target != nil && target.Platform == models.PlatformIOS {
		if opts.stageEnabled("ipa-extract") {
			list = append(list, analyzers.NewIPAExtract())
		}
		if opts.stageEnabled("plist") {
			list = append(list, analyzers.NewPlistAnalyzer())
		}
		if opts.stageEnabled("macho") {
			list = append(list, analyzers.NewMachO())
		}
		if opts.stageEnabled("codesign") {
			list = append(list, analyzers.NewCodeSign())
		}
		if opts.stageEnabled("classdump") {
			list = append(list, analyzers.NewClassDump())
		}
		if opts.stageEnabled("strings") {
			list = append(list, analyzers.NewStrings())
		}
		if opts.stageEnabled(stageGitleaks) {
			list = append(list, analyzers.NewGitleaks())
		}
		if opts.stageEnabled(stageSemgrep) {
			list = append(list, analyzers.NewSemgrep(rulePackPath(opts.rules, rules.PackIOS)))
		}
		return list
	}

	// Android decompilers. The default is jadx only: the native inventory
	// reader already covers manifest/resources/NSC, so running apktool as
	// well costs another full decode without adding core facts. apktool and
	// dexdc are opt-in; `both` keeps the historical apktool+jadx meaning,
	// and a comma-separated list (e.g. `jadx,dexdc`) selects any mix.
	for _, name := range selectedDecompilers(opts) {
		switch name {
		case stageAPKTool:
			if opts.reuse && opts.sessionDir != "" && cachedTree(opts.sessionDir, "apktool") {
				continue
			}
			list = append(list, analyzers.NewAPKTool(analyzers.APKToolConfig{NoRes: opts.noRes}))
		case stageJADX:
			if opts.reuse && opts.sessionDir != "" && cachedTree(opts.sessionDir, "jadx") {
				continue
			}
			list = append(list, analyzers.NewJADX(analyzers.JADXConfig{NoRes: opts.noRes, Threads: jadxThreadsFromEnv()}))
		case stageDEXDC:
			if opts.reuse && opts.sessionDir != "" && cachedDEXDC(opts.sessionDir) {
				continue
			}
			list = append(list, analyzers.NewDEXDC(analyzers.DEXDCConfig{}))
		}
	}
	if opts.stageEnabled("apksigner") {
		list = append(list, analyzers.NewApkSigner())
	}
	if opts.stageEnabled("elf") {
		list = append(list, analyzers.NewELF())
	}
	if opts.stageEnabled("anti-analysis") {
		list = append(list, analyzers.NewAntiAnalysis())
	}
	if opts.stageEnabled("repack") {
		list = append(list, analyzers.NewRepackWithExpectedCert(opts.expectCert))
	}
	if opts.stageEnabled("sdk") {
		list = append(list, analyzers.NewSDK())
	}
	if opts.stageEnabled(stageGitleaks) {
		list = append(list, analyzers.NewGitleaks())
	}
	if opts.stageEnabled(stageSemgrep) {
		list = append(list, analyzers.NewSemgrep(rulePackPath(opts.rules, rules.PackAndroid)))
	}
	return list
}
