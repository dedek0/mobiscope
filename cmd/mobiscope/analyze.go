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
	)

	cmd := &cobra.Command{
		Use:   "analyze <app> [more apps...]",
		Short: "Run static analysis on an Android APK or iOS IPA",
		Long:  "Orchestrates decompilation and analysis tools against one or more target APK/IPA files. Each target gets its own session directory under --workdir.",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
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
	cmd.Flags().StringVar(&stages, "stages", "", "Comma-separated stages (apktool,jadx,gitleaks,semgrep,inventory)")
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
	cmd.Flags().StringVar(&decompiler, "decompiler", "both", "Decompiler to run: apktool, jadx or both")
	cmd.Flags().StringVar(&expectCert, "expect-cert", "", "Expected signing certificate fingerprint (hex); a mismatch is reported as a repackaging signal")
	cmd.Flags().BoolVar(&osvLookup, "osv", false, "Look the detected libraries up in the OSV vulnerability database (reaches the network)")
	cmd.Flags().BoolVar(&writeSBOM, "sbom", false, "Write a CycloneDX software bill of materials next to the report")

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

	analyzersList := buildAnalyzers(stageOptions{
		stages:     stageFilter,
		noRes:      tf.noRes,
		quick:      tf.quick,
		noSecrets:  tf.noSecrets,
		rules:      tf.rulesPath,
		decompiler: tf.decompiler,
		expectCert: tf.expectCert,
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
	fmt.Fprintf(os.Stderr, "Artifacts: %s/%s/\n", workdir, session.ID)
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
	// expectCert is the signing certificate fingerprint the artifact is
	// expected to carry.
	expectCert string
}

// stageEnabled reports whether a stage runs, honouring the explicit filter
// and the quick/no-secrets switches.
func (o stageOptions) stageEnabled(name string) bool {
	if o.quick && (name == "gitleaks" || name == "semgrep") {
		return false
	}
	if o.noSecrets && name == "gitleaks" {
		return false
	}
	if len(o.stages) == 0 {
		return true
	}
	for _, s := range o.stages {
		if s == name {
			return true
		}
	}
	return false
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
		if opts.stageEnabled("gitleaks") {
			list = append(list, analyzers.NewGitleaks())
		}
		if opts.stageEnabled("semgrep") {
			list = append(list, analyzers.NewSemgrep(rulePackPath(opts.rules, rules.PackIOS)))
		}
		return list
	}

	// Android (default).
	switch opts.decompiler {
	case "apktool":
		list = append(list, analyzers.NewAPKTool(analyzers.APKToolConfig{NoRes: opts.noRes}))
	case "jadx":
		list = append(list, analyzers.NewJADX(analyzers.JADXConfig{NoRes: opts.noRes}))
	default:
		if opts.stageEnabled("apktool") {
			list = append(list, analyzers.NewAPKTool(analyzers.APKToolConfig{NoRes: opts.noRes}))
		}
		if opts.stageEnabled("jadx") {
			list = append(list, analyzers.NewJADX(analyzers.JADXConfig{NoRes: opts.noRes}))
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
	if opts.stageEnabled("gitleaks") {
		list = append(list, analyzers.NewGitleaks())
	}
	if opts.stageEnabled("semgrep") {
		list = append(list, analyzers.NewSemgrep(rulePackPath(opts.rules, rules.PackAndroid)))
	}
	return list
}
