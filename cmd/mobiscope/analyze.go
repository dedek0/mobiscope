package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dedek0/mobiscope/internal/analyzers"
	"github.com/dedek0/mobiscope/internal/config"
	"github.com/dedek0/mobiscope/internal/llm"
	"github.com/dedek0/mobiscope/internal/models"
	"github.com/dedek0/mobiscope/internal/pipeline"
	"github.com/dedek0/mobiscope/internal/platform"
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
	)

	cmd := &cobra.Command{
		Use:   "analyze <app>",
		Short: "Run static analysis on an Android APK or iOS IPA",
		Long:  "Orchestrates decompilation and analysis tools against the target APK or IPA.",
		Args:  cobra.ExactArgs(1),
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

			apkPath := args[0]
			if err := platform.MustExist(apkPath); err != nil {
				return err
			}
			target, err := platform.Detect(apkPath)
			if err != nil {
				return fmt.Errorf("detecting platform: %w", err)
			}
			logger.Info("target detected",
				"path", target.Path,
				"platform", string(target.Platform),
				"format", target.Format,
			)

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
				Platform:       target.Platform,
			}
			if maxConc <= 0 {
				if cfg, err := loadConfigWithFlags(c); err == nil {
					opts.MaxConcurrency = cfg.Pipeline.MaxConcurrency
					if !failFast {
						opts.FailFast = cfg.Pipeline.FailFast
					}
				}
			}

			analyzersList := buildAnalyzers(stageFilter, noRes, target)
			p := pipeline.NewWithOptions(analyzersList, logger, opts)

			session, err := p.Run(ctx, apkPath, workdir, stageFilter)
			if err != nil {
				return fmt.Errorf("pipeline failed: %w", err)
			}

			if dryRun {
				fmt.Fprintf(os.Stderr, "Dry run: %d stage(s) would execute\n", len(session.ToolResults))
				for _, tr := range session.ToolResults {
					fmt.Fprintf(os.Stderr, "  - %s%s\n", tr.ToolName, tr.Error)
				}
				return nil
			}

			if triage {
				if err := runTriage(c, session, logger, triageProvider); err != nil {
					return fmt.Errorf("triage failed: %w", err)
				}
				sessionDir := filepath.Join(workdir, session.ID)
				if err := pipeline.PersistArtifacts(sessionDir, session); err != nil {
					return fmt.Errorf("persisting triage results: %w", err)
				}
			}

			fmt.Fprintf(os.Stderr, "Analysis complete: %s (status: %s)\n", session.ID, session.Status)
			fmt.Fprintf(os.Stderr, "Findings: %d\n", len(session.Findings))
			if triage {
				fmt.Fprintf(os.Stderr, "Triaged: %d\n", countTriaged(session.Findings))
			}
			fmt.Fprintf(os.Stderr, "Artifacts: %s/%s/\n", workdir, session.ID)
			return nil
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

	return cmd
}

func runTriage(c *cobra.Command, session *models.AnalysisSession, logger *slog.Logger, triageProvider string) error {
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
	triageEngine := llm.NewTriageEngineWithRetry(router, cache, cost, llm.DefaultTriageConfig(), retry, timeout, logger)

	if _, err = triageEngine.Triage(c.Context(), session.Findings, nil); err != nil {
		return err
	}
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

func buildAnalyzers(stages []string, noRes bool, target *platform.Target) []analyzers.Analyzer {
	stageSet := make(map[string]bool)
	for _, s := range stages {
		stageSet[s] = true
	}
	want := func(name string) bool { return len(stages) == 0 || stageSet[name] }

	var list []analyzers.Analyzer

	if target != nil && target.Platform == models.PlatformIOS {
		if want("ipa-extract") {
			list = append(list, analyzers.NewIPAExtract())
		}
		if want("plist") {
			list = append(list, analyzers.NewPlistAnalyzer())
		}
		if want("macho") {
			list = append(list, analyzers.NewMachO())
		}
		if want("codesign") {
			list = append(list, analyzers.NewCodeSign())
		}
		if want("strings") {
			list = append(list, analyzers.NewStrings())
		}
		if stageSet["gitleaks"] {
			list = append(list, analyzers.NewGitleaks())
		}
		if stageSet["semgrep"] {
			list = append(list, analyzers.NewSemgrep("rules/mastg-ios"))
		}
		return list
	}

	// Android (default).
	if want("apktool") {
		list = append(list, analyzers.NewAPKTool(analyzers.APKToolConfig{NoRes: noRes}))
	}
	if want("jadx") {
		list = append(list, analyzers.NewJADX(analyzers.JADXConfig{NoRes: noRes}))
	}
	if stageSet["gitleaks"] {
		list = append(list, analyzers.NewGitleaks())
	}
	if stageSet["semgrep"] {
		list = append(list, analyzers.NewSemgrep("rules/mastg"))
	}
	return list
}
