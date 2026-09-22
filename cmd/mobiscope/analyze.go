package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/dedek0/mobiscope/internal/analyzers"
	"github.com/dedek0/mobiscope/internal/config"
	"github.com/dedek0/mobiscope/internal/llm"
	"github.com/dedek0/mobiscope/internal/models"
	"github.com/dedek0/mobiscope/internal/pipeline"
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
	)

	cmd := &cobra.Command{
		Use:   "analyze <apk>",
		Short: "Run static analysis on an APK file",
		Long:  "Orchestrates decompilation and analysis tools against the target APK.",
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

			apkPath := args[0]
			if _, err := os.Stat(apkPath); os.IsNotExist(err) {
				return fmt.Errorf("APK not found: %s", apkPath)
			}

			var stageFilter []string
			if stages != "" {
				stageFilter = strings.Split(stages, ",")
			}

			analyzersList := buildAnalyzers(stageFilter, noRes)
			p := pipeline.New(analyzersList, logger)

			session, err := p.Run(c.Context(), apkPath, workdir, stageFilter)
			if err != nil {
				return fmt.Errorf("pipeline failed: %w", err)
			}

			if triage {
				if err := runTriage(c, session, logger, triageProvider); err != nil {
					return fmt.Errorf("triage failed: %w", err)
				}
			}

			fmt.Fprintf(os.Stderr, "Analysis complete: %s (status: %s)\n", session.ID, session.Status)
			fmt.Fprintf(os.Stderr, "Findings: %d\n", len(session.Findings))
			if triage {
				fmt.Fprintf(os.Stderr, "Triaged: %d\n", countTriaged(session.Findings))
			}
			fmt.Fprintf(os.Stderr, "Artifacts: %s/%s/\n", workdir, session.ID[:16])
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

	return cmd
}

func runTriage(c *cobra.Command, session *models.AnalysisSession, logger *slog.Logger, triageProvider string) error {
	cfg, err := loadConfigWithFlags()
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
	triageEngine := llm.NewTriageEngine(router, cache, cost, llm.DefaultTriageConfig(), logger)

	_, err = triageEngine.Triage(c.Context(), session.Findings, nil)
	if err != nil {
		if errors.Is(err, llm.ErrCloudNotAllowed) || errors.Is(err, llm.ErrProviderUnavailable) {
			return err
		}
	}
	return err
}

func countTriaged(findings []models.Finding) int {
	count := 0
	for _, f := range findings {
		if f.LLMVerdict != "" {
			count++
		}
	}
	return count
}

func buildAnalyzers(stages []string, noRes bool) []analyzers.Analyzer {
	stageSet := make(map[string]bool)
	for _, s := range stages {
		stageSet[strings.TrimSpace(s)] = true
	}

	var list []analyzers.Analyzer

	if len(stages) == 0 || stageSet["apktool"] {
		list = append(list, analyzers.NewAPKTool(analyzers.APKToolConfig{NoRes: noRes}))
	}
	if len(stages) == 0 || stageSet["jadx"] {
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
