package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/dedek0/mobiscope/internal/pipeline"
	"github.com/dedek0/mobiscope/internal/utils"
	"github.com/spf13/cobra"
)

func newDiffCmd() *cobra.Command {
	var (
		workdir  string
		stages   string
		jsonPath string
		maxConc  int
		failFast bool
		verbose  bool
		quiet    bool
	)

	cmd := &cobra.Command{
		Use:   "diff <old> <new>",
		Short: "Compare the findings of two APK/IPA artifacts",
		Long: "Analyzes the two artifacts with the same stages and reports findings " +
			"that are new in the second artifact, findings that disappeared, and how " +
			"many are unchanged. Findings are matched by fingerprint (rule/category, " +
			"title, file and evidence), so a line shift does not create a new finding.",
		Args: cobra.ExactArgs(2),
		RunE: func(c *cobra.Command, args []string) error {
			level := slog.LevelInfo
			if verbose {
				level = slog.LevelDebug
			}
			if quiet {
				level = slog.LevelError
			}
			logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

			stageFilter := parseStageList(stages)
			opts := pipeline.Options{MaxConcurrency: maxConc, FailFast: failFast}
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

			run := func(path string) (*models.AnalysisSession, error) {
				return analyzeOne(c, path, workdir, stageFilter, &opts, targetFlags{
					logger: logger,
					ctx:    c.Context(),
				})
			}

			oldSession, err := run(args[0])
			if err != nil {
				return fmt.Errorf("%s: %w", args[0], err)
			}
			newSession, err := run(args[1])
			if err != nil {
				return fmt.Errorf("%s: %w", args[1], err)
			}

			result := pipeline.DiffFindings(oldSession.Findings, newSession.Findings)
			printDiff(os.Stdout, args[0], args[1], result)

			if jsonPath != "" {
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return fmt.Errorf("encoding diff: %w", err)
				}
				if err := utils.WriteFile(jsonPath, data); err != nil {
					return fmt.Errorf("writing %s: %w", jsonPath, err)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&workdir, "workdir", "targets", "Output base directory")
	cmd.Flags().StringVar(&stages, "stages", "", "Comma-separated stages (same rules as analyze)")
	cmd.Flags().StringVar(&jsonPath, "json", "", "Write the full diff to this JSON file")
	cmd.Flags().IntVar(&maxConc, "max-concurrency", 0, "Max external tools running at once (default from config)")
	cmd.Flags().BoolVar(&failFast, "fail-fast", false, "Abort on the first analyzer error")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Enable debug logging")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "Only log errors")
	return cmd
}

// parseStageList splits a --stages value the same way analyze does.
func parseStageList(value string) []string {
	if value == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(value, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// printDiff renders a human-readable diff.
func printDiff(w io.Writer, oldPath, newPath string, result pipeline.DiffResult) {
	fmt.Fprintf(w, "diff %s -> %s\n", oldPath, newPath)
	fmt.Fprintf(w, "new %d, resolved %d, unchanged %d\n", len(result.New), len(result.Resolved), result.Unchanged)

	if len(result.New) > 0 {
		fmt.Fprintln(w, "\nNew findings:")
		for _, f := range result.New {
			printFindingLine(w, f)
		}
	}
	if len(result.Resolved) > 0 {
		fmt.Fprintln(w, "\nResolved findings:")
		for _, f := range result.Resolved {
			printFindingLine(w, f)
		}
	}
}

func printFindingLine(w io.Writer, f models.Finding) {
	location := f.Location.File
	if f.Location.Line > 0 {
		location = fmt.Sprintf("%s:%d", location, f.Location.Line)
	}
	if location == "" {
		location = "-"
	}
	fmt.Fprintf(w, "  [%s] %s (%s)\n", f.Severity, f.Title, location)
}
