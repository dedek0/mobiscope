package analyzers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	gitleaksBinary  = "gitleaks"
	gitleaksTimeout = 10 * time.Minute
)

// gitleaksExitLeak is gitleaks' exit code when leaks are found (success for us).
const gitleaksExitLeak = 1

type Gitleaks struct {
	runner CommandRunner
	logger *slog.Logger
}

func NewGitleaks() *Gitleaks {
	return &Gitleaks{runner: &DefaultCommandRunner{}, logger: slog.Default()}
}

func NewGitleaksWithRunner(runner CommandRunner) *Gitleaks {
	return &Gitleaks{runner: runner, logger: slog.Default()}
}

func (g *Gitleaks) Name() string     { return gitleaksBinary }
func (g *Gitleaks) Available() error { return CheckBinary(gitleaksBinary) }

func (g *Gitleaks) Run(ctx context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  g.Name(),
		Version:   ParseVersion(gitleaksBinary),
		StartedAt: start,
	}

	jadxDir := JADXArtifactPath(workdir)
	if !dirExists(jadxDir) {
		jadxDir = workdir
	}

	args := []string{
		"detect",
		"--source", jadxDir,
		"--report-format", "json",
		"--no-git",
		"--quiet",
	}

	cmdResult, err := g.runner.Run(ctx, gitleaksBinary, args, gitleaksTimeout, nil)
	result.Duration = time.Since(start)

	if cmdResult != nil {
		result.ExitCode = cmdResult.ExitCode
		result.Output = extractJSONArray(cmdResult.Stdout)
	}

	if err != nil {
		var exitErr *ErrExit
		if errors.As(err, &exitErr) {
			// 0 = clean, 1 = leaks found. Anything else is a tool failure.
			if exitErr.Code == 0 || exitErr.Code == gitleaksExitLeak {
				return result, nil
			}
		}
		result.Error = err.Error()
		return result, fmt.Errorf("gitleaks execution failed: %w", err)
	}

	return result, nil
}

// extractJSONArray trims non-JSON preamble/warnings around a JSON array so
// noisy stdout does not silently yield zero findings.
func extractJSONArray(stdout string) json.RawMessage {
	s := strings.TrimSpace(stdout)
	start := strings.Index(s, "[")
	end := strings.LastIndex(s, "]")
	if start >= 0 && end > start {
		return json.RawMessage(s[start : end+1])
	}
	return json.RawMessage(s)
}

// GitleaksFinding represents a single gitleaks JSON output entry.
type GitleaksFinding struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Match       string   `json:"Match"`
	Secret      string   `json:"Secret"`
	File        string   `json:"File"`
	Commit      string   `json:"Commit"`
	Author      string   `json:"Author"`
	Email       string   `json:"Email"`
	Date        string   `json:"Date"`
	Message     string   `json:"Message"`
	Tags        []string `json:"Tags"`
	Fingerprint string   `json:"Fingerprint"`
	Entropy     float64  `json:"Entropy"`
}

// ConvertGitleaksFindings converts gitleaks JSON output to model Findings.
func ConvertGitleaksFindings(raw json.RawMessage, sessionID string) []models.Finding {
	if len(raw) == 0 || !json.Valid(raw) {
		return nil
	}

	var gitleaksFindings []GitleaksFinding
	if err := json.Unmarshal(raw, &gitleaksFindings); err != nil {
		return nil
	}

	findings := make([]models.Finding, 0, len(gitleaksFindings))
	for _, gf := range gitleaksFindings {
		endLine := gf.EndLine
		if endLine < gf.StartLine {
			endLine = gf.StartLine
		}
		f := models.Finding{
			ID:          models.GenerateID("gitleaks", models.CategorySecret, gf.File, gf.StartLine, gf.Match),
			SessionID:   sessionID,
			SourceTool:  "gitleaks",
			Category:    models.CategorySecret,
			Title:       fmt.Sprintf("Secret detected: %s", gf.RuleID),
			Description: gf.Description,
			Evidence:    gf.Secret,
			Location: models.Location{
				File:    gf.File,
				Line:    gf.StartLine,
				Snippet: gf.Match,
			},
			Severity:       gitleaksSeverity(gf),
			Sensitivity:    models.SensitivitySecret,
			Confidence:     gitleaksConfidence(gf),
			NeedsLLMTriage: true,
			Representative: true,
		}
		_ = endLine
		findings = append(findings, f)
	}
	return findings
}

// gitleaksSeverity derives severity from tags and entropy rather than
// hardcoding critical for every rule. Untagged secrets default to critical.
func gitleaksSeverity(gf GitleaksFinding) models.Severity {
	for _, t := range gf.Tags {
		switch strings.ToLower(t) {
		case "critical":
			return models.SeverityCritical
		case "high":
			return models.SeverityHigh
		case "medium", "med":
			return models.SeverityMedium
		case "low":
			return models.SeverityLow
		}
	}
	return models.SeverityCritical
}

func gitleaksConfidence(gf GitleaksFinding) float64 {
	if gf.Entropy >= 4.5 {
		return 0.95
	}
	if gf.Entropy > 0 {
		return 0.8
	}
	return 0.9
}

func dirExists(path string) bool {
	info, err := statFn(path)
	return err == nil && info.IsDir()
}
