package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	gitleaksBinary  = "gitleaks"
	gitleaksTimeout = 10 * time.Minute
)

type Gitleaks struct {
	runner CommandRunner
}

func NewGitleaks() *Gitleaks {
	return &Gitleaks{runner: &DefaultCommandRunner{}}
}

func NewGitleaksWithRunner(runner CommandRunner) *Gitleaks {
	return &Gitleaks{runner: runner}
}

func (g *Gitleaks) Name() string     { return "gitleaks" }
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
		result.Output = json.RawMessage(cmdResult.Stdout)
	}

	if err != nil {
		result.Error = err.Error()
		return result, fmt.Errorf("gitleaks execution failed: %w", err)
	}

	return result, nil
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
}

// ConvertGitleaksFindings converts gitleaks JSON output to model Findings.
func ConvertGitleaksFindings(raw json.RawMessage, sessionID string) []models.Finding {
	var gitleaksFindings []GitleaksFinding
	if err := json.Unmarshal(raw, &gitleaksFindings); err != nil {
		return nil
	}

	findings := make([]models.Finding, 0, len(gitleaksFindings))
	for _, gf := range gitleaksFindings {
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
			Severity:       models.SeverityCritical,
			Sensitivity:    models.SensitivitySecret,
			Confidence:     0.95,
			NeedsLLMTriage: true,
			Representative: true,
		}
		findings = append(findings, f)
	}
	return findings
}

func dirExists(path string) bool {
	info, err := statFn(path)
	return err == nil && info.IsDir()
}
