package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	semgrepBinary  = "semgrep"
	semgrepTimeout = 15 * time.Minute
)

type Semgrep struct {
	runner CommandRunner
	rules  string
}

func NewSemgrep(rulesPath string) *Semgrep {
	return &Semgrep{runner: &DefaultCommandRunner{}, rules: rulesPath}
}

func NewSemgrepWithRunner(rulesPath string, runner CommandRunner) *Semgrep {
	return &Semgrep{runner: runner, rules: rulesPath}
}

func (s *Semgrep) Name() string     { return "semgrep" }
func (s *Semgrep) Available() error { return CheckBinary(semgrepBinary) }

func (s *Semgrep) Run(ctx context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  s.Name(),
		Version:   ParseVersion(semgrepBinary),
		StartedAt: start,
	}

	jadxDir := JADXArtifactPath(workdir)
	if !dirExists(jadxDir) {
		jadxDir = workdir
	}

	args := []string{
		"--config", s.rules,
		"--sarif",
		"--output", "-",
		"--quiet",
		jadxDir,
	}

	cmdResult, err := s.runner.Run(ctx, semgrepBinary, args, semgrepTimeout, nil)
	result.Duration = time.Since(start)

	if cmdResult != nil {
		result.ExitCode = cmdResult.ExitCode
		result.Output = json.RawMessage(cmdResult.Stdout)
	}

	if err != nil {
		result.Error = err.Error()
		return result, fmt.Errorf("semgrep execution failed: %w", err)
	}

	return result, nil
}

// SARIF v2.1.0 minimal structures for parsing semgrep output.
type SARIFLog struct {
	Runs []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Results []SARIFResult `json:"results"`
	Tool    SARIFTool     `json:"tool"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name            string      `json:"name"`
	Rules           []SARIFRule `json:"rules"`
	SemanticVersion string      `json:"semanticVersion"`
}

type SARIFRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name"`
	ShortDescription     SARIFDescription       `json:"shortDescription"`
	DefaultConfiguration SARIFConfig            `json:"defaultConfiguration"`
	Properties           map[string]interface{} `json:"properties"`
}

type SARIFDescription struct {
	Text string `json:"text"`
}

type SARIFConfig struct {
	Level string `json:"level"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int          `json:"startLine"`
	StartColumn int          `json:"startColumn"`
	EndLine     int          `json:"endLine"`
	Snippet     SARIFSnippet `json:"snippet"`
}

type SARIFSnippet struct {
	Text string `json:"text"`
}

// ConvertSemgrepFindings converts SARIF output to model Findings.
func ConvertSemgrepFindings(raw json.RawMessage, sessionID string) []models.Finding {
	var sarif SARIFLog
	if err := json.Unmarshal(raw, &sarif); err != nil {
		return nil
	}

	ruleLookup := make(map[string]SARIFRule)
	for _, run := range sarif.Runs {
		for _, rule := range run.Tool.Driver.Rules {
			ruleLookup[rule.ID] = rule
		}
	}

	var findings []models.Finding
	for _, run := range sarif.Runs {
		for _, r := range run.Results {
			rule := ruleLookup[r.RuleID]

			file := ""
			line := 0
			snippet := ""
			if len(r.Locations) > 0 {
				loc := r.Locations[0]
				file = loc.PhysicalLocation.ArtifactLocation.URI
				line = loc.PhysicalLocation.Region.StartLine
				snippet = loc.PhysicalLocation.Region.Snippet.Text
			}

			severity := sarifLevelToSeverity(r.Level)
			sensitivity := sarifSeverityToSensitivity(rule.DefaultConfiguration.Level)

			f := models.Finding{
				ID:          models.GenerateID("semgrep", models.CategoryCodePattern, file, line, snippet),
				SessionID:   sessionID,
				SourceTool:  "semgrep",
				Category:    models.CategoryCodePattern,
				Title:       rule.ShortDescription.Text,
				Description: r.Message.Text,
				Evidence:    snippet,
				Location: models.Location{
					File:    file,
					Line:    line,
					Snippet: snippet,
				},
				Severity:       severity,
				Sensitivity:    sensitivity,
				Confidence:     0.8,
				NeedsLLMTriage: true,
				Representative: true,
			}
			findings = append(findings, f)
		}
	}
	return findings
}

func sarifLevelToSeverity(level string) models.Severity {
	switch level {
	case "error":
		return models.SeverityCritical
	case "warning":
		return models.SeverityMedium
	case "note", "info":
		return models.SeverityInfo
	default:
		return models.SeverityLow
	}
}

func sarifSeverityToSensitivity(level string) models.Sensitivity {
	switch level {
	case "error":
		return models.SensitivityConfidential
	case "warning":
		return models.SensitivityInternal
	case "note", "info":
		return models.SensitivityPublic
	default:
		return models.SensitivityPublic
	}
}
