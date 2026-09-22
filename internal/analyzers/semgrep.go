package analyzers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

	// Write SARIF to a file: stdout mixes logs with JSON and some builds
	// treat "-" as a literal filename.
	outPath := filepath.Join(workdir, "semgrep.sarif")
	args := []string{
		"--config", s.rules,
		"--sarif",
		"--output", outPath,
		"--quiet",
		jadxDir,
	}

	cmdResult, err := s.runner.Run(ctx, semgrepBinary, args, semgrepTimeout, nil)
	result.Duration = time.Since(start)

	if cmdResult != nil {
		result.ExitCode = cmdResult.ExitCode
	}

	if err != nil {
		var exitErr *ErrExit
		if !errors.As(err, &exitErr) || exitErr.Code != 0 {
			result.Error = err.Error()
			return result, fmt.Errorf("semgrep execution failed: %w", err)
		}
	}

	if data, readErr := os.ReadFile(outPath); readErr == nil { //nolint:gosec
		result.Output = json.RawMessage(data)
	} else if cmdResult != nil && json.Valid([]byte(cmdResult.Stdout)) {
		result.Output = extractJSONArray(cmdResult.Stdout)
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
	ID   string `json:"id"`
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
	if len(raw) == 0 || !json.Valid(raw) {
		return nil
	}

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

	findings := make([]models.Finding, 0, len(sarif.Runs))
	for _, run := range sarif.Runs {
		for _, r := range run.Results {
			rule := ruleLookup[r.RuleID]

			file := ""
			line := 0
			snippet := ""
			if len(r.Locations) > 0 {
				loc := r.Locations[0]
				file = normalizeSarifURI(loc.PhysicalLocation.ArtifactLocation.URI)
				line = loc.PhysicalLocation.Region.StartLine
				snippet = loc.PhysicalLocation.Region.Snippet.Text
			}

			// SARIF allows omitting level on a result; fall back to the rule default.
			level := r.Level
			if level == "" {
				level = rule.DefaultConfiguration.Level
			}
			severity := sarifLevelToSeverity(level)

			category := ruleCategory(rule)
			// Sensitivity reflects data exposure, not severity. A secret rule is
			// always SensitivitySecret so triage routes it to local providers only.
			sensitivity := categorySensitivity(category)

			title := rule.ShortDescription.Text
			if title == "" {
				title = r.RuleID
			}
			description := r.Message.Text
			if description == "" {
				description = r.Message.ID
			}

			f := models.Finding{
				ID:          models.GenerateID("semgrep", category, file, line, snippet),
				SessionID:   sessionID,
				SourceTool:  "semgrep",
				Category:    category,
				Title:       title,
				Description: description,
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

// normalizeSarifURI turns absolute or file:// URIs into workdir-relative paths
// so codeContext lookups and dedup keys stay stable.
func normalizeSarifURI(uri string) string {
	if uri == "" {
		return ""
	}
	if strings.HasPrefix(uri, "file://") {
		if u, err := url.Parse(uri); err == nil {
			uri = u.Path
		} else {
			uri = strings.TrimPrefix(uri, "file://")
		}
	}
	uri = strings.TrimPrefix(uri, "./")
	return filepath.ToSlash(uri)
}

// ruleCategory maps semgrep rule metadata (or the rule id as a fallback) to a
// finding category so secret rules are classified and privacy-routed correctly.
func ruleCategory(rule SARIFRule) models.Category {
	if rule.Properties != nil {
		if cat, ok := rule.Properties["category"].(string); ok {
			switch strings.ToLower(cat) {
			case "secret":
				return models.CategorySecret
			case "manifest_issue":
				return models.CategoryManifestIssue
			case "network_config":
				return models.CategoryNetworkConfig
			case "pinning_indicator":
				return models.CategoryPinningIndicator
			case "code_pattern":
				return models.CategoryCodePattern
			}
		}
	}

	id := strings.ToLower(rule.ID)
	if strings.Contains(id, "secret") || strings.Contains(id, "api-key") ||
		strings.Contains(id, "api_key") || strings.Contains(id, "credential") ||
		strings.Contains(id, "token") || strings.Contains(id, "password") {
		return models.CategorySecret
	}
	return models.CategoryCodePattern
}

func categorySensitivity(c models.Category) models.Sensitivity {
	if c == models.CategorySecret {
		return models.SensitivitySecret
	}
	return models.SensitivityInternal
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
