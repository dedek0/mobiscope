package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

// SARIFReporter renders the session as SARIF 2.1.0 so results can be
// consumed by GitHub code scanning, VS Code and other SARIF viewers.
type SARIFReporter struct{}

// sarifLog mirrors the subset of SARIF 2.1.0 we emit.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	InformationURI  string      `json:"informationUri,omitempty"`
	SemanticVersion string      `json:"semanticVersion,omitempty"`
	Rules           []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription sarifMessage      `json:"shortDescription,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    sarifMessage      `json:"message"`
	Locations  []sarifLocation   `json:"locations,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int          `json:"startLine,omitempty"`
	Snippet   sarifMessage `json:"snippet,omitempty"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	StartTimeUTC        string `json:"startTimeUtc,omitempty"`
	EndTimeUTC          string `json:"endTimeUtc,omitempty"`
}

const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// Render writes the session as a SARIF 2.1.0 log.
func (r *SARIFReporter) Render(session *models.AnalysisSession, w io.Writer) error {
	rules := map[string]sarifRule{}
	var results []sarifResult

	for _, f := range session.Findings {
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = f.SourceTool + "/" + string(f.Category) + "/" + f.Title
		}
		if _, ok := rules[ruleID]; !ok {
			props := map[string]string{
				"category": string(f.Category),
			}
			if len(f.MASVS) > 0 {
				props["masvs"] = f.MASVS[0]
			}
			if len(f.CWE) > 0 {
				props["cwe"] = f.CWE[0]
			}
			rules[ruleID] = sarifRule{
				ID:               ruleID,
				Name:             f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				Properties:       props,
			}
		}

		props := map[string]string{
			"platform":    string(f.Platform),
			"sensitivity": string(f.Sensitivity),
		}
		if f.ClusterID != "" {
			props["cluster_id"] = f.ClusterID
		}
		if f.LLMVerdict != "" {
			props["llm_verdict"] = string(f.LLMVerdict)
		}

		results = append(results, sarifResult{
			RuleID:  ruleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Description + " " + f.Title},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.Location.File},
					Region: sarifRegion{
						StartLine: f.Location.Line,
						Snippet:   sarifMessage{Text: f.Location.Snippet},
					},
				},
			}},
			Properties: props,
		})
	}

	ruleList := make([]sarifRule, 0, len(rules))
	for _, v := range rules {
		ruleList = append(ruleList, v)
	}

	inv := sarifInvocation{ExecutionSuccessful: session.Status == models.StatusCompleted}
	if !session.StartedAt.IsZero() {
		inv.StartTimeUTC = session.StartedAt.UTC().Format(time.RFC3339)
	}
	if session.CompletedAt != nil {
		inv.EndTimeUTC = session.CompletedAt.UTC().Format(time.RFC3339)
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:            "mobiscope",
				InformationURI:  "https://github.com/dedek0/mobiscope",
				SemanticVersion: "dev",
				Rules:           ruleList,
			}},
			Results:     results,
			Invocations: []sarifInvocation{inv},
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func sarifLevel(s models.Severity) string {
	switch s {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	case models.SeverityLow, models.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}
