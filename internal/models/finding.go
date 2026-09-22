package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

func (s Severity) String() string { return string(s) }

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

func (s *Severity) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch Severity(v) {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		*s = Severity(v)
		return nil
	default:
		return fmt.Errorf("invalid severity: %q", v)
	}
}

// Category represents the category of a security finding.
type Category string

const (
	CategorySecret           Category = "secret"
	CategoryCodePattern      Category = "code_pattern"
	CategoryManifestIssue    Category = "manifest_issue"
	CategoryNetworkConfig    Category = "network_config"
	CategoryPinningIndicator Category = "pinning_indicator"
)

func (c Category) String() string { return string(c) }

func (c Category) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(c))
}

func (c *Category) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch Category(v) {
	case CategorySecret, CategoryCodePattern, CategoryManifestIssue,
		CategoryNetworkConfig, CategoryPinningIndicator:
		*c = Category(v)
		return nil
	default:
		return fmt.Errorf("invalid category: %q", v)
	}
}

// Sensitivity represents the data sensitivity level.
type Sensitivity string

const (
	SensitivityPublic       Sensitivity = "public"
	SensitivityInternal     Sensitivity = "internal"
	SensitivityConfidential Sensitivity = "confidential"
	SensitivitySecret       Sensitivity = "secret"
)

func (s Sensitivity) String() string { return string(s) }

func (s Sensitivity) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

func (s *Sensitivity) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch Sensitivity(v) {
	case SensitivityPublic, SensitivityInternal, SensitivityConfidential, SensitivitySecret:
		*s = Sensitivity(v)
		return nil
	default:
		return fmt.Errorf("invalid sensitivity: %q", v)
	}
}

// Verdict represents the LLM assessment of a finding.
type Verdict string

const (
	VerdictConfirmed    Verdict = "confirmed"
	VerdictLikelyFP     Verdict = "likely_fp"
	VerdictInconclusive Verdict = "inconclusive"
)

func (v Verdict) String() string { return string(v) }

func (v Verdict) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(v))
}

func (v *Verdict) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch Verdict(s) {
	case VerdictConfirmed, VerdictLikelyFP, VerdictInconclusive:
		*v = Verdict(s)
		return nil
	default:
		return fmt.Errorf("invalid verdict: %q", s)
	}
}

// Location holds the source location of a finding.
type Location struct {
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	Snippet string `json:"snippet,omitempty"`
}

// Finding represents a single security finding from analysis.
type Finding struct {
	ID             string      `json:"id"               validate:"required"`
	SessionID      string      `json:"session_id"       validate:"required"`
	SourceTool     string      `json:"source_tool"      validate:"required"`
	Category       Category    `json:"category"         validate:"required"`
	Title          string      `json:"title"            validate:"required"`
	Description    string      `json:"description,omitempty"`
	Evidence       string      `json:"evidence,omitempty"`
	Location       Location    `json:"location"`
	Severity       Severity    `json:"severity"         validate:"required"`
	Sensitivity    Sensitivity `json:"sensitivity"      validate:"required"`
	Confidence     float64     `json:"confidence,omitempty"`
	NeedsLLMTriage bool        `json:"needs_llm_triage,omitempty"`
	ClusterID      string      `json:"cluster_id,omitempty"`
	Representative bool        `json:"representative,omitempty"`
	LLMVerdict     Verdict     `json:"llm_verdict,omitempty"`
	LLMConfidence  float64     `json:"llm_confidence,omitempty"`
	LLMExplanation string      `json:"llm_explanation,omitempty"`
	LLMRemediation string      `json:"llm_remediation,omitempty"`
	LLMProvider    string      `json:"llm_provider,omitempty"`
	LLMModel       string      `json:"llm_model,omitempty"`
	LLMCostUSD     float64     `json:"llm_cost_usd,omitempty"`
	LLMRawResponse string      `json:"llm_raw_response,omitempty"`
}

// GenerateID produces a deterministic 16-char hex ID from finding attributes.
func GenerateID(sourceTool string, category Category, file string, line int, snippet string) string {
	snippetHash := sha256.Sum256([]byte(snippet))
	input := fmt.Sprintf("%s%s%s%d%s", sourceTool, category, file, line, hex.EncodeToString(snippetHash[:]))
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:8])
}
