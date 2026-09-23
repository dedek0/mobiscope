package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
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
	CategoryEntitlement      Category = "entitlement"
	CategoryBinaryHardening  Category = "binary_hardening"
	CategoryObfuscation      Category = "obfuscation"
	CategoryNativeCode       Category = "native_code"
	CategoryPrivacy          Category = "privacy"
)

// knownCategories is the set accepted by UnmarshalJSON. New categories must
// be added here or previously-persisted findings will fail to parse.
var knownCategories = map[Category]struct{}{
	CategorySecret:           {},
	CategoryCodePattern:      {},
	CategoryManifestIssue:    {},
	CategoryNetworkConfig:    {},
	CategoryPinningIndicator: {},
	CategoryEntitlement:      {},
	CategoryBinaryHardening:  {},
	CategoryObfuscation:      {},
	CategoryNativeCode:       {},
	CategoryPrivacy:          {},
}

func (c Category) String() string { return string(c) }

func (c Category) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(c))
}

func (c *Category) UnmarshalJSON(data []byte) error {
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if _, ok := knownCategories[Category(v)]; ok {
		*c = Category(v)
		return nil
	}
	return fmt.Errorf("invalid category: %q", v)
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
	ID          string      `json:"id"               validate:"required"`
	SessionID   string      `json:"session_id"       validate:"required"`
	SourceTool  string      `json:"source_tool"      validate:"required"`
	Category    Category    `json:"category"         validate:"required"`
	Title       string      `json:"title"            validate:"required"`
	Description string      `json:"description,omitempty"`
	Evidence    string      `json:"evidence,omitempty"`
	Location    Location    `json:"location"`
	Severity    Severity    `json:"severity"         validate:"required"`
	Sensitivity Sensitivity `json:"sensitivity"      validate:"required"`
	Confidence  float64     `json:"confidence,omitempty"`

	// Standards and taxonomy mapping (shared by Android and iOS findings).
	Platform Platform          `json:"platform,omitempty"`
	RuleID   string            `json:"rule_id,omitempty"`
	MASVS    []string          `json:"masvs,omitempty"`
	MASTG    []string          `json:"mastg,omitempty"`
	MASWE    []string          `json:"maswe,omitempty"`
	CWE      []string          `json:"cwe,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`

	NeedsLLMTriage bool    `json:"needs_llm_triage,omitempty"`
	ClusterID      string  `json:"cluster_id,omitempty"`
	Representative bool    `json:"representative,omitempty"`
	LLMVerdict     Verdict `json:"llm_verdict,omitempty"`
	LLMConfidence  float64 `json:"llm_confidence,omitempty"`
	LLMExplanation string  `json:"llm_explanation,omitempty"`
	LLMRemediation string  `json:"llm_remediation,omitempty"`
	LLMProvider    string  `json:"llm_provider,omitempty"`
	LLMModel       string  `json:"llm_model,omitempty"`
	LLMCostUSD     float64 `json:"llm_cost_usd,omitempty"`
	LLMRawResponse string  `json:"llm_raw_response,omitempty"`
}

// GenerateID produces a deterministic 16-char hex ID from finding attributes.
// Fields are joined with NUL so that shifting content between fields cannot
// collide (e.g. file "a.java" + line 12 vs file "a.java1" + line 2).
func GenerateID(sourceTool string, category Category, file string, line int, snippet string) string {
	snippetHash := sha256.Sum256([]byte(snippet))
	input := strings.Join([]string{
		sourceTool,
		string(category),
		file,
		strconv.Itoa(line),
		hex.EncodeToString(snippetHash[:]),
	}, "\x00")
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:8])
}
