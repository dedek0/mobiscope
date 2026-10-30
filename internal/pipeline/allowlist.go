package pipeline

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/dedek0/mobiscope/internal/models"
	"gopkg.in/yaml.v3"
)

// maxAllowlistBytes caps the operator-supplied allowlist file.
const maxAllowlistBytes = 4 << 20

// AllowRule suppresses findings that match every non-empty criterion. Each
// rule must carry a reason so the allowlist documents why a finding is
// accepted. Patterns support a single * / ? / [] wildcard via path.Match;
// patterns without a wildcard are matched as substrings.
type AllowRule struct {
	// Reason is mandatory and documents the exception.
	Reason string `yaml:"reason" json:"reason"`
	// Tool matches Finding.SourceTool.
	Tool string `yaml:"tool,omitempty" json:"tool,omitempty"`
	// Category matches Finding.Category.
	Category string `yaml:"category,omitempty" json:"category,omitempty"`
	// RuleID matches Finding.RuleID.
	RuleID string `yaml:"rule_id,omitempty" json:"rule_id,omitempty"`
	// Title matches Finding.Title.
	Title string `yaml:"title,omitempty" json:"title,omitempty"`
	// File matches Finding.Location.File.
	File string `yaml:"file,omitempty" json:"file,omitempty"`
	// Evidence matches Finding.Evidence.
	Evidence string `yaml:"evidence,omitempty" json:"evidence,omitempty"`
}

// allowlistFile is the top-level YAML shape. A bare list is also accepted.
type allowlistFile struct {
	Allow []AllowRule `yaml:"allow"`
}

// LoadAllowlist parses a YAML allowlist. Rules without a reason or without any
// matching criterion are rejected: an allowlist entry must be explainable.
func LoadAllowlist(file string) ([]AllowRule, error) {
	info, err := os.Stat(file)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxAllowlistBytes {
		return nil, fmt.Errorf("allowlist too large: %d bytes", info.Size())
	}
	data, err := os.ReadFile(file) //nolint:gosec // explicit operator-supplied allowlist path
	if err != nil {
		return nil, err
	}

	var wrapper allowlistFile
	var rules []AllowRule
	if err := yaml.Unmarshal(data, &wrapper); err == nil && len(wrapper.Allow) > 0 {
		rules = wrapper.Allow
	} else {
		// Try a bare list.
		var bare []AllowRule
		if err := yaml.Unmarshal(data, &bare); err != nil {
			return nil, fmt.Errorf("decoding allowlist %s: %w", file, err)
		}
		rules = bare
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("allowlist %s has no rules", file)
	}
	for i, rule := range rules {
		if strings.TrimSpace(rule.Reason) == "" {
			return nil, fmt.Errorf("allowlist %s: rule #%d needs a reason", file, i+1)
		}
		if !rule.hasCriteria() {
			return nil, fmt.Errorf("allowlist %s: rule #%d has no matching field", file, i+1)
		}
	}
	return rules, nil
}

// hasCriteria reports whether the rule can match anything.
func (r AllowRule) hasCriteria() bool {
	return r.Tool != "" || r.Category != "" || r.RuleID != "" ||
		r.Title != "" || r.File != "" || r.Evidence != ""
}

// Matches reports whether every populated criterion matches the finding.
func (r AllowRule) Matches(f models.Finding) bool {
	if r.Tool != "" && !matchAllowPattern(r.Tool, f.SourceTool) {
		return false
	}
	if r.Category != "" && !matchAllowPattern(r.Category, string(f.Category)) {
		return false
	}
	if r.RuleID != "" && !matchAllowPattern(r.RuleID, f.RuleID) {
		return false
	}
	if r.Title != "" && !matchAllowPattern(r.Title, f.Title) {
		return false
	}
	if r.File != "" && !matchAllowPattern(r.File, f.Location.File) {
		return false
	}
	if r.Evidence != "" && !matchAllowPattern(r.Evidence, f.Evidence) {
		return false
	}
	return true
}

// matchAllowPattern matches a wildcard pattern or a substring.
func matchAllowPattern(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return true
	}
	// **/ means "any directory prefix"; path.Match does not cross
	// separators, so handle the common leading form explicitly.
	if strings.HasPrefix(pattern, "**/") {
		pattern = strings.TrimPrefix(pattern, "**/")
		if strings.HasSuffix(value, "/"+pattern) || value == pattern {
			return true
		}
	}
	if strings.ContainsAny(pattern, "*?[") {
		if ok, err := path.Match(pattern, value); err == nil && ok {
			return true
		}
		// A pattern like "*.java" is common; also try the base name.
		if ok, err := path.Match(pattern, path.Base(value)); err == nil && ok {
			return true
		}
		return false
	}
	return strings.Contains(value, pattern)
}

// FilterAllowlist removes findings matched by an allowlist rule. It returns
// the survivors and the number of suppressed findings.
func FilterAllowlist(findings []models.Finding, rules []AllowRule) ([]models.Finding, int) {
	if len(rules) == 0 {
		return findings, 0
	}
	out := make([]models.Finding, 0, len(findings))
	suppressed := 0
	for _, f := range findings {
		matched := false
		for _, rule := range rules {
			if rule.Matches(f) {
				matched = true
				break
			}
		}
		if matched {
			suppressed++
			continue
		}
		out = append(out, f)
	}
	return out, suppressed
}
