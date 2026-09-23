package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	// NameInventory is the tool identifier for the built-in inventory analyzer.
	NameInventory = "inventory"
	// AndroidManifestFile is the standard decoded manifest path.
	AndroidManifestFile = "AndroidManifest.xml"
	// NetworkSecurityConfigFile is the default NSC resource path.
	NetworkSecurityConfigFile = "res/xml/network_security_config.xml"

	// maxScanFileSize caps per-file reads during pattern scanning so one huge
	// generated file cannot exhaust memory.
	maxScanFileSize = 2 << 20
)

type Inventory struct{}

func NewInventory() *Inventory { return &Inventory{} }

func (inv *Inventory) Name() string     { return NameInventory }
func (inv *Inventory) Available() error { return nil }
func (inv *Inventory) Run(_ context.Context, _ string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  inv.Name(),
		Version:   "1.0.0",
		StartedAt: start,
	}

	jadxDir := JADXArtifactPath(workdir)
	if !dirExists(jadxDir) {
		jadxDir = workdir
	}

	findings := make([]models.Finding, 0, 16)

	findings = append(findings, inv.analyzeManifest(jadxDir, "")...)
	findings = append(findings, inv.analyzeNetworkSecurityConfig(jadxDir, "")...)
	findings = append(findings, inv.scanPatterns(jadxDir, "")...)

	raw, _ := json.Marshal(findings)
	result.Output = raw
	result.Duration = time.Since(start)
	return result, nil
}

func (inv *Inventory) Analyze(workdir string, sessionID string) []models.Finding {
	jadxDir := JADXArtifactPath(workdir)
	if !dirExists(jadxDir) {
		jadxDir = workdir
	}

	findings := make([]models.Finding, 0, 16)
	findings = append(findings, inv.analyzeManifest(jadxDir, sessionID)...)
	findings = append(findings, inv.analyzeNetworkSecurityConfig(jadxDir, sessionID)...)
	findings = append(findings, inv.scanPatterns(jadxDir, sessionID)...)
	return findings
}

// --- Pattern scanning ---

type patternRule struct {
	Name        string
	Category    models.Category
	Severity    models.Severity
	Sensitivity models.Sensitivity
	Re          *regexp.Regexp
}

var scanRules = []patternRule{
	{
		Name: "AWS Access Key", Category: models.CategorySecret,
		Severity: models.SeverityCritical, Sensitivity: models.SensitivitySecret,
		Re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	},
	{
		Name: "GCP API Key", Category: models.CategorySecret,
		Severity: models.SeverityHigh, Sensitivity: models.SensitivitySecret,
		Re: regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
	},
	{
		Name: "Google OAuth Client ID", Category: models.CategorySecret,
		Severity: models.SeverityHigh, Sensitivity: models.SensitivitySecret,
		Re: regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
	},
	{
		Name: "GitHub Token", Category: models.CategorySecret,
		Severity: models.SeverityCritical, Sensitivity: models.SensitivitySecret,
		Re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),
	},
	{
		Name: "Slack Token", Category: models.CategorySecret,
		Severity: models.SeverityCritical, Sensitivity: models.SensitivitySecret,
		Re: regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`),
	},
	{
		Name: "Private Key Block", Category: models.CategorySecret,
		Severity: models.SeverityCritical, Sensitivity: models.SensitivitySecret,
		Re: regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`),
	},
	{
		Name: "Firebase URL", Category: models.CategorySecret,
		Severity: models.SeverityHigh, Sensitivity: models.SensitivityConfidential,
		Re: regexp.MustCompile(`https://[a-z0-9\-]+\.firebaseio\.com`),
	},
	{
		Name: "Generic URL", Category: models.CategoryCodePattern,
		Severity: models.SeverityInfo, Sensitivity: models.SensitivityPublic,
		Re: regexp.MustCompile(`https?://[^\s"'<>]+`),
	},
	{
		Name: "IP Address", Category: models.CategoryCodePattern,
		Severity: models.SeverityLow, Sensitivity: models.SensitivityInternal,
		Re: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
	},
	{
		Name: "Email Address", Category: models.CategoryCodePattern,
		Severity: models.SeverityInfo, Sensitivity: models.SensitivityInternal,
		Re: regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
	},
	// Pinning indicators
	{
		Name: "X509TrustManager", Category: models.CategoryPinningIndicator,
		Severity: models.SeverityInfo, Sensitivity: models.SensitivityPublic,
		Re: regexp.MustCompile(`X509TrustManager`),
	},
	{
		Name: "CertificatePinner", Category: models.CategoryPinningIndicator,
		Severity: models.SeverityInfo, Sensitivity: models.SensitivityPublic,
		Re: regexp.MustCompile(`CertificatePinner`),
	},
	{
		Name: "TrustKit", Category: models.CategoryPinningIndicator,
		Severity: models.SeverityInfo, Sensitivity: models.SensitivityPublic,
		Re: regexp.MustCompile(`TrustKit`),
	},
	{
		Name: "sha256/ pin", Category: models.CategoryPinningIndicator,
		Severity: models.SeverityInfo, Sensitivity: models.SensitivityPublic,
		Re: regexp.MustCompile(`sha256/[A-Za-z0-9+/=]+`),
	},
	{
		Name: "pin-sha256", Category: models.CategoryPinningIndicator,
		Severity: models.SeverityInfo, Sensitivity: models.SensitivityPublic,
		Re: regexp.MustCompile(`pin-sha256`),
	},
	{
		Name: "BEGIN CERTIFICATE", Category: models.CategoryPinningIndicator,
		Severity: models.SeverityInfo, Sensitivity: models.SensitivityPublic,
		Re: regexp.MustCompile(`-----BEGIN CERTIFICATE-----`),
	},
}

func (inv *Inventory) scanPatterns(dir string, sessionID string) []models.Finding {
	var findings []models.Finding

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		// Never follow symlinks: a malicious APK can plant a link to a host
		// file and exfiltrate it into findings and LLM prompts.
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".java" && ext != ".smali" && ext != ".xml" && ext != ".kt" && ext != ".json" && ext != ".properties" && ext != ".cfg" {
			return nil
		}

		info, err := d.Info()
		if err == nil && info.Size() > maxScanFileSize {
			return nil
		}

		data, err := os.ReadFile(path) //nolint:gosec
		if err != nil {
			return nil
		}

		content := string(data)
		relPath, _ := filepath.Rel(dir, path)

		for _, rule := range scanRules {
			locs := rule.Re.FindAllStringIndex(content, -1)
			for _, loc := range locs {
				snippet := content[loc[0]:minInt(loc[1], loc[0]+120)]
				line := countLines(content[:loc[0]])

				f := models.Finding{
					ID:          models.GenerateID(NameInventory, rule.Category, relPath, line, snippet),
					SessionID:   sessionID,
					SourceTool:  NameInventory,
					Category:    rule.Category,
					Title:       rule.Name,
					Description: fmt.Sprintf("Pattern match for %s in %s", rule.Name, relPath),
					Evidence:    snippet,
					Location:    models.Location{File: relPath, Line: line, Snippet: snippet},
					Severity:    rule.Severity,
					Sensitivity: rule.Sensitivity,
					Confidence:  0.7,
				}
				findings = append(findings, f)
			}
		}
		return nil
	})

	return findings
}

func countLines(s string) int {
	return strings.Count(s, "\n") + 1
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
