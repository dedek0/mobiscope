package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

	// maxURLSamples caps the unique URL sample stored in inventory.json.
	maxURLSamples = 100
)

// urlRe matches generic http(s) URLs. The generic URL rule was demoted from
// one finding per URL to an aggregate in inventory.json (it flooded reports).
var urlRe = regexp.MustCompile(`https?://[^\s"'` + "`" + `<>\\)\]}]+`)

// URLAggregate is the aggregate of generic URL occurrences found while
// scanning: Count is the total number of matches, URLs a bounded, sorted
// sample of unique normalized values.
type URLAggregate struct {
	Count int
	URLs  []string
}

type Inventory struct {
	urls URLAggregate
}

func NewInventory() *Inventory { return &Inventory{} }

// URLAggregate returns the URL aggregate collected by the last Run/Analyze
// call on this instance.
func (inv *Inventory) URLAggregate() URLAggregate { return inv.urls }

func (inv *Inventory) Name() string     { return NameInventory }
func (inv *Inventory) Available() error { return nil }
func (inv *Inventory) Run(_ context.Context, _ string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  inv.Name(),
		Version:   toolVersion,
		StartedAt: start,
	}

	srcDir := SourceRoot(workdir)

	findings := make([]models.Finding, 0, 16)

	findings = append(findings, inv.analyzeManifest(srcDir, "")...)
	findings = append(findings, inv.analyzeNetworkSecurityConfig(srcDir, "")...)
	scanned, agg := inv.scanPatterns(srcDir, "")
	findings = append(findings, scanned...)
	inv.urls = agg

	raw, _ := json.Marshal(findings)
	result.Output = raw
	result.Duration = time.Since(start)
	return result, nil
}

func (inv *Inventory) Analyze(workdir string, sessionID string) []models.Finding {
	srcDir := SourceRoot(workdir)

	findings := make([]models.Finding, 0, 16)
	findings = append(findings, inv.analyzeManifest(srcDir, sessionID)...)
	findings = append(findings, inv.analyzeNetworkSecurityConfig(srcDir, sessionID)...)
	scanned, agg := inv.scanPatterns(srcDir, sessionID)
	findings = append(findings, scanned...)
	inv.urls = agg
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
		Name: "JWT", Category: models.CategorySecret,
		Severity: models.SeverityHigh, Sensitivity: models.SensitivitySecret,
		Re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	},
	{
		Name: "Azure Storage Connection String", Category: models.CategorySecret,
		Severity: models.SeverityCritical, Sensitivity: models.SensitivitySecret,
		Re: regexp.MustCompile(`(?is)(?:DefaultEndpointsProtocol=https?|AccountName=[a-z0-9\-]+)[^"'\s]{0,120}AccountKey=[A-Za-z0-9+/=]{40,}`),
	},
	{
		Name: "Predictable IV (IvParameterSpec)", Category: models.CategoryCodePattern,
		Severity: models.SeverityMedium, Sensitivity: models.SensitivityInternal,
		Re: regexp.MustCompile(`IvParameterSpec\(\s*(?:null|new\s+byte\[\s*\d*\s*\]|"[0-9A-Fa-f]{16,}")`),
	},
	{
		Name: "Firebase URL", Category: models.CategorySecret,
		Severity: models.SeverityHigh, Sensitivity: models.SensitivityConfidential,
		Re: regexp.MustCompile(`https://[a-z0-9\-]+\.firebaseio\.com`),
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

func (inv *Inventory) scanPatterns(dir string, sessionID string) ([]models.Finding, URLAggregate) {
	var findings []models.Finding
	agg := URLAggregate{}
	seen := make(map[string]bool, maxURLSamples)

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

		// Aggregate generic URLs: count every match, keep a bounded unique
		// sample for inventory.json instead of one finding per URL.
		for _, m := range urlRe.FindAllString(content, -1) {
			agg.Count++
			u := strings.TrimRight(m, ".,;:!?)]}")
			if !seen[u] && len(seen) < maxURLSamples {
				seen[u] = true
				agg.URLs = append(agg.URLs, u)
			}
		}

		for _, rule := range scanRules {
			locs := rule.Re.FindAllStringIndex(content, -1)
			lineCursor := 1
			matchEnd := 0
			for _, loc := range locs {
				// Incremental line count: matches arrive in order.
				for i := matchEnd; i < loc[0]; i++ {
					if content[i] == '\n' {
						lineCursor++
					}
				}
				matchEnd = loc[1]
				snippet := content[loc[0]:min(loc[1], loc[0]+120)]
				line := lineCursor

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

	sort.Strings(agg.URLs)
	return findings, agg
}

func countLines(s string) int {
	return strings.Count(s, "\n") + 1
}
