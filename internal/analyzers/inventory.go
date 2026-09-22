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

// --- AndroidManifest.xml analysis ---

var (
	exportedComponentRe = regexp.MustCompile(`android:exported\s*=\s*"true"`)
	debuggableRe        = regexp.MustCompile(`android:debuggable\s*=\s*"true"`)
	permissionRe        = regexp.MustCompile(`<uses-permission\s+android:name="([^"]+)"`)
)

func (inv *Inventory) analyzeManifest(dir string, sessionID string) []models.Finding {
	manifestPath := filepath.Join(dir, AndroidManifestFile)
	data, err := os.ReadFile(manifestPath) //nolint:gosec
	if err != nil {
		return nil
	}

	content := string(data)
	var findings []models.Finding //nolint:prealloc

	if debuggableRe.MatchString(content) {
		findings = append(findings, models.Finding{
			ID:          models.GenerateID(NameInventory, models.CategoryManifestIssue, AndroidManifestFile, 1, "debuggable=true"),
			SessionID:   sessionID,
			SourceTool:  NameInventory,
			Category:    models.CategoryManifestIssue,
			Title:       "Application is debuggable",
			Description: "android:debuggable=true allows debugging and inspection of the app.",
			Evidence:    "android:debuggable=\"true\"",
			Location:    models.Location{File: AndroidManifestFile, Line: 1, Snippet: "android:debuggable=\"true\""},
			Severity:    models.SeverityHigh,
			Sensitivity: models.SensitivityConfidential,
			Confidence:  1.0,
		})
	}

	for _, m := range exportedComponentRe.FindAllStringIndex(content, -1) {
		line := countLines(content[:m[0]])
		snippet := content[m[0]:minInt(m[1]+40, len(content))]
		findings = append(findings, models.Finding{
			ID:          models.GenerateID(NameInventory, models.CategoryManifestIssue, AndroidManifestFile, line, snippet),
			SessionID:   sessionID,
			SourceTool:  NameInventory,
			Category:    models.CategoryManifestIssue,
			Title:       "Exported component detected",
			Description: "Component with android:exported=true can be invoked by other applications.",
			Evidence:    snippet,
			Location:    models.Location{File: AndroidManifestFile, Line: line, Snippet: snippet},
			Severity:    models.SeverityMedium,
			Sensitivity: models.SensitivityInternal,
			Confidence:  0.9,
		})
	}

	for _, m := range permissionRe.FindAllStringSubmatchIndex(content, -1) {
		perm := content[m[2]:m[3]]
		line := countLines(content[:m[0]])
		if isDangerousPermission(perm) {
			findings = append(findings, models.Finding{
				ID:          models.GenerateID(NameInventory, models.CategoryManifestIssue, AndroidManifestFile, line, perm),
				SessionID:   sessionID,
				SourceTool:  NameInventory,
				Category:    models.CategoryManifestIssue,
				Title:       fmt.Sprintf("Dangerous permission: %s", perm),
				Description: fmt.Sprintf("The app requests dangerous permission %s.", perm),
				Evidence:    perm,
				Location:    models.Location{File: AndroidManifestFile, Line: line, Snippet: perm},
				Severity:    models.SeverityMedium,
				Sensitivity: models.SensitivityInternal,
				Confidence:  0.8,
			})
		}
	}

	return findings
}

var dangerousPerms = []string{
	"READ_CALENDAR", "WRITE_CALENDAR", "CAMERA",
	"READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
	"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
	"RECORD_AUDIO", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
	"CALL_PHONE", "ANSWER_PHONE_CALLS", "READ_CALL_LOG",
	"WRITE_CALL_LOG", "ADD_VOICEMAIL", "USE_SIP",
	"BODY_SENSORS", "SEND_SMS", "RECEIVE_SMS", "READ_SMS",
	"RECEIVE_WAP_PUSH", "RECEIVE_MMS", "READ_EXTERNAL_STORAGE",
	"WRITE_EXTERNAL_STORAGE",
}

func isDangerousPermission(perm string) bool {
	for _, dp := range dangerousPerms {
		if strings.HasSuffix(perm, dp) {
			return true
		}
	}
	return false
}

// --- Network Security Config ---

var (
	cleartextRe   = regexp.MustCompile(`cleartextTrafficPermitted\s*=\s*"true"`)
	trustAnchorRe = regexp.MustCompile(`<trust-anchors>`)
	certPinRe     = regexp.MustCompile(`<pin-set>`)
)

func (inv *Inventory) analyzeNetworkSecurityConfig(dir string, sessionID string) []models.Finding {
	nscPath := filepath.Join(dir, "res", "xml", "network_security_config.xml")
	data, err := os.ReadFile(nscPath) //nolint:gosec
	if err != nil {
		return nil
	}

	content := string(data)
	var findings []models.Finding

	if cleartextRe.MatchString(content) {
		findings = append(findings, models.Finding{
			ID:          models.GenerateID(NameInventory, models.CategoryNetworkConfig, NetworkSecurityConfigFile, 1, "cleartext=true"),
			SessionID:   sessionID,
			SourceTool:  NameInventory,
			Category:    models.CategoryNetworkConfig,
			Title:       "Cleartext traffic permitted",
			Description: "The network security config allows cleartext (HTTP) traffic.",
			Evidence:    "cleartextTrafficPermitted=\"true\"",
			Location:    models.Location{File: NetworkSecurityConfigFile, Line: 1, Snippet: "cleartextTrafficPermitted=\"true\""},
			Severity:    models.SeverityHigh,
			Sensitivity: models.SensitivityConfidential,
			Confidence:  1.0,
		})
	}

	if trustAnchorRe.MatchString(content) {
		findings = append(findings, models.Finding{
			ID:          models.GenerateID(NameInventory, models.CategoryNetworkConfig, NetworkSecurityConfigFile, 1, "trust-anchors"),
			SessionID:   sessionID,
			SourceTool:  NameInventory,
			Category:    models.CategoryNetworkConfig,
			Title:       "Custom trust anchors configured",
			Description: "Custom trust anchors may weaken TLS validation if misconfigured.",
			Evidence:    "<trust-anchors>",
			Location:    models.Location{File: NetworkSecurityConfigFile, Line: 1, Snippet: "<trust-anchors>"},
			Severity:    models.SeverityMedium,
			Sensitivity: models.SensitivityInternal,
			Confidence:  0.7,
		})
	}

	if certPinRe.MatchString(content) {
		findings = append(findings, models.Finding{
			ID:          models.GenerateID(NameInventory, models.CategoryPinningIndicator, NetworkSecurityConfigFile, 1, "pin-set"),
			SessionID:   sessionID,
			SourceTool:  NameInventory,
			Category:    models.CategoryPinningIndicator,
			Title:       "Certificate pinning configured (XML)",
			Description: "The app uses network_security_config pin-set for certificate pinning.",
			Evidence:    "<pin-set>",
			Location:    models.Location{File: NetworkSecurityConfigFile, Line: 1, Snippet: "<pin-set>"},
			Severity:    models.SeverityInfo,
			Sensitivity: models.SensitivityPublic,
			Confidence:  1.0,
		})
	}

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

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".java" && ext != ".smali" && ext != ".xml" && ext != ".kt" && ext != ".json" && ext != ".properties" && ext != ".cfg" {
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
