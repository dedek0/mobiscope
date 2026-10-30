package analyzers

import (
	"context"
	"encoding/base64"
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

	// maxIPSamples and maxEmailSamples cap the unique sample lists stored in
	// inventory.json. The full occurrence count is kept separately.
	maxIPSamples    = 50
	maxEmailSamples = 50
)

// urlRe matches generic http(s) URLs. The generic URL rule was demoted from
// one finding per URL to an aggregate in inventory.json (it flooded reports).
var urlRe = regexp.MustCompile(`https?://[^\s"'` + "`" + `<>\\)\]}]+`)

// ipRe and emailRe feed aggregate-only inventory counters. They are never
// converted into findings: on a real app they are dominated by resource files
// and third-party SDKs.
var (
	ipRe    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
)

// privateKeyRe matches a complete PEM private-key block. Matching the whole
// block (header + body + footer) avoids the classic false positive where a
// parser such as JSch or Netty ships the header as a string constant.
var privateKeyRe = regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`)

// pinningMarkers are the literals that indicate certificate pinning support.
// They are aggregated into one app-level finding instead of one finding per
// occurrence.
var pinningMarkers = []string{
	"X509TrustManager",
	"CertificatePinner",
	"TrustKit",
	"sha256/",
	"pin-sha256",
	"-----BEGIN CERTIFICATE-----",
}

// URLAggregate is the aggregate of generic URL occurrences found while
// scanning: Count is the total number of matches, URLs a bounded, sorted
// sample of unique normalized values.
type URLAggregate struct {
	Count int
	URLs  []string
}

// ScanAggregate holds the low-signal observations that belong in
// inventory.json rather than in the findings list.
type ScanAggregate struct {
	URLs         URLAggregate
	IPs          []string
	IPCount      int
	Emails       []string
	EmailCount   int
	Pinning      []string
	PinningCount int
}

type Inventory struct {
	agg ScanAggregate
}

func NewInventory() *Inventory { return &Inventory{} }

// Aggregate returns the aggregate collected by the last Run/Analyze call.
func (inv *Inventory) Aggregate() ScanAggregate { return inv.agg }

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
	inv.agg = agg

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
	inv.agg = agg
	return findings
}

// --- Pattern scanning ---

type patternRule struct {
	Name        string
	Category    models.Category
	Severity    models.Severity
	Sensitivity models.Sensitivity
	Re          *regexp.Regexp
	// Description overrides the generic "Pattern match for X" text.
	Description string
	// Redact replaces the matched body in the evidence with a placeholder.
	Redact bool
}

var scanRules = []patternRule{
	{
		Name: "AWS Access Key", Category: models.CategorySecret,
		Severity: models.SeverityCritical, Sensitivity: models.SensitivitySecret,
		Re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	},
	{
		// AIza… keys are client-side identifiers (Maps/Firebase). They are
		// only a secret when API restrictions are missing, so they are
		// reported as informational rather than critical.
		Name: "GCP API Key", Category: models.CategorySecret,
		Severity: models.SeverityInfo, Sensitivity: models.SensitivityPublic,
		Re:          regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
		Description: "Google API key (client-side identifier). Verify that the key is restricted to the expected Android app and APIs; it is usually not a server-side secret.",
	},
	{
		Name: "Google OAuth Client ID", Category: models.CategorySecret,
		Severity: models.SeverityInfo, Sensitivity: models.SensitivityPublic,
		Re:          regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
		Description: "Google OAuth client ID. It identifies the app and is not a client secret.",
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
		Re:     privateKeyRe,
		Redact: true,
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
		// Firebase database URLs are public endpoints; they are only
		// interesting in combination with an open security rule.
		Name: "Firebase URL", Category: models.CategorySecret,
		Severity: models.SeverityInfo, Sensitivity: models.SensitivityPublic,
		Re:          regexp.MustCompile(`https://[a-z0-9\-]+\.firebaseio\.com`),
		Description: "Firebase Realtime Database URL. It is not a secret by itself; confirm that the database rules are not public.",
	},
}

func (inv *Inventory) scanPatterns(dir string, sessionID string) ([]models.Finding, ScanAggregate) {
	var findings []models.Finding
	agg := ScanAggregate{}
	urlSeen := make(map[string]bool, maxURLSamples)
	ipSeen := make(map[string]bool, maxIPSamples)
	emailSeen := make(map[string]bool, maxEmailSamples)
	pinSeen := make(map[string]bool, len(pinningMarkers))
	firstPinFile, firstPinLine := "", 0

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
			agg.URLs.Count++
			u := strings.TrimRight(m, ".,;:!?)]}")
			if !urlSeen[u] && len(urlSeen) < maxURLSamples {
				urlSeen[u] = true
				agg.URLs.URLs = append(agg.URLs.URLs, u)
			}
		}

		// IPs and e-mail addresses are inherently low-signal in resources and
		// third-party SDKs. They feed inventory.json, never the findings list.
		for _, m := range ipRe.FindAllString(content, -1) {
			agg.IPCount++
			if !ipSeen[m] && len(ipSeen) < maxIPSamples {
				ipSeen[m] = true
				agg.IPs = append(agg.IPs, m)
			}
		}
		for _, m := range emailRe.FindAllString(content, -1) {
			agg.EmailCount++
			if !emailSeen[m] && len(emailSeen) < maxEmailSamples {
				emailSeen[m] = true
				agg.Emails = append(agg.Emails, m)
			}
		}

		// Pinning support is an app-level property: collect the markers and
		// emit one informational finding, not one per occurrence.
		for _, marker := range pinningMarkers {
			n := strings.Count(content, marker)
			if n == 0 {
				continue
			}
			agg.PinningCount += n
			if pinSeen[marker] {
				continue
			}
			pinSeen[marker] = true
			agg.Pinning = append(agg.Pinning, marker)
			if firstPinFile == "" {
				firstPinFile = relPath
				firstPinLine = lineOfOffset(content, strings.Index(content, marker))
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

				raw := content[loc[0]:loc[1]]
				if rule.Name == "Private Key Block" && !validPEMBlock(raw) {
					continue
				}
				snippet := raw
				if rule.Redact {
					snippet = redactPEM(raw)
				}
				if len(snippet) > 120 {
					snippet = snippet[:120]
				}
				line := lineCursor

				desc := rule.Description
				if desc == "" {
					desc = fmt.Sprintf("Pattern match for %s in %s", rule.Name, relPath)
				}

				f := models.Finding{
					ID:          models.GenerateID(NameInventory, rule.Category, relPath, line, snippet),
					SessionID:   sessionID,
					SourceTool:  NameInventory,
					Category:    rule.Category,
					Platform:    models.PlatformAndroid,
					Title:       rule.Name,
					Description: desc,
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

	sort.Strings(agg.URLs.URLs)
	sort.Strings(agg.IPs)
	sort.Strings(agg.Emails)
	sort.Strings(agg.Pinning)

	if len(agg.Pinning) > 0 {
		if firstPinFile == "" {
			firstPinFile = "inventory"
		}
		snippet := strings.Join(agg.Pinning, ", ")
		findings = append(findings, models.Finding{
			ID:          models.GenerateID(NameInventory, models.CategoryPinningIndicator, firstPinFile, firstPinLine, snippet),
			SessionID:   sessionID,
			SourceTool:  NameInventory,
			Category:    models.CategoryPinningIndicator,
			Platform:    models.PlatformAndroid,
			Title:       "Certificate pinning indicators detected",
			Description: fmt.Sprintf("The app references pinning-related APIs or certificate material (%s) in %d place(s). Confirm that pinning is enforced on the paths that carry credentials.", snippet, agg.PinningCount),
			Evidence:    snippet,
			Location:    models.Location{File: firstPinFile, Line: firstPinLine, Snippet: snippet},
			Severity:    models.SeverityInfo,
			Sensitivity: models.SensitivityPublic,
			Confidence:  0.85,
		})
	}
	return findings, agg
}

// lineOfOffset returns the 1-based line number of an offset.
func lineOfOffset(content string, off int) int {
	if off < 0 || off > len(content) {
		return 0
	}
	return strings.Count(content[:off], "\n") + 1
}

// validPEMBlock reports whether a matched PEM block carries a plausible
// base64 body. Header-only constants (the JSch/Netty false positive) fail
// this check because they contain no footer.
func validPEMBlock(block string) bool {
	lines := strings.Split(block, "\n")
	if len(lines) < 3 {
		return false
	}
	var body strings.Builder
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-----END ") {
			break
		}
		body.WriteString(line)
	}
	raw := body.String()
	if len(raw) < 64 {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	return err == nil && len(decoded) >= 32
}

// redactPEM replaces the key body so report artifacts and LLM prompts never
// contain private key material.
func redactPEM(block string) string {
	if idx := strings.IndexByte(block, '\n'); idx > 0 {
		return block[:idx] + " [body redacted]"
	}
	return "PRIVATE KEY [body redacted]"
}
