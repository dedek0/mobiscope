package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
	"howett.net/plist"
)

const (
	plistName = "plist"
)

// PlistAnalyzer decodes Info.plist and reports ATS, privacy and URL-scheme
// issues. Parsed in-process with howett.net/plist (handles binary and XML).
type PlistAnalyzer struct{}

func NewPlistAnalyzer() *PlistAnalyzer { return &PlistAnalyzer{} }

func (p *PlistAnalyzer) Name() string     { return plistName }
func (p *PlistAnalyzer) Available() error { return nil }

func (p *PlistAnalyzer) Run(_ context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  p.Name(),
		Version:   toolVersion,
		StartedAt: start,
	}

	bundle := appBundleDir(workdir)
	if bundle == "" {
		result.Duration = time.Since(start)
		return result, fmt.Errorf("app bundle not found under %s", IPAExtractArtifactPath(workdir))
	}

	infoPath := filepath.Join(bundle, "Info.plist")
	info, err := readPlist(infoPath)
	if err != nil {
		result.Duration = time.Since(start)
		result.Error = err.Error()
		return result, fmt.Errorf("reading Info.plist: %w", err)
	}

	ats := map[string]interface{}{}
	if v, ok := info["NSAppTransportSecurity"].(map[string]interface{}); ok {
		ats = v
	}

	schemes := []string{}
	if types, ok := info["CFBundleURLTypes"].([]interface{}); ok {
		for _, t := range types {
			if m, ok := t.(map[string]interface{}); ok {
				if list, ok := m["CFBundleURLSchemes"].([]interface{}); ok {
					for _, s := range list {
						if str, ok := s.(string); ok {
							schemes = append(schemes, str)
						}
					}
				}
			}
		}
	}

	raw, _ := json.Marshal(map[string]interface{}{
		"bundle_id":      strOr(info["CFBundleIdentifier"]),
		"version":        strOr(info["CFBundleShortVersionString"]),
		"build":          strOr(info["CFBundleVersion"]),
		"min_os":         strOr(info["MinimumOSVersion"]),
		"executable":     strOr(info["CFBundleExecutable"]),
		"url_schemes":    schemes,
		"ats":            ats,
		"file_sharing":   boolOr(info["UIFileSharingEnabled"]),
		"docs_in_place":  boolOr(info["LSSupportsOpeningDocumentsInPlace"]),
		"usage_required": usageDescriptionKeys(info),
	})
	result.Output = raw
	result.Duration = time.Since(start)
	return result, nil
}

// plistOutput is the JSON shape written by PlistAnalyzer.Run.
type plistOutput struct {
	BundleID      string                 `json:"bundle_id"`
	Version       string                 `json:"version"`
	Build         string                 `json:"build"`
	MinOS         string                 `json:"min_os"`
	URLSchemes    []string               `json:"url_schemes"`
	ATS           map[string]interface{} `json:"ats"`
	FileSharing   bool                   `json:"file_sharing"`
	DocsInPlace   bool                   `json:"docs_in_place"`
	UsageRequired []string               `json:"usage_required"`
}

// ConvertPlistFindings turns ATS/privacy observations into findings.
func ConvertPlistFindings(raw []byte, sessionID string) []models.Finding {
	var out plistOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}

	var findings []models.Finding
	const file = "Info.plist"

	add := func(title, desc, snippet string, cat models.Category, sev models.Severity, sens models.Sensitivity, conf float64) {
		f := iosFinding(plistName, cat, file, snippet, title, desc, sev, sens, conf)
		findings = append(findings, withSession(f, sessionID))
	}

	if boolOr(out.ATS["NSAllowsArbitraryLoads"]) {
		add("ATS: arbitrary loads allowed",
			"NSAppTransportSecurity.NSAllowsArbitraryLoads=true disables ATS entirely; any cleartext or weak-TLS connection is permitted.",
			"NSAllowsArbitraryLoads=true",
			models.CategoryNetworkConfig, models.SeverityHigh, models.SensitivityConfidential, 1.0)
	}
	for _, key := range []string{"NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsInMediaStreaming"} {
		if boolOr(out.ATS[key]) {
			add("ATS: arbitrary loads in "+key,
				fmt.Sprintf("%s=true weakens ATS for that subsystem.", key),
				key+"=true",
				models.CategoryNetworkConfig, models.SeverityMedium, models.SensitivityConfidential, 0.9)
		}
	}
	if boolOr(out.ATS["NSAllowsLocalNetworking"]) {
		add("ATS: local networking allowed",
			"NSAllowsLocalNetworking=true permits cleartext to local hosts; usually fine for dev, risky if shipped.",
			"NSAllowsLocalNetworking=true",
			models.CategoryNetworkConfig, models.SeverityLow, models.SensitivityInternal, 0.7)
	}

	// Domain-scoped exceptions.
	if domains, ok := out.ATS["NSExceptionDomains"].(map[string]interface{}); ok {
		for domain, raw := range domains {
			m, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			insecure := boolOr(m["NSExceptionAllowsInsecureHTTPLoads"]) ||
				boolOr(m["NSTemporaryExceptionAllowsInsecureHTTPLoads"])
			if insecure {
				add("ATS exception allows insecure HTTP: "+domain,
					fmt.Sprintf("Domain %q is exempted from ATS and permits insecure HTTP loads.", domain),
					domain+" NSExceptionAllowsInsecureHTTPLoads=true",
					models.CategoryNetworkConfig, models.SeverityHigh, models.SensitivityConfidential, 0.95)
			}
		}
	}

	if out.FileSharing || out.DocsInPlace {
		add("iTunes file sharing enabled",
			"UIFileSharingEnabled/LSSupportsOpeningDocumentsInPlace exposes the app's Documents directory to the Files app and other users of the device.",
			fmt.Sprintf("UIFileSharingEnabled=%v LSSupportsOpeningDocumentsInPlace=%v", out.FileSharing, out.DocsInPlace),
			models.CategoryPrivacy, models.SeverityMedium, models.SensitivityConfidential, 0.8)
	}

	for _, scheme := range out.URLSchemes {
		if strings.EqualFold(scheme, "http") || strings.EqualFold(scheme, "https") ||
			strings.EqualFold(scheme, "file") || strings.EqualFold(scheme, "javascript") {
			add("Dangerous custom URL scheme: "+scheme,
				fmt.Sprintf("Registering %q as a custom URL scheme can hijack system navigation.", scheme),
				"CFBundleURLSchemes "+scheme,
				models.CategoryManifestIssue, models.SeverityHigh, models.SensitivityConfidential, 0.9)
		}
	}

	return findings
}

func readPlist(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, err
	}
	var v interface{}
	if _, err := plist.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("decoding plist: %w", err)
	}
	m, ok := v.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("plist root is not a dictionary")
	}
	return m, nil
}

func strOr(v interface{}) string {
	s, _ := v.(string)
	return s
}

func boolOr(v interface{}) bool {
	b, _ := v.(bool)
	return b
}

func usageDescriptionKeys(info map[string]interface{}) []string {
	var keys []string
	for k := range info {
		if strings.HasSuffix(k, "UsageDescription") {
			keys = append(keys, k)
		}
	}
	return keys
}
