package analyzers

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dedek0/mobiscope/internal/models"
)

// androidManifest is a decoded AndroidManifest.xml.
//
// jadx/apktool emit the standard AXML-decoded XML form. Attributes use the
// android: prefix; Go's encoding/xml does not match namespaced attributes
// via `xml:"ns-uri name"` struct tags, so we match the local name with
// `,attr` which works regardless of the prefix.
type androidManifest struct {
	XMLName xml.Name `xml:"manifest"`
	Package string   `xml:"package,attr"`

	Application     application      `xml:"application"`
	UsesPermissions []usesPermission `xml:"uses-permission"`
	UsesPermSDK23   []usesPermission `xml:"uses-permission-sdk-23"`
	PermissionDecls []permissionDecl `xml:"permission"`
	Queries         queries          `xml:"queries"`
	SharedUserID    string           `xml:"sharedUserId,attr"`
}

// application holds the <application> element's attributes and components.
//
// NOTE on XML tags: Go's encoding/xml does not match namespaced attributes
// via `xml:"ns-uri name"` struct tags. Matching the local name with `,attr`
// works regardless of the android: prefix, which is what we want here.
type application struct {
	Debuggable            string      `xml:"debuggable,attr"`
	AllowBackup           string      `xml:"allowBackup,attr"`
	UsesCleartextTraffic  string      `xml:"usesCleartextTraffic,attr"`
	TestOnly              string      `xml:"testOnly,attr"`
	NetworkSecurityConfig string      `xml:"networkSecurityConfig,attr"`
	FullBackupContent     string      `xml:"fullBackupContent,attr"`
	DataExtractionRules   string      `xml:"dataExtractionRules,attr"`
	ExtractNativeLibs     string      `xml:"extractNativeLibs,attr"`
	Activities            []component `xml:"activity"`
	ActivityAliases       []component `xml:"activity-alias"`
	Services              []component `xml:"service"`
	Receivers             []component `xml:"receiver"`
	Providers             []component `xml:"provider"`
}

type component struct {
	Name          string         `xml:"name,attr"`
	Exported      string         `xml:"exported,attr"`
	Permission    string         `xml:"permission,attr"`
	Process       string         `xml:"process,attr"`
	GrantURI      string         `xml:"grantUriPermissions,attr"`
	Authorities   string         `xml:"authorities,attr"`
	IntentFilters []intentFilter `xml:"intent-filter"`
}

type intentFilter struct {
	Actions    []action   `xml:"action"`
	Categories []category `xml:"category"`
	Data       []dataElem `xml:"data"`
}

type action struct {
	Name string `xml:"name,attr"`
}

type category struct {
	Name string `xml:"name,attr"`
}

type dataElem struct {
	Scheme     string `xml:"scheme,attr"`
	Host       string `xml:"host,attr"`
	Path       string `xml:"path,attr"`
	PathPrefix string `xml:"pathPrefix,attr"`
}

type usesPermission struct {
	Name string `xml:"name,attr"`
}

type permissionDecl struct {
	Name            string `xml:"name,attr"`
	ProtectionLevel string `xml:"protectionLevel,attr"`
}

type queries struct {
	Packages []struct {
		Name string `xml:"name,attr"`
	} `xml:"package"`
	Intent []intentFilter `xml:"intent"`
}

// parsedComponent flattens a component element with its kind.
type parsedComponent struct {
	Kind          string
	Name          string
	Exported      bool
	Protected     bool
	Process       string
	GrantURI      bool
	Auth          string
	IntentFilters []parsedIntentFilter
}

type parsedIntentFilter struct {
	Actions []string
	Schemes []string
	Hosts   []string
}

// decodeManifest parses AndroidManifest.xml.
func decodeManifest(data []byte) (*androidManifest, error) {
	var m androidManifest
	if err := xml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("decoding manifest: %w", err)
	}
	return &m, nil
}

// components returns every component with its kind and attributes resolved.
func (m *androidManifest) components() []parsedComponent {
	var out []parsedComponent
	add := func(kind string, c component) {
		filters := make([]parsedIntentFilter, 0, len(c.IntentFilters))
		for _, f := range c.IntentFilters {
			pf := parsedIntentFilter{}
			for _, a := range f.Actions {
				if a.Name != "" {
					pf.Actions = append(pf.Actions, a.Name)
				}
			}
			for _, d := range f.Data {
				if d.Scheme != "" {
					pf.Schemes = append(pf.Schemes, d.Scheme)
				}
				if d.Host != "" {
					pf.Hosts = append(pf.Hosts, d.Host)
				}
			}
			if len(pf.Actions) > 0 || len(pf.Schemes) > 0 {
				filters = append(filters, pf)
			}
		}
		out = append(out, parsedComponent{
			Kind:          kind,
			Name:          c.Name,
			Exported:      strings.EqualFold(c.Exported, "true"),
			Protected:     c.Permission != "",
			Process:       c.Process,
			GrantURI:      strings.EqualFold(c.GrantURI, "true"),
			Auth:          c.Authorities,
			IntentFilters: filters,
		})
	}
	for _, c := range m.Application.Activities {
		add("activity", c)
	}
	for _, c := range m.Application.ActivityAliases {
		add("activity-alias", c)
	}
	for _, c := range m.Application.Services {
		add("service", c)
	}
	for _, c := range m.Application.Receivers {
		add("receiver", c)
	}
	for _, c := range m.Application.Providers {
		add("provider", c)
	}
	return out
}

// permissions returns all requested permission names.
func (m *androidManifest) permissions() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range append(append([]usesPermission{}, m.UsesPermissions...), m.UsesPermSDK23...) {
		if p.Name == "" || seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		out = append(out, p.Name)
	}
	return out
}

// dangerousPermSuffixes are the permission-name suffixes considered dangerous.
// Matched against the final segment after the last dot so a custom
// com.foo.MANAGE_CAMERA does not false-positive on CAMERA.
var dangerousPermSuffixes = map[string]bool{
	"READ_CALENDAR": true, "WRITE_CALENDAR": true, "CAMERA": true,
	"READ_CONTACTS": true, "WRITE_CONTACTS": true, "GET_ACCOUNTS": true,
	"ACCESS_FINE_LOCATION": true, "ACCESS_COARSE_LOCATION": true,
	"ACCESS_BACKGROUND_LOCATION": true,
	"RECORD_AUDIO":               true, "READ_PHONE_STATE": true, "READ_PHONE_NUMBERS": true,
	"CALL_PHONE": true, "ANSWER_PHONE_CALLS": true, "READ_CALL_LOG": true,
	"WRITE_CALL_LOG": true, "ADD_VOICEMAIL": true, "USE_SIP": true,
	"BODY_SENSORS": true, "BODY_SENSORS_BACKGROUND": true,
	"SEND_SMS": true, "RECEIVE_SMS": true, "READ_SMS": true,
	"RECEIVE_WAP_PUSH": true, "RECEIVE_MMS": true,
	"READ_EXTERNAL_STORAGE": true, "WRITE_EXTERNAL_STORAGE": true,
	"READ_MEDIA_IMAGES": true, "READ_MEDIA_VIDEO": true, "READ_MEDIA_AUDIO": true,
	"READ_MEDIA_VISUAL_USER_SELECTED": true,
	"POST_NOTIFICATIONS":              true,
	"BLUETOOTH_CONNECT":               true, "BLUETOOTH_SCAN": true, "BLUETOOTH_ADVERTISE": true,
	"NEARBY_WIFI_DEVICES": true,
}

// isDangerousPermission reports whether perm is a known dangerous permission,
// matched on its final name segment.
func isDangerousPermission(perm string) bool {
	seg := perm
	if i := strings.LastIndexByte(perm, '.'); i >= 0 {
		seg = perm[i+1:]
	}
	return dangerousPermSuffixes[seg]
}

// analyzeManifest inspects AndroidManifest.xml via real XML decoding so
// attribute order, comments and namespaced declarations are handled correctly.
func (inv *Inventory) analyzeManifest(dir, sessionID string) []models.Finding {
	manifestPath := filepath.Join(dir, AndroidManifestFile)
	data, err := os.ReadFile(manifestPath) //nolint:gosec
	if err != nil {
		return nil
	}

	m, err := decodeManifest(data)
	if err != nil {
		// Fall back to the legacy regex pass if the manifest is not XML.
		return inv.analyzeManifestLegacy(string(data), sessionID)
	}

	var findings []models.Finding
	app := m.Application

	if strings.EqualFold(app.Debuggable, "true") {
		findings = append(findings, manifestFinding(sessionID,
			"Application is debuggable",
			"android:debuggable=true allows debugging and inspection of the app.",
			"android:debuggable=\"true\"",
			models.SeverityHigh, models.SensitivityConfidential, 1.0))
	}
	if strings.EqualFold(app.TestOnly, "true") {
		findings = append(findings, manifestFinding(sessionID,
			"Application is test-only",
			"android:testOnly=true marks the app as not intended for release; it can be granted extra privileges.",
			"android:testOnly=\"true\"",
			models.SeverityMedium, models.SensitivityInternal, 0.9))
	}
	if strings.EqualFold(app.AllowBackup, "true") {
		findings = append(findings, manifestFinding(sessionID,
			"ADB backup allowed",
			"android:allowBackup=true lets `adb backup` extract app data on debuggable or older devices.",
			"android:allowBackup=\"true\"",
			models.SeverityMedium, models.SensitivityConfidential, 0.8))
	}
	if strings.EqualFold(app.UsesCleartextTraffic, "true") {
		findings = append(findings, manifestFinding(sessionID,
			"Cleartext traffic permitted (manifest)",
			"android:usesCleartextTraffic=true allows unencrypted HTTP to any host.",
			"android:usesCleartextTraffic=\"true\"",
			models.SeverityHigh, models.SensitivityConfidential, 1.0))
	}

	for _, comp := range m.components() {
		if comp.Kind == "provider" && comp.GrantURI {
			findings = append(findings, manifestFinding(sessionID,
				fmt.Sprintf("Content provider grants URI permissions: %s", comp.Name),
				"android:grantUriPermissions=true can expose provider data to other apps.",
				comp.Name+" grantUriPermissions=\"true\"",
				models.SeverityHigh, models.SensitivityConfidential, 0.9))
		}
		if !comp.Exported {
			continue
		}
		severity := models.SeverityMedium
		sensitivity := models.SensitivityInternal
		if comp.Kind == "provider" {
			severity = models.SeverityHigh
			sensitivity = models.SensitivityConfidential
		}
		if !comp.Protected && len(comp.IntentFilters) > 0 {
			// Exported, unprotected, and reachable via an intent-filter
			// (deeplink/IPC hijack risk).
			severity = models.SeverityHigh
		}
		title := fmt.Sprintf("Exported %s: %s", comp.Kind, comp.Name)
		desc := fmt.Sprintf("%s with android:exported=true can be invoked by other applications.", comp.Kind)
		if !comp.Protected {
			desc += " No android:permission guard is set."
		}
		findings = append(findings, manifestFinding(sessionID,
			title, desc,
			comp.Name+" exported=\"true\"",
			severity, sensitivity, 0.9))
	}

	for _, perm := range m.permissions() {
		if isDangerousPermission(perm) {
			findings = append(findings, manifestFinding(sessionID,
				fmt.Sprintf("Dangerous permission: %s", perm),
				fmt.Sprintf("The app requests dangerous permission %s.", perm),
				perm,
				models.SeverityMedium, models.SensitivityInternal, 0.8))
		}
	}

	// Custom permission declarations with a weak protection level.
	for _, pd := range m.PermissionDecls {
		lvl := strings.ToLower(pd.ProtectionLevel)
		if strings.Contains(lvl, "dangerous") || strings.Contains(lvl, "signature|privileged") {
			continue
		}
		if lvl == "normal" || lvl == "" {
			findings = append(findings, manifestFinding(sessionID,
				fmt.Sprintf("Custom permission with weak protection: %s", pd.Name),
				"Custom permissions declared at protectionLevel=normal are grantable by any app.",
				pd.Name+" protectionLevel=\""+pd.ProtectionLevel+"\"",
				models.SeverityMedium, models.SensitivityInternal, 0.7))
		}
	}

	return findings
}

func manifestFinding(sessionID, title, desc, snippet string, sev models.Severity, sens models.Sensitivity, conf float64) models.Finding {
	return models.Finding{
		ID:          models.GenerateID(NameInventory, models.CategoryManifestIssue, AndroidManifestFile, 1, snippet),
		SessionID:   sessionID,
		SourceTool:  NameInventory,
		Category:    models.CategoryManifestIssue,
		Platform:    models.PlatformAndroid,
		Title:       title,
		Description: desc,
		Evidence:    snippet,
		Location:    models.Location{File: AndroidManifestFile, Line: 1, Snippet: snippet},
		Severity:    sev,
		Sensitivity: sens,
		Confidence:  conf,
	}
}

// nscResourceName extracts the @xml/… reference from the manifest's
// android:networkSecurityConfig attribute. Returns "" when absent.
func nscResourceName(m *androidManifest) string {
	if m == nil {
		return ""
	}
	ref := strings.TrimSpace(m.Application.NetworkSecurityConfig)
	ref = strings.TrimPrefix(ref, "@xml/")
	ref = strings.TrimPrefix(ref, "@*xml/")
	if ref == "" || strings.ContainsAny(ref, "/\\") {
		return ""
	}
	return ref
}

// resolveNSCPath returns the filesystem path of the network security config,
// following android:networkSecurityConfig when set.
func resolveNSCPath(dir string, m *androidManifest) (string, string) {
	if name := nscResourceName(m); name != "" {
		rel := filepath.Join("res", "xml", name+".xml")
		abs := filepath.Join(dir, "res", "xml", name+".xml")
		if fileExists(abs) {
			return abs, rel
		}
	}
	abs := filepath.Join(dir, "res", "xml", "network_security_config.xml")
	if fileExists(abs) {
		return abs, NetworkSecurityConfigFile
	}
	return "", ""
}

// analyzeNetworkSecurityConfig inspects the app's network security config,
// resolving the file from the manifest when it is not at the default path.
//
// Only genuine relaxations are reported: a stock <trust-anchors> block that
// merely lists src="system" is NOT a finding.
func (inv *Inventory) analyzeNetworkSecurityConfig(dir, sessionID string) []models.Finding {
	data, err := os.ReadFile(filepath.Join(dir, AndroidManifestFile)) //nolint:gosec
	var m *androidManifest
	if err == nil {
		m, _ = decodeManifest(data)
	}

	nscAbs, nscRel := resolveNSCPath(dir, m)
	if nscAbs == "" {
		return nil
	}

	raw, err := os.ReadFile(nscAbs) //nolint:gosec
	if err != nil {
		return nil
	}
	content := string(raw)

	var findings []models.Finding

	if strings.Contains(content, `cleartextTrafficPermitted="true"`) {
		findings = append(findings, nscFinding(sessionID, nscRel,
			"Cleartext traffic permitted",
			"The network security config allows cleartext (HTTP) traffic.",
			`cleartextTrafficPermitted="true"`,
			models.CategoryNetworkConfig, models.SeverityHigh, models.SensitivityConfidential, 1.0))
	}

	// Only flag custom trust anchors (src="user" or src="@"); a stock
	// <trust-anchors><certificates src="system"/></trust-anchors> is fine.
	if hasCustomTrustAnchor(content) {
		findings = append(findings, nscFinding(sessionID, nscRel,
			"Custom trust anchors configured",
			"Custom trust anchors (src=\"user\" or src=\"@\") may weaken TLS validation if misconfigured.",
			"trust-anchors src=\"user\"",
			models.CategoryNetworkConfig, models.SeverityMedium, models.SensitivityInternal, 0.8))
	}

	if strings.Contains(content, "overridePins=\"true\"") {
		findings = append(findings, nscFinding(sessionID, nscRel,
			"Certificate pinning override enabled",
			"overridePins=\"true\" disables pin enforcement (typically debug builds); never ship it enabled.",
			`overridePins="true"`,
			models.CategoryNetworkConfig, models.SeverityHigh, models.SensitivityConfidential, 0.9))
	}

	if strings.Contains(content, "<pin-set") {
		findings = append(findings, nscFinding(sessionID, nscRel,
			"Certificate pinning configured (XML)",
			"The app uses network_security_config pin-set for certificate pinning.",
			"<pin-set>",
			models.CategoryPinningIndicator, models.SeverityInfo, models.SensitivityPublic, 1.0))
	}

	return findings
}

func nscFinding(sessionID, file, title, desc, snippet string, cat models.Category, sev models.Severity, sens models.Sensitivity, conf float64) models.Finding {
	return models.Finding{
		ID:          models.GenerateID(NameInventory, cat, file, 1, snippet),
		SessionID:   sessionID,
		SourceTool:  NameInventory,
		Category:    cat,
		Platform:    models.PlatformAndroid,
		Title:       title,
		Description: desc,
		Evidence:    snippet,
		Location:    models.Location{File: file, Line: 1, Snippet: snippet},
		Severity:    sev,
		Sensitivity: sens,
		Confidence:  conf,
	}
}

// hasCustomTrustAnchor reports whether any trust-anchor block lists a
// non-system certificate source.
func hasCustomTrustAnchor(content string) bool {
	if !strings.Contains(content, "trust-anchors") && !strings.Contains(content, "certificates") {
		return false
	}
	for _, src := range []string{`src="user"`, `src="*"`} {
		if strings.Contains(content, src) {
			return true
		}
	}
	// src="@raw/ca", src="@my_ca", …
	if strings.Contains(content, `src="@`) {
		return true
	}
	return false
}

// fileExists reports whether path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// analyzeManifestLegacy is the regex fallback for non-XML manifests.
func (inv *Inventory) analyzeManifestLegacy(content, sessionID string) []models.Finding {
	var findings []models.Finding

	if strings.Contains(content, `android:debuggable="true"`) {
		findings = append(findings, manifestFinding(sessionID,
			"Application is debuggable",
			"android:debuggable=true allows debugging and inspection of the app.",
			`android:debuggable="true"`,
			models.SeverityHigh, models.SensitivityConfidential, 0.9))
	}
	if strings.Contains(content, `android:allowBackup="true"`) {
		findings = append(findings, manifestFinding(sessionID,
			"ADB backup allowed",
			"android:allowBackup=true lets `adb backup` extract app data.",
			`android:allowBackup="true"`,
			models.SeverityMedium, models.SensitivityConfidential, 0.7))
	}
	for _, perm := range legacyPermissionRe(content) {
		if isDangerousPermission(perm) {
			findings = append(findings, manifestFinding(sessionID,
				fmt.Sprintf("Dangerous permission: %s", perm),
				fmt.Sprintf("The app requests dangerous permission %s.", perm),
				perm,
				models.SeverityMedium, models.SensitivityInternal, 0.7))
		}
	}
	return findings
}

// legacyPermissionRe extracts android:name values from uses-permission tags
// regardless of attribute order.
func legacyPermissionRe(content string) []string {
	var out []string
	for _, tag := range []string{"uses-permission", "uses-permission-sdk-23"} {
		for _, chunk := range strings.Split(content, "<"+tag) {
			if idx := strings.Index(chunk, ">"); idx >= 0 {
				chunk = chunk[:idx]
			}
			if i := strings.Index(chunk, `android:name="`); i >= 0 {
				rest := chunk[i+len(`android:name="`):]
				if j := strings.IndexByte(rest, '"'); j >= 0 {
					out = append(out, rest[:j])
				}
			}
		}
	}
	return out
}
