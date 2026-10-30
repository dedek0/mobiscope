package analyzers

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

	VersionName  string `xml:"versionName,attr"`
	VersionCode  string `xml:"versionCode,attr"`
	SharedUserID string `xml:"sharedUserId,attr"`

	UsesSDK         usesSDK          `xml:"uses-sdk"`
	Application     application      `xml:"application"`
	UsesPermissions []usesPermission `xml:"uses-permission"`
	UsesPermSDK23   []usesPermission `xml:"uses-permission-sdk-23"`
	PermissionDecls []permissionDecl `xml:"permission"`
	Queries         queries          `xml:"queries"`
}

// usesSDK carries the API-level range declared by <uses-sdk>.
type usesSDK struct {
	MinSDKVersion    string `xml:"minSdkVersion,attr"`
	TargetSDKVersion string `xml:"targetSdkVersion,attr"`
	MaxSDKVersion    string `xml:"maxSdkVersion,attr"`
}

// targetSDK returns the manifest's targetSdkVersion as an integer, or 0 when
// it is absent or not numeric.
func (m *androidManifest) targetSDK() int {
	if m == nil {
		return 0
	}
	return atoiSafe(strings.TrimSpace(m.UsesSDK.TargetSDKVersion))
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
	Permission            string      `xml:"permission,attr"`
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
	TaskAffinity  string         `xml:"taskAffinity,attr"`
	ReadPerm      string         `xml:"readPermission,attr"`
	WritePerm     string         `xml:"writePermission,attr"`
	Enabled       string         `xml:"enabled,attr"`
	DirectBoot    string         `xml:"directBootAware,attr"`
	Priority      string         `xml:"priority,attr"`
	AllowBackup   string         `xml:"allowBackup,attr"`
	Multiprocess  string         `xml:"multiprocess,attr"`
	LaunchMode    string         `xml:"launchMode,attr"`
	TaskReparent  string         `xml:"allowTaskReparenting,attr"`
	IntentFilters []intentFilter `xml:"intent-filter"`
	// GrantURIChildren is set by a <grant-uri-permission> child element,
	// which is equivalent to android:grantUriPermissions="true".
	GrantURIChildren []struct{} `xml:"grant-uri-permission"`
}

type intentFilter struct {
	Actions    []action   `xml:"action"`
	Categories []category `xml:"category"`
	Data       []dataElem `xml:"data"`
	AutoVerify string     `xml:"autoVerify,attr"`
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
	Kind     string
	Name     string
	Exported bool
	// ExportedExplicit records whether android:exported was present. A
	// component with an intent-filter and no explicit attribute is
	// implicitly exported on API levels below 31.
	ExportedExplicit bool
	Protected        bool
	Process          string
	GrantURI         bool
	Auth             string
	TaskAffinity     string
	ReadPerm         string
	WritePerm        string
	Enabled          bool
	DirectBoot       bool
	Priority         int
	AllowBackup      bool
	LaunchMode       string
	TaskReparent     bool
	IntentFilters    []parsedIntentFilter
}

type parsedIntentFilter struct {
	Actions    []string
	Categories []string
	Schemes    []string
	Hosts      []string
	AutoVerify bool
}

// browsable reports whether the filter is reachable from a browser (the
// android.intent.category.BROWSABLE category).
func (f parsedIntentFilter) browsable() bool {
	for _, c := range f.Categories {
		if c == "android.intent.category.BROWSABLE" {
			return true
		}
	}
	return false
}

// hasAction reports whether the filter declares the given action.
func (f parsedIntentFilter) hasAction(name string) bool {
	for _, a := range f.Actions {
		if a == name {
			return true
		}
	}
	return false
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
			for _, c := range f.Categories {
				if c.Name != "" {
					pf.Categories = append(pf.Categories, c.Name)
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
			pf.AutoVerify = strings.EqualFold(f.AutoVerify, "true")
			if len(pf.Actions) > 0 || len(pf.Schemes) > 0 {
				filters = append(filters, pf)
			}
		}
		out = append(out, parsedComponent{
			Kind:             kind,
			Name:             c.Name,
			Exported:         strings.EqualFold(c.Exported, "true"),
			ExportedExplicit: c.Exported != "",
			Protected:        c.Permission != "",
			Process:          c.Process,
			GrantURI:         strings.EqualFold(c.GrantURI, "true") || len(c.GrantURIChildren) > 0,
			Auth:             c.Authorities,
			TaskAffinity:     c.TaskAffinity,
			ReadPerm:         c.ReadPerm,
			WritePerm:        c.WritePerm,
			Enabled:          !strings.EqualFold(c.Enabled, "false"),
			DirectBoot:       strings.EqualFold(c.DirectBoot, "true"),
			Priority:         atoiSafe(strings.TrimSpace(c.Priority)),
			AllowBackup:      !strings.EqualFold(c.AllowBackup, "false"),
			LaunchMode:       c.LaunchMode,
			TaskReparent:     strings.EqualFold(c.TaskReparent, "true"),
			IntentFilters:    filters,
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
		add(componentKindProvider, c)
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
	data, err := readFileCapped(manifestPath, maxManifestBytes)
	if err != nil {
		return nil
	}

	m, err := decodeManifest(data)
	if err != nil {
		// Fall back to the legacy regex pass if the manifest is not XML.
		return inv.analyzeManifestLegacy(string(data), sessionID)
	}

	return inv.manifestFindings(m, sessionID)
}

// manifestFindings applies the manifest checks to an already decoded manifest.
// It is shared by the decoded-XML path and the in-process AXML path.
func (inv *Inventory) manifestFindings(m *androidManifest, sessionID string) []models.Finding {
	var findings []models.Finding
	if m == nil {
		return findings
	}
	app := m.Application
	targetSDK := m.targetSDK()

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
	// Before targetSdk 28 the platform permits cleartext by default when the
	// app neither sets the flag nor ships a network security config.
	if app.UsesCleartextTraffic == "" && app.NetworkSecurityConfig == "" && targetSDK > 0 && targetSDK < 28 {
		findings = append(findings, manifestFinding(sessionID,
			"Cleartext traffic permitted by targetSdk default",
			fmt.Sprintf("targetSdkVersion=%d predates the API 28 cleartext default, so HTTP is allowed unless a network security config narrows it.", targetSDK),
			fmt.Sprintf("targetSdkVersion=%d (usesCleartextTraffic not set)", targetSDK),
			models.SeverityMedium, models.SensitivityInternal, 0.7))
	}

	for _, comp := range m.components() {
		if comp.Kind == componentKindProvider && comp.GrantURI {
			findings = append(findings, manifestFinding(sessionID,
				fmt.Sprintf("Content provider grants URI permissions: %s", comp.Name),
				"android:grantUriPermissions=true can expose provider data to other apps.",
				comp.Name+" grantUriPermissions=\"true\"",
				models.SeverityHigh, models.SensitivityConfidential, 0.9))
		}
		if comp.Kind == componentKindProvider && comp.Exported && comp.ReadPerm == "" && comp.WritePerm == "" {
			findings = append(findings, manifestFinding(sessionID,
				fmt.Sprintf("Exported provider without read/write permission: %s", comp.Name),
				"The provider is exported and declares neither android:readPermission nor android:writePermission, so any app can read from it.",
				comp.Name+" exported=\"true\" (no readPermission/writePermission)",
				models.SeverityHigh, models.SensitivityConfidential, 0.85))
		}

		// A component with an intent-filter and no explicit android:exported
		// is implicitly exported on API levels below 31. From API 31 on the
		// platform rejects such a manifest at install time, so reporting it
		// as an exported surface would be a false positive.
		implicitlyExported := !comp.ExportedExplicit && len(comp.IntentFilters) > 0 &&
			(targetSDK == 0 || targetSDK < 31)
		// <provider> has its own default: exported on API 16 and below,
		// private from API 17 on, regardless of intent filters.
		if !comp.ExportedExplicit && comp.Kind == componentKindProvider && targetSDK > 0 && targetSDK <= 16 {
			implicitlyExported = true
		}
		if implicitlyExported && !comp.Protected {
			findings = append(findings, manifestFinding(sessionID,
				fmt.Sprintf("Implicitly exported %s: %s", comp.Kind, comp.Name),
				"The component declares an intent-filter but no android:exported attribute. On API levels below 31 it is exported by default, and it has no permission guard.",
				comp.Name+" implicit export (intent-filter, no android:exported)",
				models.SeverityHigh, models.SensitivityInternal, 0.8))
		}

		// A custom URI scheme on an exported activity can be hijacked by a
		// malicious app that registers the same scheme.
		for _, filter := range comp.IntentFilters {
			for _, scheme := range filter.Schemes {
				if scheme == "http" || scheme == "https" {
					continue
				}
				if comp.Exported || implicitlyExported {
					findings = append(findings, manifestFinding(sessionID,
						fmt.Sprintf("Custom URI scheme %q is reachable from other apps: %s", scheme, comp.Name),
						"Any app can register the same custom scheme and intercept the deep links, or receive the data they carry.",
						comp.Name+" custom scheme=\""+scheme+"\"",
						models.SeverityMedium, models.SensitivityInternal, 0.7))
				}
			}
		}

		// App Links: a https VIEW filter that is browsable but does not set
		// android:autoVerify lets any app claim the same host.
		if comp.Exported || implicitlyExported {
			for _, filter := range comp.IntentFilters {
				if !filter.hasAction("android.intent.action.VIEW") || !filter.browsable() {
					continue
				}
				for _, host := range filter.Hosts {
					if host == "" || host == "*" {
						continue
					}
					hasHTTPS := false
					for _, scheme := range filter.Schemes {
						if scheme == "https" {
							hasHTTPS = true
						}
					}
					if !hasHTTPS || filter.AutoVerify {
						continue
					}
					findings = append(findings, manifestFinding(sessionID,
						fmt.Sprintf("App Link without autoVerify: %s", host),
						fmt.Sprintf("%s handles https://%s but does not set android:autoVerify=\"true\", so any app can register the same host and receive the links.", comp.Name, host),
						comp.Name+" autoVerify missing for "+host,
						models.SeverityMedium, models.SensitivityInternal, 0.75))
				}
			}
		}

		// Task hijacking: a singleTask/singleInstance activity whose task can
		// be adopted by another app lets an attacker show their activity in
		// this app's task.
		if comp.Kind == "activity" && (comp.LaunchMode == "singleTask" || comp.LaunchMode == "singleInstance") {
			sameAffinity := comp.TaskAffinity == "" || (m.Package != "" && comp.TaskAffinity == m.Package)
			if sameAffinity || comp.TaskReparent {
				findings = append(findings, manifestFinding(sessionID,
					fmt.Sprintf("Task hijacking surface: %s", comp.Name),
					fmt.Sprintf("The activity uses launchMode=%s and %s, which lets a malicious app place its activity in this app's task.", comp.LaunchMode, taskAffinityReason(comp)),
					comp.Name+" launchMode=\""+comp.LaunchMode+"\"",
					models.SeverityMedium, models.SensitivityInternal, 0.7))
			}
		}

		// A receiver registered for a sensitive broadcast with a high
		// priority can preempt other receivers.
		if comp.Kind == "receiver" && comp.Priority >= 500 {
			findings = append(findings, manifestFinding(sessionID,
				fmt.Sprintf("High-priority broadcast receiver: %s", comp.Name),
				fmt.Sprintf("The receiver declares android:priority=%d, which lets it receive a broadcast before other apps.", comp.Priority),
				comp.Name+" android:priority=\""+strconv.Itoa(comp.Priority)+"\"",
				models.SeverityLow, models.SensitivityInternal, 0.6))
		}

		// A task affinity equal to the package name lets another app with
		// the same affinity reuse this app's task.
		if comp.TaskAffinity != "" && m.Package != "" && comp.TaskAffinity == m.Package {
			findings = append(findings, manifestFinding(sessionID,
				fmt.Sprintf("Task affinity equal to the package name: %s", comp.Name),
				"android:taskAffinity matches the package name, so another app signed with the same key (or with the same affinity) can reuse this task and appear as this app.",
				comp.Name+" android:taskAffinity=\""+comp.TaskAffinity+"\"",
				models.SeverityLow, models.SensitivityInternal, 0.6))
		}

		if !comp.Exported {
			continue
		}
		severity := models.SeverityMedium
		sensitivity := models.SensitivityInternal
		if comp.Kind == componentKindProvider {
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

	// Backup exposure beyond the allowBackup flag: the newer
	// dataExtractionRules and the legacy fullBackupContent decide which
	// domains are copied.
	if app.DataExtractionRules != "" {
		findings = append(findings, manifestFinding(sessionID,
			"Cloud backup rules are declared",
			"android:dataExtractionRules is set, so the app defines what is copied to the cloud. Review the rules to make sure credentials and tokens are excluded.",
			"android:dataExtractionRules=\""+app.DataExtractionRules+"\"",
			models.SeverityInfo, models.SensitivityInternal, 0.7))
	}
	if app.FullBackupContent != "" {
		findings = append(findings, manifestFinding(sessionID,
			"Backup content rules are declared",
			"android:fullBackupContent is set, so the app defines what `adb backup` copies. Review the rules to make sure credentials and tokens are excluded.",
			"android:fullBackupContent=\""+app.FullBackupContent+"\"",
			models.SeverityInfo, models.SensitivityInternal, 0.7))
	}
	if m.SharedUserID != "" {
		findings = append(findings, manifestFinding(sessionID,
			"Application shares a user ID",
			fmt.Sprintf("android:sharedUserId=%q makes the app share its UID with every other app signed with the same key, which widens the blast radius of a compromise.", m.SharedUserID),
			"android:sharedUserId=\""+m.SharedUserID+"\"",
			models.SeverityMedium, models.SensitivityInternal, 0.8))
	}
	if strings.EqualFold(app.ExtractNativeLibs, "true") {
		findings = append(findings, manifestFinding(sessionID,
			"Native libraries are extracted to disk",
			"android:extractNativeLibs=true extracts the .so files to the app's data directory, where they can be replaced by anything with write access to that directory.",
			"android:extractNativeLibs=\"true\"",
			models.SeverityLow, models.SensitivityInternal, 0.7))
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

// taskAffinityReason describes the affinity property that makes a task
// hijacking finding applicable.
func taskAffinityReason(c parsedComponent) string {
	if c.TaskReparent {
		return "allowTaskReparenting=\"true\""
	}
	if c.TaskAffinity == "" {
		return "an empty taskAffinity (the package default)"
	}
	return "a taskAffinity equal to the package name"
}

func manifestFinding(sessionID, title, desc, snippet string, sev models.Severity, sens models.Sensitivity, conf float64) models.Finding {
	return models.Finding{
		ID:          models.GenerateID(NameInventory, models.CategoryManifestIssue, AndroidManifestFile, 1, snippet),
		SessionID:   sessionID,
		SourceTool:  NameInventory,
		Category:    models.CategoryManifestIssue,
		Platform:    models.PlatformAndroid,
		Origin:      OriginApp,
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
	data, err := readFileCapped(filepath.Join(dir, AndroidManifestFile), maxManifestBytes)
	var m *androidManifest
	if err == nil {
		m, _ = decodeManifest(data)
	}

	nscAbs, nscRel := resolveNSCPath(dir, m)
	if nscAbs == "" {
		return nil
	}

	raw, err := readFileCapped(nscAbs, maxManifestBytes)
	if err != nil {
		return nil
	}
	policy, err := parseNSCPolicy(raw, nil)
	if err != nil {
		return nil
	}
	inv.network = networkPolicyFromNSC(policy)
	inv.hasNet = true
	return nscFindings(policy, sessionID, nscRel)
}

// nscFindingsFromAPK reads the network security config named by the manifest
// straight out of the APK, including the compiled binary-XML form.
func nscFindingsFromAPK(a *apkArchive, m *androidManifest, sessionID string) ([]models.Finding, models.NetworkPolicy, bool) {
	policy, file, ok := nscPolicyFromAPK(a, m)
	if !ok {
		return nil, models.NetworkPolicy{}, false
	}
	return nscFindings(policy, sessionID, file), networkPolicyFromNSC(policy), true
}

// nscPolicyFromAPK locates and parses the network security config inside the
// APK. It understands both the compiled binary-XML form and plain XML.
func nscPolicyFromAPK(a *apkArchive, m *androidManifest) (*nscPolicy, string, bool) {
	if a == nil {
		return nil, "", false
	}
	candidates := []string{}
	if name := nscResourceName(m); name != "" {
		candidates = append(candidates, filepath.ToSlash(filepath.Join("res", "xml", name+".xml")))
	}
	candidates = append(candidates, NetworkSecurityConfigFile)

	for _, rel := range candidates {
		raw, ok := a.file(rel, maxManifestBytes)
		if !ok {
			continue
		}
		policy, err := parseNSCPolicy(raw, a.resolve)
		if err != nil {
			continue
		}
		return policy, rel, true
	}
	return nil, "", false
}

func nscFinding(sessionID, file, title, desc, snippet string, cat models.Category, sev models.Severity, sens models.Sensitivity, conf float64) models.Finding {
	return models.Finding{
		ID:          models.GenerateID(NameInventory, cat, file, 1, snippet),
		SessionID:   sessionID,
		SourceTool:  NameInventory,
		Category:    cat,
		Platform:    models.PlatformAndroid,
		Origin:      OriginApp,
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
