package analyzers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	// NameInventory is the tool identifier for the built-in inventory analyzer.
	NameInventory = "inventory"

	// boolTrue is the canonical string form of an Android boolean attribute.
	boolTrue = "true"
	// privateKeyRuleName is the scanRules entry that needs the full-PEM
	// validation and redaction path.
	privateKeyRuleName = "Private Key Block"
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
	agg     ScanAggregate
	target  string
	network models.NetworkPolicy
	hasNet  bool
}

func NewInventory() *Inventory { return &Inventory{} }

// Aggregate returns the aggregate collected by the last Run/Analyze call.
func (inv *Inventory) Aggregate() ScanAggregate { return inv.agg }

// NetworkPolicy returns the structured network security policy read from the
// APK (or the decoded tree). hasNet is false when the app has no config.
func (inv *Inventory) NetworkPolicy() (models.NetworkPolicy, bool) {
	return inv.network, inv.hasNet
}

func (inv *Inventory) Name() string     { return NameInventory }
func (inv *Inventory) Available() error { return nil }
func (inv *Inventory) Run(_ context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  inv.Name(),
		Version:   toolVersion,
		StartedAt: start,
	}

	findings := inv.AnalyzeTarget(target, workdir, "")

	raw, _ := json.Marshal(findings)
	result.Output = raw
	result.Duration = time.Since(start)
	return result, nil
}

// Analyze runs the inventory over the decoded tree in workdir.
func (inv *Inventory) Analyze(workdir string, sessionID string) []models.Finding {
	return inv.analyze(workdir, sessionID, inv.target)
}

// AnalyzeTarget runs the inventory with direct access to the APK. The binary
// manifest, resources.arsc, the network security config and every DEX string
// pool are read in-process; the decoded tree is only a fallback.
func (inv *Inventory) AnalyzeTarget(target, workdir string, sessionID string) []models.Finding {
	inv.target = target
	return inv.analyze(workdir, sessionID, target)
}

func (inv *Inventory) analyze(workdir, sessionID, target string) []models.Finding {
	srcDir := SourceRoot(workdir)

	findings := make([]models.Finding, 0, 16)
	nativeManifest, nativeNSC := false, false

	if target != "" {
		if a, err := openAPKArchive(target); err == nil {
			var m *androidManifest
			if m, err = a.manifest(); err == nil {
				findings = append(findings, inv.manifestFindings(m, sessionID)...)
				nativeManifest = true
			}
			if nscFindings, policy, ok := nscFindingsFromAPK(a, m, sessionID); ok {
				findings = append(findings, nscFindings...)
				inv.network = policy
				inv.hasNet = true
				nativeNSC = true
			}
			a.close()
		}
	}

	if !nativeManifest {
		// No native manifest (a corrupt archive, an unreadable manifest or a
		// caller that only has a decoded tree): use the tree.
		findings = append(findings, inv.analyzeManifest(srcDir, sessionID)...)
	}
	if !nativeNSC {
		findings = append(findings, inv.analyzeNetworkSecurityConfig(srcDir, sessionID)...)
	}

	scanned, agg := inv.scanPatterns(srcDir, sessionID)
	findings = append(findings, scanned...)
	treeHadPinning := len(agg.Pinning) > 0

	dexFindings, dexAgg := scanDEXStrings(target, sessionID)
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		seen[scanKey(f)] = true
	}
	for _, f := range dexFindings {
		if seen[scanKey(f)] {
			continue
		}
		seen[scanKey(f)] = true
		findings = append(findings, f)
	}
	mergeAggregate(&agg, dexAgg)
	inv.agg = agg

	if !treeHadPinning && len(agg.Pinning) > 0 {
		findings = append(findings, pinningFinding(agg, sessionID, "classes.dex"))
	}
	return findings
}

// scanKey identifies a duplicate between the decoded-tree scan and the DEX
// string-pool scan.
func scanKey(f models.Finding) string {
	return string(f.Category) + "\x00" + f.Evidence
}

// mergeAggregate copies the DEX aggregates only when the tree scan produced
// none, so a decompiled run does not double-count the same strings.
func mergeAggregate(dst *ScanAggregate, dex ScanAggregate) {
	if dst.URLs.Count == 0 {
		dst.URLs = dex.URLs
	}
	if dst.IPCount == 0 {
		dst.IPs, dst.IPCount = dex.IPs, dex.IPCount
	}
	if dst.EmailCount == 0 {
		dst.Emails, dst.EmailCount = dex.Emails, dex.EmailCount
	}
	if dst.PinningCount == 0 {
		dst.Pinning, dst.PinningCount = dex.Pinning, dex.PinningCount
	}
}

// pinningFinding emits the single app-level pinning indicator.
func pinningFinding(agg ScanAggregate, sessionID, file string) models.Finding {
	if file == "" {
		file = "inventory"
	}
	snippet := strings.Join(agg.Pinning, ", ")
	return models.Finding{
		ID:          models.GenerateID(NameInventory, models.CategoryPinningIndicator, file, 0, snippet),
		SessionID:   sessionID,
		SourceTool:  NameInventory,
		Category:    models.CategoryPinningIndicator,
		Platform:    models.PlatformAndroid,
		Origin:      OriginApp,
		Title:       "Certificate pinning indicators detected",
		Description: fmt.Sprintf("The app references pinning-related APIs or certificate material (%s) in %d place(s). Confirm that pinning is enforced on the paths that carry credentials.", snippet, agg.PinningCount),
		Evidence:    snippet,
		Location:    models.Location{File: file, Line: 0, Snippet: snippet},
		Severity:    models.SeverityInfo,
		Sensitivity: models.SensitivityPublic,
		Confidence:  0.85,
	}
}

// --- Pattern scanning ---

type patternRule struct {
	Name        string
	Category    models.Category
	Severity    models.Severity
	Sensitivity models.Sensitivity
	Re          *regexp.Regexp
	// Needle is a cheap substring that every match must contain. It keeps
	// the regex engine out of the hot path during a full-tree scan.
	Needle string
	// Description overrides the generic "Pattern match for X" text.
	Description string
	// Redact replaces the matched body in the evidence with a placeholder.
	Redact bool
}

var scanRules = []patternRule{
	{
		Name: "AWS Access Key", Category: models.CategorySecret,
		Severity: models.SeverityCritical, Sensitivity: models.SensitivitySecret,
		Re:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Needle: "AKIA",
	},
	{
		// AIza… keys are client-side identifiers (Maps/Firebase). They are
		// only a secret when API restrictions are missing, so they are
		// reported as informational rather than critical.
		Name: "GCP API Key", Category: models.CategorySecret,
		Severity: models.SeverityInfo, Sensitivity: models.SensitivityPublic,
		Re:          regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
		Needle:      "AIza",
		Description: "Google API key (client-side identifier). Verify that the key is restricted to the expected Android app and APIs; it is usually not a server-side secret.",
	},
	{
		Name: "Google OAuth Client ID", Category: models.CategorySecret,
		Severity: models.SeverityInfo, Sensitivity: models.SensitivityPublic,
		Re:          regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`),
		Needle:      "apps.googleusercontent.com",
		Description: "Google OAuth client ID. It identifies the app and is not a client secret.",
	},
	{
		Name: "GitHub Token", Category: models.CategorySecret,
		Severity: models.SeverityCritical, Sensitivity: models.SensitivitySecret,
		Re:     regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),
		Needle: "gh",
	},
	{
		Name: "Slack Token", Category: models.CategorySecret,
		Severity: models.SeverityCritical, Sensitivity: models.SensitivitySecret,
		Re:     regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`),
		Needle: "xox",
	},
	{
		Name: privateKeyRuleName, Category: models.CategorySecret,
		Severity: models.SeverityCritical, Sensitivity: models.SensitivitySecret,
		Re:     privateKeyRe,
		Needle: "-----BEGIN ",
		Redact: true,
	},
	{
		Name: "JWT", Category: models.CategorySecret,
		Severity: models.SeverityHigh, Sensitivity: models.SensitivitySecret,
		Re:     regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
		Needle: "eyJ",
	},
	{
		Name: "Azure Storage Connection String", Category: models.CategorySecret,
		Severity: models.SeverityCritical, Sensitivity: models.SensitivitySecret,
		Re:     regexp.MustCompile(`(?is)(?:DefaultEndpointsProtocol=https?|AccountName=[a-z0-9\-]+)[^"'\s]{0,120}AccountKey=[A-Za-z0-9+/=]{40,}`),
		Needle: "AccountKey=",
	},
	{
		Name: "Predictable IV (IvParameterSpec)", Category: models.CategoryCodePattern,
		Severity: models.SeverityMedium, Sensitivity: models.SensitivityInternal,
		Re:     regexp.MustCompile(`IvParameterSpec\(\s*(?:null|new\s+byte\[\s*\d*\s*\]|"[0-9A-Fa-f]{16,}")`),
		Needle: "IvParameterSpec",
	},
	{
		// Firebase database URLs are public endpoints; they are only
		// interesting in combination with an open security rule.
		Name: "Firebase URL", Category: models.CategorySecret,
		Severity: models.SeverityInfo, Sensitivity: models.SensitivityPublic,
		Re:          regexp.MustCompile(`https://[a-z0-9\-]+\.firebaseio\.com`),
		Needle:      "firebaseio.com",
		Description: "Firebase Realtime Database URL. It is not a secret by itself; confirm that the database rules are not public.",
	},
}

func (inv *Inventory) scanPatterns(dir string, sessionID string) ([]models.Finding, ScanAggregate) {
	paths := collectScanFiles(dir)

	workers := runtime.NumCPU()
	if workers > 8 {
		workers = 8
	}
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan string)
	results := make(chan fileScanResult, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				results <- scanOneFile(dir, path, sessionID)
			}
		}()
	}
	go func() {
		for _, path := range paths {
			jobs <- path
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	agg := ScanAggregate{}
	urlSeen := make(map[string]bool, maxURLSamples)
	ipSeen := make(map[string]bool, maxIPSamples)
	emailSeen := make(map[string]bool, maxEmailSamples)
	pinSeen := make(map[string]bool, len(pinningMarkers))
	firstPinFile, firstPinLine := "", 0

	var findings []models.Finding
	for part := range results {
		findings = append(findings, part.findings...)
		agg.URLs.Count += part.urlCount
		for _, u := range part.urls {
			if !urlSeen[u] && len(urlSeen) < maxURLSamples {
				urlSeen[u] = true
				agg.URLs.URLs = append(agg.URLs.URLs, u)
			}
		}
		agg.IPCount += part.ipCount
		for _, ip := range part.ips {
			if !ipSeen[ip] && len(ipSeen) < maxIPSamples {
				ipSeen[ip] = true
				agg.IPs = append(agg.IPs, ip)
			}
		}
		agg.EmailCount += part.emailCount
		for _, email := range part.emails {
			if !emailSeen[email] && len(emailSeen) < maxEmailSamples {
				emailSeen[email] = true
				agg.Emails = append(agg.Emails, email)
			}
		}
		agg.PinningCount += part.pinCount
		for _, marker := range part.pinMarkers {
			if pinSeen[marker] {
				continue
			}
			pinSeen[marker] = true
			agg.Pinning = append(agg.Pinning, marker)
			if firstPinFile == "" || part.pinFile < firstPinFile ||
				(part.pinFile == firstPinFile && part.pinLine < firstPinLine) {
				firstPinFile, firstPinLine = part.pinFile, part.pinLine
			}
		}
	}

	sort.Strings(agg.URLs.URLs)
	sort.Strings(agg.IPs)
	sort.Strings(agg.Emails)
	sort.Strings(agg.Pinning)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Location.File != findings[j].Location.File {
			return findings[i].Location.File < findings[j].Location.File
		}
		if findings[i].Location.Line != findings[j].Location.Line {
			return findings[i].Location.Line < findings[j].Location.Line
		}
		return findings[i].Evidence < findings[j].Evidence
	})

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
			Origin:      OriginApp,
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

// fileScanResult is the per-file output merged after the parallel walk.
type fileScanResult struct {
	findings []models.Finding

	urls       []string
	urlCount   int
	ips        []string
	ipCount    int
	emails     []string
	emailCount int

	pinMarkers []string
	pinCount   int
	pinFile    string
	pinLine    int
}

// collectScanFiles walks the tree once, skips symlinks and vendor SDK trees,
// and returns the files the pattern scanner should read.
func collectScanFiles(dir string) []string {
	var paths []string
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			rel, relErr := filepath.Rel(dir, path)
			if relErr == nil && rel != "." && isVendorPath(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".java" && ext != ".smali" && ext != ".xml" && ext != ".kt" &&
			ext != ".json" && ext != ".properties" && ext != ".cfg" {
			return nil
		}
		if info, statErr := d.Info(); statErr == nil && info.Size() > maxScanFileSize {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	sort.Strings(paths)
	return paths
}

// vendorPathPrefixes are third-party trees whose literals are already covered
// by the DEX string scanner; scanning them again in source form mostly adds
// duplicates and cost.
var vendorPathPrefixes = []string{
	"androidx/",
	"com/google/firebase/",
	"com/google/android/gms/",
	"com/google/android/material/",
	"com/google/gson/",
	"com/google/common/",
	"com/google/protobuf/",
	"com/facebook/",
	"kotlin/",
	"kotlinx/",
	"okhttp3/",
	"okio/",
	"retrofit2/",
	"org/apache/",
	"org/bouncycastle/",
	"io/reactivex/",
	"io/sentry/",
	"com/squareup/",
	"com/bumptech/",
	"com/crashlytics/",
}

// isVendorPath reports whether a relative path lives under a known vendor tree.
func isVendorPath(rel string) bool {
	p := "/" + strings.ReplaceAll(rel, "\\", "/") + "/"
	for _, prefix := range vendorPathPrefixes {
		if strings.Contains(p, "/"+prefix) {
			return true
		}
	}
	return false
}

// scanOneFile runs the aggregate and rule patterns over one file.
func scanOneFile(dir, path, sessionID string) fileScanResult {
	result := fileScanResult{}
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return result
	}
	content := string(data)
	relPath, _ := filepath.Rel(dir, path)

	urlSeen := make(map[string]bool, maxURLSamples)
	for _, m := range urlRe.FindAllString(content, -1) {
		result.urlCount++
		u := strings.TrimRight(m, ".,;:!?)]}")
		if !urlSeen[u] && len(result.urls) < maxURLSamples {
			urlSeen[u] = true
			result.urls = append(result.urls, u)
		}
	}
	ipSeen := make(map[string]bool, maxIPSamples)
	for _, m := range ipRe.FindAllString(content, -1) {
		result.ipCount++
		if !ipSeen[m] && len(result.ips) < maxIPSamples {
			ipSeen[m] = true
			result.ips = append(result.ips, m)
		}
	}
	emailSeen := make(map[string]bool, maxEmailSamples)
	for _, m := range emailRe.FindAllString(content, -1) {
		result.emailCount++
		if !emailSeen[m] && len(result.emails) < maxEmailSamples {
			emailSeen[m] = true
			result.emails = append(result.emails, m)
		}
	}

	pinSeen := make(map[string]bool, len(pinningMarkers))
	for _, marker := range pinningMarkers {
		n := strings.Count(content, marker)
		if n == 0 {
			continue
		}
		result.pinCount += n
		if pinSeen[marker] {
			continue
		}
		pinSeen[marker] = true
		result.pinMarkers = append(result.pinMarkers, marker)
		line := lineOfOffset(content, strings.Index(content, marker))
		if result.pinFile == "" || relPath < result.pinFile ||
			(relPath == result.pinFile && line < result.pinLine) {
			result.pinFile, result.pinLine = relPath, line
		}
	}

	for _, rule := range scanRules {
		if rule.Needle != "" && !strings.Contains(content, rule.Needle) {
			continue
		}
		locs := rule.Re.FindAllStringIndex(content, -1)
		lineCursor := 1
		matchEnd := 0
		for _, loc := range locs {
			for i := matchEnd; i < loc[0]; i++ {
				if content[i] == '\n' {
					lineCursor++
				}
			}
			matchEnd = loc[1]

			raw := content[loc[0]:loc[1]]
			if rule.Name == privateKeyRuleName && !validPEMBlock(raw) {
				continue
			}
			snippet := raw
			if rule.Redact {
				snippet = redactPEM(raw)
			}
			if len(snippet) > 120 {
				snippet = snippet[:120]
			}
			desc := rule.Description
			if desc == "" {
				desc = fmt.Sprintf("Pattern match for %s in %s", rule.Name, relPath)
			}
			result.findings = append(result.findings, models.Finding{
				ID:          models.GenerateID(NameInventory, rule.Category, relPath, lineCursor, snippet),
				SessionID:   sessionID,
				SourceTool:  NameInventory,
				Category:    rule.Category,
				Platform:    models.PlatformAndroid,
				Origin:      OriginForPath(relPath),
				Title:       rule.Name,
				Description: desc,
				Evidence:    snippet,
				Location:    models.Location{File: relPath, Line: lineCursor, Snippet: snippet},
				Severity:    rule.Severity,
				Sensitivity: rule.Sensitivity,
				Confidence:  0.7,
			})
		}
	}
	return result
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
	// Decompiled Java/Kotlin strings often carry the newlines escaped as the
	// two characters \n; normalize them before looking for the base64 body.
	block = strings.ReplaceAll(block, `\n`, "\n")
	block = strings.ReplaceAll(block, `\r`, "")
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
