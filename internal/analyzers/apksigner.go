package analyzers

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
	"gopkg.in/yaml.v3"
)

const (
	apksignerName   = "apksigner"
	apksignerBinary = "apksigner"
	apksignerTo     = 2 * time.Minute
	// apkSigBlockMagic ends the v2/v3 APK Signing Block.
	apkSigBlockMagic = "APK Sig Block 42"
)

// ApkSigner verifies the APK signature and records the signing identity.
// Uses `apksigner verify --print-certs` when available; degrades to a
// META-INF scan otherwise.
type ApkSigner struct {
	runner CommandRunner
}

func NewApkSigner() *ApkSigner {
	return &ApkSigner{runner: &DefaultCommandRunner{}}
}

func NewApkSignerWithRunner(runner CommandRunner) *ApkSigner {
	return &ApkSigner{runner: runner}
}

func (a *ApkSigner) Name() string { return apksignerName }

// Available reports whether the apksigner binary is present. The analyzer
// still runs without it (the META-INF heuristic takes over), but the dry-run
// output must say that the strong check is unavailable.
func (a *ApkSigner) Available() error {
	if err := CheckBinary(apksignerBinary); err != nil {
		return fmt.Errorf("%w (the META-INF fallback will be used)", err)
	}
	return nil
}

// Phase marks the analyzer as independent: it verifies the target artifact
// itself and does not read decompiler output.
func (a *ApkSigner) Phase() Phase { return PhaseIndependent }

func (a *ApkSigner) Run(ctx context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  a.Name(),
		Version:   toolVersion,
		StartedAt: start,
	}

	var scheme, certFP, signerCount, debug string

	if CheckBinary(apksignerBinary) == nil {
		cmdRes, err := a.runner.Run(ctx, apksignerBinary, []string{
			"verify", "--print-certs", "--verbose", "--", target,
		}, apksignerTo, nil)
		if cmdRes != nil {
			scheme, certFP, signerCount, debug = parseApksignerOutput(cmdRes.Stdout + cmdRes.Stderr)
		}
		if err != nil {
			// Non-fatal: fall through to the META-INF heuristic.
			result.Error = err.Error()
		}
	}
	if scheme == "" {
		scheme, certFP, signerCount = metaInfHeuristic(target)
	}

	raw, _ := json.Marshal(map[string]interface{}{
		"signature_scheme": scheme,
		"signing_cert_fp":  certFP,
		"signer_count":     signerCount,
		"debug_signed":     debug == "true" || strings.Contains(strings.ToLower(debug), "debug"),
	})
	result.Output = raw
	result.Duration = time.Since(start)
	return result, nil
}

// apksignerOutput is the JSON shape written by ApkSigner.Run.
type apksignerOutput struct {
	SignatureScheme string `json:"signature_scheme"`
	SigningCertFP   string `json:"signing_cert_fp"`
	SignerCount     string `json:"signer_count"`
	DebugSigned     bool   `json:"debug_signed"`
}

// ConvertApkSignerFindings reports signature-level issues.
func ConvertApkSignerFindings(raw []byte, sessionID string) []models.Finding {
	var out apksignerOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}

	var findings []models.Finding
	add := func(title, desc, snippet string, sev models.Severity, sens models.Sensitivity, conf float64) {
		f := models.Finding{
			ID:          models.GenerateID(apksignerName, models.CategoryManifestIssue, metaInfDir, 1, snippet),
			SessionID:   sessionID,
			SourceTool:  apksignerName,
			Category:    models.CategoryManifestIssue,
			Platform:    models.PlatformAndroid,
			Title:       title,
			Description: desc,
			Evidence:    snippet,
			Location:    models.Location{File: metaInfDir, Line: 1, Snippet: snippet},
			Severity:    sev,
			Sensitivity: sens,
			Confidence:  conf,
		}
		findings = append(findings, f)
	}

	if out.DebugSigned {
		add("APK is debug-signed",
			"The APK is signed with a debug keystore; it is not suitable for release and may indicate a repackaged build.",
			out.SigningCertFP, models.SeverityHigh, models.SensitivityConfidential, 0.9)
	}
	if out.SignerCount == "0" && (out.SignatureScheme == valueNone || out.SignatureScheme == "") {
		add("APK has no signer",
			"No signing certificate was found; the APK cannot be verified as authentic.",
			"signer_count=0", models.SeverityHigh, models.SensitivityConfidential, 0.8)
	}
	if out.SignatureScheme == "v1" {
		add("APK uses only v1 (JAR) signing",
			"v1 signatures do not cover the entire APK and are vulnerable to Janus-style attacks; prefer v2/v3.",
			"scheme=v1", models.SeverityMedium, models.SensitivityConfidential, 0.85)
	}
	return findings
}

// parseApksignerOutput extracts the fields `apksigner verify --print-certs`
// prints. Best-effort string scraping. Order matters: specific lines
// ("Signer #1 certificate DN/SHA-256 digest") must be matched before any
// generic "signer #" substring.
func parseApksignerOutput(out string) (scheme, certFP, signerCount, debug string) {
	signers := 0
	explicitSigners := -1
	for _, line := range strings.Split(out, "\n") {
		low := strings.ToLower(line)
		switch {
		case strings.Contains(low, "verified using v3") && strings.Contains(low, ": true"):
			scheme = "v3"
		case strings.Contains(low, "verified using v2") && strings.Contains(low, ": true"):
			scheme = "v2"
		case strings.Contains(low, "verified using v1") && strings.Contains(low, ": true") && scheme == "":
			scheme = "v1"
		case strings.Contains(low, "number of signers:"):
			if n, ok := parseCountAfterColon(line); ok {
				explicitSigners = n
			}
		case strings.Contains(low, "signer #") && strings.Contains(low, "certificate dn:"):
			// One line per signer; the DN also carries the debug flag.
			signers++
			if strings.Contains(low, "debug") {
				debug = "true"
			}
		case strings.Contains(low, "sha-256 digest:"):
			// Covers "Signer #1 certificate SHA-256 digest" and the older
			// "Signing certificate #1 SHA-256 digest" wording.
			if certFP == "" {
				certFP = strings.TrimSpace(line[strings.Index(line, ":")+1:])
			}
		}
	}
	switch {
	case explicitSigners >= 0:
		signerCount = strconv.Itoa(explicitSigners)
	case signers > 0:
		signerCount = strconv.Itoa(signers)
	default:
		// Unknown, not zero: reporting "0" would claim the APK has no
		// signer when the output was merely unparsable.
		signerCount = unknownVersion
	}
	return scheme, certFP, signerCount, debug
}

// parseCountAfterColon reads an integer that follows the last colon of a
// "key: value" line. It reports false when the value is not a number.
func parseCountAfterColon(line string) (int, bool) {
	idx := strings.LastIndex(line, ":")
	if idx < 0 || idx+1 >= len(line) {
		return 0, false
	}
	value := strings.TrimSpace(line[idx+1:])
	if value == "" {
		return 0, false
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// metaInfHeuristic inspects the APK's signature material without apksigner.
// It checks the v1 META-INF block and the v2/v3 APK Signing Block, so a
// modern v2/v3-only APK is not misreported as unsigned.
func metaInfHeuristic(target string) (scheme, certFP, signerCount string) {
	zr, err := openZip(target)
	if err != nil {
		return unknownVersion, "", "unknown"
	}
	defer zr.Close()

	certs := 0
	for _, f := range zr.File {
		name := strings.ToUpper(f.Name)
		if strings.HasPrefix(name, "META-INF/") {
			if strings.HasSuffix(name, ".RSA") || strings.HasSuffix(name, ".DSA") || strings.HasSuffix(name, ".EC") {
				certs++
			}
		}
	}

	hasBlock := hasAPKSigningBlock(target)
	switch {
	case certs > 0 && hasBlock:
		return "v1+v2/v3", "", fmt.Sprintf("%d", certs)
	case certs > 0:
		return "v1", "", fmt.Sprintf("%d", certs)
	case hasBlock:
		return "v2/v3", "", "unknown"
	default:
		return valueNone, "", "0"
	}
}

// hasAPKSigningBlock reports whether the APK carries the v2/v3 APK Signing
// Block. The block sits immediately before the ZIP central directory and ends
// with the 16-byte "APK Sig Block 42" magic.
func hasAPKSigningBlock(path string) bool {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return false
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil || st.Size() < 32 {
		return false
	}
	size := st.Size()

	// The EOCD record lives in the last 64 KiB + 22 bytes.
	tailLen := int64(64*1024 + 22)
	if tailLen > size {
		tailLen = size
	}
	tail := make([]byte, tailLen)
	if _, err := f.ReadAt(tail, size-tailLen); err != nil {
		return false
	}
	idx := bytes.LastIndex(tail, []byte("PK\x05\x06"))
	if idx < 0 || idx+22 > len(tail) {
		return false
	}
	cdOffset := int64(binary.LittleEndian.Uint32(tail[idx+16:]))
	if cdOffset < 24 || cdOffset > size {
		return false
	}

	footer := make([]byte, 24)
	if _, err := f.ReadAt(footer, cdOffset-24); err != nil {
		return false
	}
	return string(footer[8:24]) == apkSigBlockMagic
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// AndroidManifestInfo is the subset of the decoded manifest used to populate
// AppInventory.
func AndroidManifestInfo(workdir string) models.AppInventory {
	info := models.AppInventory{}
	manifestPath := ""
	for _, dir := range []string{
		filepath.Join(workdir, "jadx"),
		filepath.Join(workdir, "apktool"),
		workdir,
	} {
		candidate := filepath.Join(dir, AndroidManifestFile)
		if fileExists(candidate) {
			manifestPath = candidate
			break
		}
	}
	if manifestPath == "" {
		return info
	}
	data, err := readFileCapped(manifestPath, maxManifestBytes)
	if err != nil {
		return info
	}
	m, err := decodeManifest(data)
	if err != nil {
		return info
	}
	info.BundleID = m.Package
	info.Permissions = m.permissions()
	if strings.EqualFold(m.Application.Debuggable, "true") {
		info.Debuggable = true
	}

	// Only claim a network security config when the manifest actually
	// references one (or the conventional file exists next to it).
	root := filepath.Dir(manifestPath)
	if nscAbs, _ := resolveNSCPath(root, m); nscAbs != "" {
		info.Network = models.NetworkPolicy{Kind: "network_security_config"}
		if nsc, err := readFileCapped(nscAbs, maxManifestBytes); err == nil {
			content := string(nsc)
			info.Network.CleartextPermitted = strings.Contains(content, `cleartextTrafficPermitted="true"`)
			info.Network.Pinned = strings.Contains(content, "<pin-set")
		}
	}

	// apktool.yml carries versionInfo/sdkInfo that the manifest does not.
	applyApktoolYML(workdir, &info)
	return info
}

// apktoolYML is the subset of apktool.yml that matters for inventory.
type apktoolYML struct {
	VersionInfo struct {
		VersionCode any    `yaml:"versionCode"`
		VersionName string `yaml:"versionName"`
	} `yaml:"versionInfo"`
	SDKInfo struct {
		MinSDKVersion    any `yaml:"minSdkVersion"`
		TargetSDKVersion any `yaml:"targetSdkVersion"`
	} `yaml:"sdkInfo"`
}

// applyApktoolYML fills VersionName/VersionCode/MinOS/TargetSDK from the
// apktool.yml written next to the decoded manifest.
func applyApktoolYML(workdir string, info *models.AppInventory) {
	for _, dir := range []string{
		filepath.Join(workdir, "apktool"),
		filepath.Join(workdir, "jadx"),
		workdir,
	} {
		path := filepath.Join(dir, "apktool.yml")
		data, err := readFileCapped(path, maxManifestBytes)
		if err != nil {
			continue
		}
		var y apktoolYML
		if err := yaml.Unmarshal(data, &y); err != nil {
			continue
		}
		if info.VersionName == "" && y.VersionInfo.VersionName != "" {
			info.VersionName = y.VersionInfo.VersionName
		}
		if info.VersionCode == "" {
			info.VersionCode = scalarString(y.VersionInfo.VersionCode)
		}
		if info.MinOS == "" {
			info.MinOS = scalarString(y.SDKInfo.MinSDKVersion)
		}
		if info.TargetSDK == "" {
			info.TargetSDK = scalarString(y.SDKInfo.TargetSDKVersion)
		}
		return
	}
}

func scalarString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case int:
		return strconv.Itoa(s)
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", s)
	}
}

// IOSAppInfo builds AppInventory for an iOS bundle.
func IOSAppInfo(workdir string) models.AppInventory {
	info := models.AppInventory{}
	bundle := AppBundleDir(workdir)
	if bundle == "" {
		return info
	}
	if data, err := readFileCapped(filepath.Join(bundle, "Info.plist"), maxManifestBytes); err == nil {
		if m, err := decodePlistMapAny(data); err == nil {
			info.BundleID = strOr(m["CFBundleIdentifier"])
			info.VersionName = strOr(m["CFBundleShortVersionString"])
			info.VersionCode = strOr(m["CFBundleVersion"])
			info.MinOS = strOr(m["MinimumOSVersion"])
		}
	}
	info.Network = models.NetworkPolicy{Kind: "NSAppTransportSecurity"}
	return info
}

// openZip opens a ZIP archive read-only.
func openZip(path string) (*zip.ReadCloser, error) {
	return zip.OpenReader(path)
}

// SigningIdentity returns (certFP, scheme) for the target APK by running the
// apksigner analyzer once. Returns empty strings when unavailable.
func SigningIdentity(target string) (string, string) {
	a := NewApkSigner()
	res, err := a.Run(context.TODO(), target, filepath.Dir(target))
	if err != nil || res.Output == nil {
		return "", ""
	}
	var out apksignerOutput
	if err := json.Unmarshal(res.Output, &out); err != nil {
		return "", ""
	}
	return out.SigningCertFP, out.SignatureScheme
}
