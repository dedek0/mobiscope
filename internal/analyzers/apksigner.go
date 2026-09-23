package analyzers

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	apksignerName   = "apksigner"
	apksignerBinary = "apksigner"
	apksignerTo     = 2 * time.Minute
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

func (a *ApkSigner) Available() error {
	if err := CheckBinary(apksignerBinary); err == nil {
		return nil
	}
	return nil
}

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
			"verify", "--print-certs", "--verbose", target,
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
			ID:          models.GenerateID(apksignerName, models.CategoryManifestIssue, "META-INF", 1, snippet),
			SessionID:   sessionID,
			SourceTool:  apksignerName,
			Category:    models.CategoryManifestIssue,
			Platform:    models.PlatformAndroid,
			Title:       title,
			Description: desc,
			Evidence:    snippet,
			Location:    models.Location{File: "META-INF", Line: 1, Snippet: snippet},
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
	if out.SignerCount == "0" {
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
// prints. Best-effort string scraping.
func parseApksignerOutput(out string) (scheme, certFP, signerCount, debug string) {
	for _, line := range strings.Split(out, "\n") {
		low := strings.ToLower(line)
		switch {
		case strings.Contains(low, "verified using v2"):
			scheme = "v2"
		case strings.Contains(low, "verified using v3"):
			scheme = "v3"
		case strings.Contains(low, "verified using v1") && scheme == "":
			scheme = "v1"
		case strings.Contains(low, "signer #"):
			if signerCount == "" {
				signerCount = "1"
			} else {
				signerCount = fmt.Sprintf("%d", atoiSafe(signerCount)+1)
			}
		case strings.Contains(low, "signing certificate #1 sha-256 digest:"):
			certFP = strings.TrimSpace(line[strings.Index(line, ":")+1:])
		case strings.Contains(low, "signer #1 certificate dn:"):
			if strings.Contains(low, "debug") {
				debug = "true"
			}
		}
	}
	if signerCount == "" {
		signerCount = "0"
	}
	return scheme, certFP, signerCount, debug
}

// metaInfHeuristic inspects the APK's META-INF directory for signature files.
func metaInfHeuristic(target string) (scheme, certFP, signerCount string) {
	zr, err := openZip(target)
	if err != nil {
		return unknownVersion, "", "0"
	}
	defer zr.Close()

	certs := 0
	v1 := false
	for _, f := range zr.File {
		name := strings.ToUpper(f.Name)
		if strings.HasPrefix(name, "META-INF/") {
			if strings.HasSuffix(name, ".RSA") || strings.HasSuffix(name, ".DSA") || strings.HasSuffix(name, ".EC") {
				v1 = true
				certs++
			}
		}
	}
	if certs == 0 {
		return "none", "", "0"
	}
	if v1 {
		return "v1", "", fmt.Sprintf("%d", certs)
	}
	return unknownVersion, "", fmt.Sprintf("%d", certs)
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
	manifestPath := filepath.Join(workdir, "jadx", AndroidManifestFile)
	if !fileExists(manifestPath) {
		manifestPath = filepath.Join(workdir, AndroidManifestFile)
	}
	data, err := os.ReadFile(manifestPath) //nolint:gosec
	if err != nil {
		return info
	}
	m, err := decodeManifest(data)
	if err != nil {
		return info
	}
	info.BundleID = m.Package
	info.Permissions = m.permissions()
	info.Network = models.NetworkPolicy{Kind: "network_security_config"}
	if strings.EqualFold(m.Application.Debuggable, "true") {
		info.Debuggable = true
	}
	return info
}

// IOSAppInfo builds AppInventory for an iOS bundle.
func IOSAppInfo(workdir string) models.AppInventory {
	info := models.AppInventory{}
	bundle := appBundleDir(workdir)
	if bundle == "" {
		return info
	}
	if data, err := os.ReadFile(filepath.Join(bundle, "Info.plist")); err == nil { //nolint:gosec
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
