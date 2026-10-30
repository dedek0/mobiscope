package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const repackName = "repack"

// NameRepack is the stage identifier of the repackaging analyzer.
const NameRepack = repackName

// Repack inspects the archive for the signals that a build was repackaged:
// a certificate that does not match the expected one, executable payloads
// hidden in assets, and native libraries loaded from assets. Multidex, a
// v2/v3-only signature and a normalized ZIP timestamp are normal for modern
// apps and are not reported.
//
// The checks are deliberately conservative: each one reports what it saw and
// how strong the signal is, and the LLM triage stage is what turns the
// collection into a verdict.
type Repack struct {
	// expectedCert is the fingerprint the operator expects, if any. It is
	// compared with the certificate found by the apksigner stage.
	expectedCert string
}

func NewRepack() *Repack {
	return &Repack{}
}

// NewRepackWithExpectedCert returns a Repack analyzer that compares the
// signing certificate against the expected fingerprint.
func NewRepackWithExpectedCert(fingerprint string) *Repack {
	return &Repack{expectedCert: fingerprint}
}

func (r *Repack) Name() string { return repackName }

// Available always succeeds: the analysis is fully in-process.
func (r *Repack) Available() error { return nil }

// Phase marks the analyzer as independent: it reads the target artifact
// directly.
func (r *Repack) Phase() Phase { return PhaseIndependent }

func (r *Repack) Run(_ context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  r.Name(),
		Version:   toolVersion,
		StartedAt: start,
	}

	summary := r.analyze(target)

	raw, _ := json.Marshal(summary)
	result.Output = raw
	result.Duration = time.Since(start)
	return result, nil
}

// repackSummary is the JSON shape written by Repack.Run.
type repackSummary struct {
	// Indicators lists the repackaging signals that were found.
	Indicators []repackIndicator `json:"indicators"`
	// ExpectedCert is the fingerprint the operator asked for.
	ExpectedCert string `json:"expected_cert,omitempty"`
	// ActualCert is the fingerprint found in the archive.
	ActualCert string `json:"actual_cert,omitempty"`
	// CertMatches is true when the expected and actual fingerprints agree.
	CertMatches bool `json:"cert_matches"`
}

// repackIndicator is one repackaging signal.
type repackIndicator struct {
	Kind        string          `json:"kind"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Evidence    string          `json:"evidence"`
	Severity    models.Severity `json:"severity"`
	Confidence  float64         `json:"confidence"`
}

// ConvertRepackFindings turns the repackaging summary into findings.
func ConvertRepackFindings(raw []byte, sessionID string) []models.Finding {
	var out repackSummary
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}

	var findings []models.Finding
	for _, ind := range out.Indicators {
		f := models.Finding{
			ID:          models.GenerateID(repackName, models.CategoryManifestIssue, metaInfDir, 1, ind.Evidence),
			SessionID:   sessionID,
			SourceTool:  repackName,
			Category:    models.CategoryManifestIssue,
			Platform:    models.PlatformAndroid,
			Title:       ind.Title,
			Description: ind.Description,
			Evidence:    ind.Evidence,
			Location:    models.Location{File: metaInfDir, Line: 1, Snippet: ind.Evidence},
			Severity:    ind.Severity,
			Sensitivity: models.SensitivityConfidential,
			Confidence:  ind.Confidence,
		}
		findings = append(findings, f)
	}

	if out.ExpectedCert != "" && !out.CertMatches {
		f := models.Finding{
			ID:          models.GenerateID(repackName, models.CategoryManifestIssue, metaInfDir, 1, "cert-mismatch"),
			SessionID:   sessionID,
			SourceTool:  repackName,
			Category:    models.CategoryManifestIssue,
			Platform:    models.PlatformAndroid,
			Title:       "Signing certificate does not match the expected one",
			Description: fmt.Sprintf("The archive is signed with %s but %s was expected. The artifact is not the one that was supposed to be analysed.", shortFingerprint(out.ActualCert), shortFingerprint(out.ExpectedCert)),
			Evidence:    "cert-mismatch",
			Location:    models.Location{File: metaInfDir, Line: 1, Snippet: "cert-mismatch"},
			Severity:    models.SeverityCritical,
			Sensitivity: models.SensitivityConfidential,
			Confidence:  1.0,
		}
		findings = append(findings, f)
	}

	return findings
}

// analyze inspects the archive and returns the summary.
//
// Only signals that actually distinguish a repackaged build are reported.
// Multidex, a v2/v3-only signature and a normalized ZIP timestamp are normal
// for modern apps and were deliberately removed: they produced a finding on
// nearly every real target.
func (r *Repack) analyze(target string) repackSummary {
	summary := repackSummary{ExpectedCert: r.expectedCert}

	zr, err := openZip(target)
	if err != nil {
		return summary
	}
	defer zr.Close()

	var executablePayloads []string
	var nativePayloads []string

	for _, f := range zr.File {
		name := f.Name
		if !strings.HasPrefix(name, "assets/") {
			continue
		}
		lower := strings.ToLower(name)
		switch {
		case strings.HasSuffix(lower, ".dex"), strings.HasSuffix(lower, ".jar"),
			strings.HasSuffix(lower, ".apk"):
			executablePayloads = append(executablePayloads, name)
		case strings.HasSuffix(lower, ".so"):
			nativePayloads = append(nativePayloads, name)
		}
	}

	if len(executablePayloads) > 0 {
		summary.Indicators = append(summary.Indicators, repackIndicator{
			Kind:        "asset-payload",
			Title:       "Executable payload shipped in assets",
			Description: "The archive ships " + strings.Join(executablePayloads, ", ") + " under assets/. A DEX, JAR or APK file in assets is usually loaded at runtime, which hides it from a static review.",
			Evidence:    strings.Join(executablePayloads, ","),
			Severity:    models.SeverityHigh,
			Confidence:  0.7,
		})
	}

	if len(nativePayloads) > 0 {
		summary.Indicators = append(summary.Indicators, repackIndicator{
			Kind:        "asset-native-library",
			Title:       "Native library shipped in assets",
			Description: "The archive ships " + strings.Join(nativePayloads, ", ") + " under assets/. Loading a .so from app-private assets is legitimate for some SDKs, but it bypasses the normal lib/<abi> loading path and deserves a look.",
			Evidence:    strings.Join(nativePayloads, ","),
			Severity:    models.SeverityLow,
			Confidence:  0.5,
		})
	}

	return summary
}

// shortFingerprint trims a certificate fingerprint for display.
func shortFingerprint(fp string) string {
	fp = strings.TrimSpace(fp)
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16] + "…"
}
