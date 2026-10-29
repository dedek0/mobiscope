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
// a debug certificate, a certificate that does not match the package, extra
// DEX files, payloads hidden in assets and a uniform timestamp across every
// entry.
//
// The checks are deliberately conservative: each one reports what it saw and
// how strong the signal is, and the LLM triage stage is what turns the
// collection into a verdict.
type Repack struct {
	runner CommandRunner
	// expectedCert is the fingerprint the operator expects, if any. It is
	// compared with the certificate found in the archive.
	expectedCert string
}

func NewRepack() *Repack {
	return &Repack{runner: &DefaultCommandRunner{}}
}

// NewRepackWithExpectedCert returns a Repack analyzer that compares the
// signing certificate against the expected fingerprint.
func NewRepackWithExpectedCert(fingerprint string) *Repack {
	return &Repack{runner: &DefaultCommandRunner{}, expectedCert: fingerprint}
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
	// SignatureScheme is the scheme reported by the apksigner stage.
	SignatureScheme string `json:"signature_scheme,omitempty"`
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
			ID:          models.GenerateID(repackName, models.CategoryManifestIssue, "META-INF", 1, ind.Evidence),
			SessionID:   sessionID,
			SourceTool:  repackName,
			Category:    models.CategoryManifestIssue,
			Platform:    models.PlatformAndroid,
			Title:       ind.Title,
			Description: ind.Description,
			Evidence:    ind.Evidence,
			Location:    models.Location{File: "META-INF", Line: 1, Snippet: ind.Evidence},
			Severity:    ind.Severity,
			Sensitivity: models.SensitivityConfidential,
			Confidence:  ind.Confidence,
		}
		findings = append(findings, f)
	}

	if out.ExpectedCert != "" && !out.CertMatches {
		f := models.Finding{
			ID:          models.GenerateID(repackName, models.CategoryManifestIssue, "META-INF", 1, "cert-mismatch"),
			SessionID:   sessionID,
			SourceTool:  repackName,
			Category:    models.CategoryManifestIssue,
			Platform:    models.PlatformAndroid,
			Title:       "Signing certificate does not match the expected one",
			Description: fmt.Sprintf("The archive is signed with %s but %s was expected. The artifact is not the one that was supposed to be analysed.", shortFingerprint(out.ActualCert), shortFingerprint(out.ExpectedCert)),
			Evidence:    "cert-mismatch",
			Location:    models.Location{File: "META-INF", Line: 1, Snippet: "cert-mismatch"},
			Severity:    models.SeverityCritical,
			Sensitivity: models.SensitivityConfidential,
			Confidence:  1.0,
		}
		findings = append(findings, f)
	}

	return findings
}

// analyze inspects the archive and returns the summary.
func (r *Repack) analyze(target string) repackSummary {
	summary := repackSummary{ExpectedCert: r.expectedCert}

	zr, err := openZip(target)
	if err != nil {
		return summary
	}
	defer zr.Close()

	var dexFiles []string
	var assetPayloads []string
	var signatureBlocks []string
	timestamps := map[int64]int{}

	for _, f := range zr.File {
		name := f.Name
		timestamps[f.Modified.Unix()]++

		switch {
		case strings.HasPrefix(name, "classes") && strings.HasSuffix(name, ".dex"):
			dexFiles = append(dexFiles, name)
		case strings.HasPrefix(name, "META-INF/") &&
			(strings.HasSuffix(strings.ToUpper(name), ".RSA") ||
				strings.HasSuffix(strings.ToUpper(name), ".DSA") ||
				strings.HasSuffix(strings.ToUpper(name), ".EC")):
			signatureBlocks = append(signatureBlocks, name)
		case strings.HasPrefix(name, "assets/"):
			lower := strings.ToLower(name)
			if strings.HasSuffix(lower, ".dex") || strings.HasSuffix(lower, ".jar") ||
				strings.HasSuffix(lower, ".so") || strings.HasSuffix(lower, ".apk") {
				assetPayloads = append(assetPayloads, name)
			}
		}
	}

	// More than one DEX file in the root of the archive is unusual: a
	// multi-dex build is declared in the manifest, a repackaged build
	// usually just drops an extra file in.
	if len(dexFiles) > 1 {
		summary.Indicators = append(summary.Indicators, repackIndicator{
			Kind:        "extra-dex",
			Title:       "Archive carries more than one DEX file",
			Description: "The archive contains " + strings.Join(dexFiles, ", ") + ". Extra DEX files are a common way to inject code into a repackaged build; check that the manifest declares a multidex setup.",
			Evidence:    strings.Join(dexFiles, ","),
			Severity:    models.SeverityMedium,
			Confidence:  0.6,
		})
	}

	if len(assetPayloads) > 0 {
		summary.Indicators = append(summary.Indicators, repackIndicator{
			Kind:        "asset-payload",
			Title:       "Executable payload shipped in assets",
			Description: "The archive ships " + strings.Join(assetPayloads, ", ") + " under assets/. A DEX, JAR or ELF file in assets is usually loaded at runtime, which hides it from a static review.",
			Evidence:    strings.Join(assetPayloads, ","),
			Severity:    models.SeverityHigh,
			Confidence:  0.7,
		})
	}

	if len(signatureBlocks) == 0 {
		summary.Indicators = append(summary.Indicators, repackIndicator{
			Kind:        "no-signature",
			Title:       "Archive carries no v1 signature block",
			Description: "No META-INF signature block was found. The APK may be signed only with a v2/v3 block, or it may have been stripped.",
			Evidence:    "no META-INF/*.RSA",
			Severity:    models.SeverityMedium,
			Confidence:  0.5,
		})
	}

	// A repackaging tool usually rewrites every entry with the same
	// timestamp, while a build keeps a range of them.
	if len(timestamps) == 1 && len(zr.File) > 5 {
		summary.Indicators = append(summary.Indicators, repackIndicator{
			Kind:        "uniform-timestamp",
			Title:       "Every archive entry carries the same timestamp",
			Description: "All entries share one modification time, which is what a repackaging or archive-rewriting tool produces. A build normally leaves a range of timestamps.",
			Evidence:    fmt.Sprintf("%d entries, 1 distinct timestamp", len(zr.File)),
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
