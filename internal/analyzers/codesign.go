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
	"howett.net/plist"
)

const (
	codesignName = "codesign"
	entName      = "entitlements.plist"
)

var entBlobRe = regexp.MustCompile(`(?s)<plist[^>]*>(.*?)</plist>`)

// CodeSign extracts entitlements and provisioning-profile signals.
//
// On Linux there is no codesign(1); we parse the entitlements blob out of
// the __LINKEDIT code-signature slot when present and decode
// embedded.mobileprovision via openssl-compatible CMS/PKCS#7 wrapping (the
// payload is a plain plist).
type CodeSign struct {
	runner CommandRunner
}

func NewCodeSign() *CodeSign {
	return &CodeSign{runner: &DefaultCommandRunner{}}
}

func NewCodeSignWithRunner(runner CommandRunner) *CodeSign {
	return &CodeSign{runner: runner}
}

func (c *CodeSign) Name() string { return codesignName }

// Available is satisfied in-process; ldid/codesign are used opportunistically
// when present but never required.
func (c *CodeSign) Available() error { return nil }

func (c *CodeSign) Run(_ context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  c.Name(),
		Version:   toolVersion,
		StartedAt: start,
	}

	bundle := appBundleDir(workdir)
	if bundle == "" {
		result.Duration = time.Since(start)
		return result, fmt.Errorf("app bundle not found under %s", IPAExtractArtifactPath(workdir))
	}

	entitlements := map[string]interface{}{}
	// Prefer the entitlements file extracted next to the binary; fall back to
	// scanning for an embedded.plist-shaped blob.
	for _, cand := range []string{entName, "Entitlements.plist"} {
		p := filepath.Join(bundle, cand)
		if m, err := readPlist(p); err == nil {
			entitlements = m
			break
		}
	}
	if len(entitlements) == 0 {
		// Try to locate a plist inside the code signature slot by scanning
		// the main executable for an <plist>…</plist> block.
		infoMap, _ := readPlist(filepath.Join(bundle, "Info.plist"))
		if exe := strOr(infoMap["CFBundleExecutable"]); exe != "" {
			if data, err := os.ReadFile(filepath.Join(bundle, exe)); err == nil { //nolint:gosec
				if m := extractPlistFromBytes(data); len(m) > 0 {
					entitlements = m
				}
			}
		}
	}

	profile := map[string]interface{}{}
	profPath := filepath.Join(bundle, "embedded.mobileprovision")
	if data, err := os.ReadFile(profPath); err == nil { //nolint:gosec
		// The CMS wrapper is binary; the inner plist is still greppable.
		if m := extractPlistFromBytes(data); len(m) > 0 {
			profile = m
		}
	}

	raw, _ := json.Marshal(map[string]interface{}{
		"entitlements":        entitlements,
		"provisioning":        profile,
		"has_mobileprovision": fileExists(profPath),
	})
	result.Output = raw
	result.Duration = time.Since(start)
	return result, nil
}

// codesignOutput is the JSON shape written by CodeSign.Run.
type codesignOutput struct {
	Entitlements map[string]interface{} `json:"entitlements"`
	Provisioning map[string]interface{} `json:"provisioning"`
}

// ConvertCodeSignFindings turns entitlements/provisioning into findings.
func ConvertCodeSignFindings(raw []byte, sessionID string) []models.Finding {
	var out codesignOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}

	var findings []models.Finding
	add := func(title, desc, snippet string, sev models.Severity, sens models.Sensitivity, conf float64) {
		f := iosFinding(codesignName, models.CategoryEntitlement, entName, snippet, title, desc, sev, sens, conf)
		findings = append(findings, withSession(f, sessionID))
	}

	if boolOr(out.Entitlements["get-task-allow"]) {
		add("Debug entitlement: get-task-allow",
			"get-task-allow=true marks a debug build; on a production device it allows any process to attach a debugger and read memory.",
			"get-task-allow=true", models.SeverityCritical, models.SensitivityConfidential, 1.0)
	}
	if boolOr(out.Entitlements["task_for_pid-allow"]) {
		add("Dangerous entitlement: task_for_pid-allow",
			"task_for_pid-allow permits obtaining task ports for other processes (full process introspection).",
			"task_for_pid-allow=true", models.SeverityCritical, models.SensitivityConfidential, 1.0)
	}
	if boolOr(out.Entitlements["com.apple.security.cs.disable-library-validation"]) {
		add("Library validation disabled",
			"com.apple.security.cs.disable-library-validation=true lets the process load unsigned/other-team dylibs (dylib injection).",
			"com.apple.security.cs.disable-library-validation", models.SeverityHigh, models.SensitivityConfidential, 0.95)
	}
	if boolOr(out.Entitlements["com.apple.security.cs.allow-dyld-environment-variables"]) {
		add("DYLD environment variables allowed",
			"com.apple.security.cs.allow-dyld-environment-variables=true enables dyld injection vectors.",
			"com.apple.security.cs.allow-dyld-environment-variables", models.SeverityHigh, models.SensitivityConfidential, 0.9)
	}
	for k := range out.Entitlements {
		if strings.HasPrefix(k, "com.apple.private.") {
			add("Private entitlement: "+k,
				fmt.Sprintf("Entitlement %q is a private Apple entitlement; requesting it is unsupported and can expose privileged APIs.", k),
				k, models.SeverityHigh, models.SensitivityConfidential, 0.8)
		}
	}
	if env, ok := out.Entitlements["aps-environment"].(string); ok && env == "development" {
		add("APNs environment is development",
			"aps-environment=development in a shipped build means push tokens are sandboxed and the build was not production-signed.",
			"aps-environment=development", models.SeverityLow, models.SensitivityInternal, 0.7)
	}

	return findings
}

// extractPlistFromBytes returns the first embedded plist dictionary found in b.
func extractPlistFromBytes(b []byte) map[string]interface{} {
	loc := entBlobRe.FindSubmatch(b)
	if loc == nil {
		return nil
	}
	body := loc[0]
	var out interface{}
	if _, err := plist.Unmarshal(body, &out); err == nil {
		if m, ok := out.(map[string]interface{}); ok {
			return m
		}
	}
	// Some builds store the plist with a binary header; strip leading junk.
	if idx := strings.Index(string(body), "<plist"); idx >= 0 {
		var out2 interface{}
		if _, err := plist.Unmarshal(body[idx:], &out2); err == nil {
			if m, ok := out2.(map[string]interface{}); ok {
				return m
			}
		}
	}
	return nil
}
