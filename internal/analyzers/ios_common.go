package analyzers

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/dedek0/mobiscope/internal/models"
)

// toolVersion is stamped on every in-process analyzer ToolResult.
const (
	toolVersion    = "1.0.0"
	unknownVersion = "unknown"
)

// IPAExtractArtifactPath is where ipa-extract unpacks the Payload/<App>.app tree.
func IPAExtractArtifactPath(workdir string) string {
	return filepath.Join(workdir, "extract")
}

// appBundleDir returns the path to Payload/<Something>.app under an extracted
// IPA. Returns "" when the bundle cannot be located.
func appBundleDir(workdir string) string {
	payload := filepath.Join(IPAExtractArtifactPath(workdir), "Payload")
	entries, err := os.ReadDir(payload)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".app") {
			return filepath.Join(payload, e.Name())
		}
	}
	return ""
}

// iosSourceRoot is the directory scanned for iOS code/secrets: the extracted
// app bundle if present, else the workdir.
func iosSourceRoot(workdir string) string {
	if dir := appBundleDir(workdir); dir != "" {
		return dir
	}
	if dir := IPAExtractArtifactPath(workdir); dirExists(dir) {
		return dir
	}
	return workdir
}

// iosCodeExts are the source/resource extensions scanned for patterns on iOS.
var iosCodeExts = map[string]bool{
	".swift": true, ".m": true, ".h": true, ".mm": true,
	".plist": true, ".strings": true, ".json": true,
	".js": true, ".html": true, ".xml": true,
}

// isIOSCodeFile reports whether path is scanned for patterns on iOS.
func isIOSCodeFile(path string) bool {
	return iosCodeExts[strings.ToLower(filepath.Ext(path))]
}

// iosFinding builds a Finding tagged for iOS at line 1 of the named file.
func iosFinding(tool string, cat models.Category, file, snippet, title, desc string, sev models.Severity, sens models.Sensitivity, conf float64) models.Finding {
	return models.Finding{
		ID:          models.GenerateID(tool, cat, file, 1, snippet),
		SourceTool:  tool,
		Category:    cat,
		Platform:    models.PlatformIOS,
		Title:       title,
		Description: desc,
		Evidence:    snippet,
		Location:    models.Location{File: file, Line: 1, Snippet: snippet},
		Severity:    sev,
		Sensitivity: sens,
		Confidence:  conf,
	}
}

// withSession is a tiny helper so iOS analyzers can set SessionID uniformly.
func withSession(f models.Finding, sessionID string) models.Finding {
	f.SessionID = sessionID
	return f
}
