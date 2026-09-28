package pipeline

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/dedek0/mobiscope/internal/analyzers"
	"github.com/dedek0/mobiscope/internal/llm"
	"github.com/dedek0/mobiscope/internal/models"
)

// triageContextFileCap bounds how much of one file is read into the triage
// code context map (the per-finding excerpt is truncated separately).
const triageContextFileCap = 512 << 10

// BuildTriageContext assembles the code and platform context used by the LLM
// triage prompts.
//
//   - codeContext maps each finding's file to its source, so the model sees
//     real code around the hit instead of only the snippet.
//   - manifestContext is an excerpt of the app's configuration manifest
//     (AndroidManifest.xml or Info.plist + entitlements) so configuration
//     findings can be reasoned about in context.
//
// Either result may be empty; the prompts degrade gracefully.
func BuildTriageContext(workdir string, plat models.Platform, findings []models.Finding) (map[string]string, string) {
	codeCtx := buildCodeContext(workdir, plat, findings)
	manifestCtx := buildManifestContext(workdir, plat)
	return codeCtx, manifestCtx
}

// TriageConfigFor assembles an llm.TriageConfig carrying the manifest excerpt.
func TriageConfigFor(workdir string, plat models.Platform, findings []models.Finding) (map[string]string, llm.TriageConfig) {
	codeCtx, manifest := BuildTriageContext(workdir, plat, findings)
	cfg := llm.DefaultTriageConfig()
	cfg.ManifestContext = truncateRunes(manifest, cfg.MaxContextChars)
	return codeCtx, cfg
}

func buildManifestContext(workdir string, plat models.Platform) string {
	var b strings.Builder

	if plat == models.PlatformIOS {
		if bundle := analyzers.AppBundleDir(workdir); bundle != "" {
			appendFile(&b, filepath.Join(bundle, "Info.plist"))
			for _, name := range []string{"entitlements.plist", "Entitlements.plist"} {
				appendFile(&b, filepath.Join(bundle, name))
			}
		}
		return b.String()
	}

	// Android: the decoded manifest and, when present, the network security
	// config referenced from it.
	manifestPath := filepath.Join(workdir, "jadx", "AndroidManifest.xml")
	if !fileExists(manifestPath) {
		manifestPath = filepath.Join(workdir, "AndroidManifest.xml")
	}
	appendFile(&b, manifestPath)

	for _, cand := range []string{
		filepath.Join(workdir, "jadx", "res", "xml", "network_security_config.xml"),
		filepath.Join(workdir, "res", "xml", "network_security_config.xml"),
	} {
		if fileExists(cand) {
			appendFile(&b, cand)
			break
		}
	}
	return b.String()
}

func buildCodeContext(workdir string, plat models.Platform, findings []models.Finding) map[string]string {
	root := sourceRoot(workdir, plat)
	if root == "" {
		return nil
	}

	// Only the files referenced by findings, to keep the map small.
	wanted := map[string]bool{}
	for _, f := range findings {
		if f.Location.File != "" {
			wanted[filepath.Base(f.Location.File)] = true
		}
	}
	if len(wanted) == 0 {
		return nil
	}

	out := map[string]string{}
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !wanted[d.Name()] {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if _, ok := out[rel]; ok {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec
		if err != nil {
			return nil
		}
		if len(data) > triageContextFileCap {
			data = data[:triageContextFileCap]
		}
		out[rel] = string(data)
		return nil
	})
	return out
}

func sourceRoot(workdir string, plat models.Platform) string {
	if plat == models.PlatformIOS {
		return iosRoot(workdir)
	}
	jadxDir := analyzers.JADXArtifactPath(workdir)
	if fileExists(jadxDir) || dirExists(jadxDir) {
		return jadxDir
	}
	return workdir
}

func iosRoot(workdir string) string {
	extract := filepath.Join(workdir, "extract")
	if dirExists(extract) {
		return extract
	}
	return workdir
}

func appendFile(b *strings.Builder, path string) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return
	}
	if len(data) > triageContextFileCap {
		data = data[:triageContextFileCap]
	}
	b.WriteString("===== " + filepath.Base(path) + " =====\n")
	b.Write(data)
	b.WriteString("\n")
}

func truncateRunes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n... [truncated]"
}

func isRuneStart(b byte) bool {
	return b&0xC0 != 0x80
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
