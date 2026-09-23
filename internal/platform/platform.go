// Package platform detects whether an artifact is an Android APK or an
// iOS IPA. Detection reads the ZIP central directory: both formats are
// ZIP archives, so magic bytes alone cannot discriminate.
package platform

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dedek0/mobiscope/internal/models"
)

// Target describes a detected analysis artifact.
type Target struct {
	// Path is the original artifact path as given by the user.
	Path string
	// Format is the container format: "apk" or "ipa".
	Format string
	// Platform is the mobile platform the artifact targets.
	Platform models.Platform
}

// Container format names recorded in Target.Format.
const (
	FormatAPK = "apk"
	FormatIPA = "ipa"
)

// ipaAppPlistRe matches the Info.plist entry inside an IPA's Payload/<App>.app.
var ipaAppPlistRe = regexp.MustCompile(`(?i)^payload/[^/]+\.app/info\.plist$`)

// maxEntries bounds how many central-directory entries are inspected so a
// hostile archive with millions of entries cannot stall detection.
const maxEntries = 4096

// Detect inspects the ZIP central directory and returns the target platform.
// The filename extension is a tiebreaker only; content decides.
func Detect(path string) (*Target, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("not a ZIP archive: %w", err)
	}
	defer zr.Close()

	var hasManifest, hasDex, hasPayloadPlist bool
	for i, f := range zr.File {
		if i >= maxEntries {
			break
		}
		name := f.Name
		switch {
		case name == "AndroidManifest.xml" || strings.HasSuffix(name, "/AndroidManifest.xml"):
			hasManifest = true
		case strings.HasPrefix(name, "classes") && strings.HasSuffix(name, ".dex"):
			hasDex = true
		case ipaAppPlistRe.MatchString(strings.ReplaceAll(name, "\\", "/")):
			hasPayloadPlist = true
		}
	}

	ext := strings.ToLower(filepath.Ext(path))

	switch {
	case hasPayloadPlist:
		return &Target{Path: path, Format: FormatIPA, Platform: models.PlatformIOS}, nil
	case hasManifest || hasDex:
		return &Target{Path: path, Format: FormatAPK, Platform: models.PlatformAndroid}, nil
	case ext == ".ipa":
		return &Target{Path: path, Format: FormatIPA, Platform: models.PlatformIOS}, nil
	case ext == ".apk":
		return &Target{Path: path, Format: FormatAPK, Platform: models.PlatformAndroid}, nil
	default:
		return nil, fmt.Errorf("unrecognized target %q: no AndroidManifest.xml, classes*.dex or Payload/*.app/Info.plist", path)
	}
}

// DetectReader is Detect for an already-open file (used by tests).
func DetectReader(r io.ReaderAt, size int64, name string) (*Target, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("not a ZIP archive: %w", err)
	}

	var hasManifest, hasDex, hasPayloadPlist bool
	for i, f := range zr.File {
		if i >= maxEntries {
			break
		}
		n := f.Name
		switch {
		case n == "AndroidManifest.xml" || strings.HasSuffix(n, "/AndroidManifest.xml"):
			hasManifest = true
		case strings.HasPrefix(n, "classes") && strings.HasSuffix(n, ".dex"):
			hasDex = true
		case ipaAppPlistRe.MatchString(strings.ReplaceAll(n, "\\", "/")):
			hasPayloadPlist = true
		}
	}

	ext := strings.ToLower(filepath.Ext(name))
	switch {
	case hasPayloadPlist:
		return &Target{Path: name, Format: FormatIPA, Platform: models.PlatformIOS}, nil
	case hasManifest || hasDex:
		return &Target{Path: name, Format: FormatAPK, Platform: models.PlatformAndroid}, nil
	case ext == ".ipa":
		return &Target{Path: name, Format: FormatIPA, Platform: models.PlatformIOS}, nil
	case ext == ".apk":
		return &Target{Path: name, Format: FormatAPK, Platform: models.PlatformAndroid}, nil
	default:
		return nil, fmt.Errorf("unrecognized target %q", name)
	}
}

// MustExist is a convenience check that path exists and is a regular file.
func MustExist(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("artifact not found: %s: %w", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("artifact is a directory, not a file: %s", path)
	}
	return nil
}
