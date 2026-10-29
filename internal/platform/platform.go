// Package platform detects whether an artifact is an Android APK or an
// iOS IPA. Detection reads the ZIP central directory: both formats are
// ZIP archives, so magic bytes alone cannot discriminate.
package platform

import (
	"archive/zip"
	"encoding/binary"
	"errors"
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
	// Confidence is "high" when the content was decisive, "low" when only
	// the file extension decided.
	Confidence string
}

// Container format names recorded in Target.Format.
const (
	FormatAPK = "apk"
	FormatIPA = "ipa"
)

// Detection confidence values.
const (
	ConfidenceHigh = "high"
	ConfidenceLow  = "low"
)

// ipaAppPlistRe matches the Info.plist entry inside an IPA's Payload/<App>.app.
var ipaAppPlistRe = regexp.MustCompile(`(?i)^payload/[^/]+\.app/info\.plist$`)

// ipaAppDirRe matches a bundle directory inside an IPA's Payload.
var ipaAppDirRe = regexp.MustCompile(`(?i)^payload/[^/]+\.app/$`)

// maxEntries bounds how many central-directory entries are inspected so a
// hostile archive with millions of entries cannot stall detection.
const maxEntries = 200000

// maxCentralDirBytes bounds the size of the ZIP central directory we are
// willing to parse. A crafted archive can declare millions of entries; the
// directory is materialised in memory by archive/zip, so the count has to be
// checked before opening the archive.
const maxCentralDirBytes = 64 << 20

// eocdLen is the size of the ZIP end-of-central-directory record without a
// comment.
const eocdLen = 22

// eocdSignature is the ZIP end-of-central-directory record magic.
const eocdSignature = 0x06054b50

// Detect inspects the ZIP central directory and returns the target platform.
// The filename extension is a tiebreaker only; content decides.
func Detect(path string) (*Target, error) {
	if err := checkArchiveSize(path); err != nil {
		return nil, err
	}
	f, err := os.Open(path) //nolint:gosec // G304: the path is supplied by the operator
	if err != nil {
		return nil, fmt.Errorf("opening artifact: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat artifact: %w", err)
	}
	return detect(f, info.Size(), path)
}

// DetectReader is Detect for an already-open file (used by tests).
func DetectReader(r io.ReaderAt, size int64, name string) (*Target, error) {
	return detect(r, size, name)
}

// detect scores the archive content against both platform hypotheses and
// picks the stronger one. Scoring (rather than a precedence switch) keeps a
// crafted APK that carries a Payload/*.app/Info.plist entry from being
// misrouted to the iOS toolchain.
func detect(r io.ReaderAt, size int64, name string) (*Target, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("not a ZIP archive: %w", err)
	}

	apkScore, ipaScore := scoreEntries(zr)

	ext := strings.ToLower(filepath.Ext(name))

	switch {
	case apkScore > ipaScore:
		return &Target{Path: name, Format: FormatAPK, Platform: models.PlatformAndroid, Confidence: ConfidenceHigh}, nil
	case ipaScore > apkScore:
		return &Target{Path: name, Format: FormatIPA, Platform: models.PlatformIOS, Confidence: ConfidenceHigh}, nil
	}

	// No decisive content: fall back to the extension and say so.
	switch ext {
	case ".ipa":
		return &Target{Path: name, Format: FormatIPA, Platform: models.PlatformIOS, Confidence: ConfidenceLow}, nil
	case ".apk":
		return &Target{Path: name, Format: FormatAPK, Platform: models.PlatformAndroid, Confidence: ConfidenceLow}, nil
	default:
		return nil, fmt.Errorf("unrecognized target %q: no AndroidManifest.xml, classes*.dex or Payload/*.app/Info.plist", name)
	}
}

// scoreEntries weighs the central-directory entries against the Android and
// iOS layouts and returns both scores.
func scoreEntries(zr *zip.Reader) (apk, ios int) {
	entries := zr.File
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}

	for _, f := range entries {
		entry := strings.ReplaceAll(f.Name, "\\", "/")
		switch {
		case entry == "AndroidManifest.xml":
			apk += 3
		case entry == "classes.dex" || (strings.HasPrefix(entry, "classes") && strings.HasSuffix(entry, ".dex")):
			apk += 2
		case entry == "resources.arsc":
			apk += 1
		case strings.HasPrefix(entry, "lib/") && strings.HasSuffix(entry, ".so"):
			apk++
		case ipaAppPlistRe.MatchString(entry):
			ios += 3
		case ipaAppDirRe.MatchString(entry):
			ios += 1
		case strings.HasPrefix(entry, "Payload/") && strings.HasSuffix(entry, "/Info.plist"):
			ios++
		case strings.HasPrefix(entry, "_CodeSignature/"), strings.HasPrefix(entry, "SwiftSupport/"):
			ios++
		}
	}
	return apk, ios
}

// checkArchiveSize rejects archives whose central directory is implausibly
// large before archive/zip materialises it in memory.
func checkArchiveSize(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("artifact not found: %s: %w", path, err)
	}
	if info.Size() < eocdLen {
		return fmt.Errorf("not a ZIP archive: %s: file too small", path)
	}

	f, err := os.Open(path) //nolint:gosec // G304: the path is supplied by the operator
	if err != nil {
		return fmt.Errorf("opening artifact: %w", err)
	}
	defer f.Close()

	// The end-of-central-directory record lives in the last 64 KiB (the
	// comment field may be up to 64 KiB long).
	const tailLen = 64 << 10
	tailSize := int64(tailLen)
	if info.Size() < tailSize {
		tailSize = info.Size()
	}
	tail := make([]byte, tailSize)
	if _, err := f.ReadAt(tail, info.Size()-tailSize); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("reading artifact tail: %w", err)
	}

	idx := lastEOCD(tail)
	if idx < 0 {
		// No EOCD: let archive/zip produce the canonical error message.
		return nil
	}

	// Offset 10 holds the total number of entries in the central directory.
	total := binary.LittleEndian.Uint16(tail[idx+10:])
	cdSize := binary.LittleEndian.Uint32(tail[idx+12:])
	if int64(cdSize) > maxCentralDirBytes {
		return fmt.Errorf("archive central directory too large: %d bytes", cdSize)
	}
	if int(total) > maxEntries*4 {
		return fmt.Errorf("archive declares %d entries, refusing to parse", total)
	}
	return nil
}

// lastEOCD returns the index of the end-of-central-directory record inside
// buf, or -1 when there is none.
func lastEOCD(buf []byte) int {
	for i := len(buf) - eocdLen; i >= 0; i-- {
		if binary.LittleEndian.Uint32(buf[i:]) == eocdSignature {
			return i
		}
	}
	return -1
}

// MustExist is a convenience check that path exists and is a regular file.
func MustExist(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("artifact not found: %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("artifact is a symlink, refusing to follow: %s", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("artifact is not a regular file: %s", path)
	}
	return nil
}
