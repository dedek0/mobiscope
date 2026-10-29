package analyzers

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxToolReportBytes bounds how much of an external tool's report file is
// read into memory. A scanner can emit a report with millions of entries;
// the artifact stays on disk and is truncated on read.
const maxToolReportBytes = 64 << 20

// maxManifestBytes bounds the size of a manifest, plist or other small
// configuration file that is read whole. Anything larger is refused rather
// than loaded.
const maxManifestBytes = 16 << 20

// readFileCapped reads a file, refusing to load more than limit bytes. The
// file is read in chunks so a huge file never lands in memory whole.
func readFileCapped(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file: %s", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file too large: %s (%d bytes > %d)", path, info.Size(), limit)
	}

	f, err := os.Open(path) //nolint:gosec // G304: the path is derived from the session workdir
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(io.LimitReader(f, limit))
}

// safeJoinPath joins a base directory with a name taken from untrusted
// content and guarantees the result stays inside base. It is the guard for
// paths that come out of an Info.plist or a manifest.
func safeJoinPath(base, name string) (string, error) {
	clean := strings.TrimSpace(name)
	if clean == "" {
		return "", fmt.Errorf("empty path component")
	}
	// Reject anything that is not a plain file name inside the base.
	if filepath.Base(clean) != clean || clean == "." || clean == ".." {
		return "", fmt.Errorf("path component escapes the base directory: %q", name)
	}
	joined := filepath.Join(base, clean)
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	if absJoined != absBase && !strings.HasPrefix(absJoined, absBase+string(os.PathSeparator)) {
		return "", fmt.Errorf("path escapes the base directory: %q", name)
	}
	return joined, nil
}
