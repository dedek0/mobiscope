package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Sha256File computes the SHA-256 hex digest of the file at path.
func Sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("opening file for hash: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("reading file for hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// EnsureDir creates the directory (and parents) if it does not exist.
func EnsureDir(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("creating directory %s: %w", path, err)
	}
	return nil
}

// SafeRmtree removes the directory tree at path if it exists, refusing to
// touch anything outside root. root and path are resolved through symlinks
// before the check so a symlinked path cannot escape the jail.
func SafeRmtree(root, path string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolving root %s: %w", root, err)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolving path %s: %w", path, err)
	}
	if resolved, err := filepath.EvalSymlinks(absRoot); err == nil {
		absRoot = resolved
	}
	if resolved, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = resolved
	}

	if absPath == absRoot {
		// Allow removing the root itself only when it is a dedicated temp-like
		// directory (at least two path segments and not a filesystem root).
		if absPath == string(os.PathSeparator) || filepath.Dir(absPath) == absPath {
			return fmt.Errorf("refusing to remove filesystem root %s", absPath)
		}
	} else if !strings.HasPrefix(absPath, absRoot+string(os.PathSeparator)) {
		return fmt.Errorf("refusing to remove %s: outside root %s", absPath, absRoot)
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil
	}
	if err := os.RemoveAll(absPath); err != nil {
		return fmt.Errorf("removing tree %s: %w", absPath, err)
	}
	return nil
}

// HumanSize returns a human-readable representation of a byte count.
func HumanSize(bytes int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)

	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// DirSize returns the total size in bytes of all files under dir (non-recursive symlink).
func DirSize(dir string) (int64, error) {
	var total int64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

// Exists returns true if path exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsDirEmpty returns true if dir exists and contains no entries.
func IsDirEmpty(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, fmt.Errorf("reading directory %s: %w", dir, err)
	}
	return len(entries) == 0, nil
}

// NormalizePath returns a cleaned absolute path.
func NormalizePath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("resolving path %s: %w", p, err)
	}
	return filepath.Clean(abs), nil
}

// SanitizeFilename replaces path separators, traversal segments and other
// problematic chars so the result is safe to use as a single path component.
func SanitizeFilename(name string) string {
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		"\x00", "_",
	)
	name = replacer.Replace(name)
	// Strip control characters (including newlines).
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, name)
	// Collapse traversal segments and leading dots.
	name = strings.ReplaceAll(name, "..", "_")
	name = strings.Trim(name, ".")
	if name == "" {
		return "_"
	}
	return name
}

// WriteFile writes data to path, creating parent directories as needed.
// Files are written 0600 because analysis artifacts may contain secrets.
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := EnsureDir(dir); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec
		return fmt.Errorf("writing file %s: %w", path, err)
	}
	return nil
}
