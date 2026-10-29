// Package rules embeds the semgrep rule packs that ship with mobiscope.
//
// The packs used to live in a `rules/` directory at the repository root and
// were referenced by a path relative to the process working directory. That
// broke every installed binary that was not run from a checkout. Embedding
// them makes the tool self-contained; a custom pack can still be passed with
// `--rules`.
package rules

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

//go:embed mastg/rules.yaml
var mastgYAML []byte

//go:embed mastg-ios/rules.yaml
var mastgIOSYAML []byte

// Pack identifies an embedded rule pack.
type Pack string

const (
	// PackAndroid is the MASTG-derived pack for Android/Java sources.
	PackAndroid Pack = "android"
	// PackIOS is the MASTG-derived pack for Swift/Objective-C sources.
	PackIOS Pack = "ios"
)

var (
	materializeOnce sync.Once
	materializeDir  string
	materializeErr  error
)

// Materialize writes the embedded rule packs to a temporary directory and
// returns the path of the requested pack. Semgrep needs a real path on disk,
// so the embedded bytes are extracted once per process.
func Materialize(p Pack) (string, error) {
	materializeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "mobiscope-rules-")
		if err != nil {
			materializeErr = fmt.Errorf("creating rules directory: %w", err)
			return
		}
		materializeDir = dir
		for name, data := range map[string][]byte{
			"mastg/rules.yaml":     mastgYAML,
			"mastg-ios/rules.yaml": mastgIOSYAML,
		} {
			path := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				materializeErr = fmt.Errorf("creating rules directory: %w", err)
				return
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				materializeErr = fmt.Errorf("writing rule pack %s: %w", name, err)
				return
			}
		}
	})
	if materializeErr != nil {
		return "", materializeErr
	}

	switch p {
	case PackAndroid:
		return filepath.Join(materializeDir, "mastg", "rules.yaml"), nil
	case PackIOS:
		return filepath.Join(materializeDir, "mastg-ios", "rules.yaml"), nil
	default:
		return "", fmt.Errorf("unknown rule pack %q", p)
	}
}

// Cleanup removes the temporary directory holding the materialized packs.
func Cleanup() {
	if materializeDir != "" {
		_ = os.RemoveAll(materializeDir)
		materializeDir = ""
	}
}

// AndroidYAML returns the embedded Android pack bytes.
func AndroidYAML() []byte { return mastgYAML }

// IOSYAML returns the embedded iOS pack bytes.
func IOSYAML() []byte { return mastgIOSYAML }
