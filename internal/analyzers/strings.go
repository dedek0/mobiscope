package analyzers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

const (
	stringsName = "strings"
	stringsTool = "llvm-strings"
	stringsBin  = "strings"
	stringsTo   = 2 * time.Minute
)

// Strings runs secret/pinning regexes over the binary's printable strings.
// The heavy lifting is done in-process; llvm-strings/strings is optional.
type Strings struct {
	runner CommandRunner
}

func NewStrings() *Strings {
	return &Strings{runner: &DefaultCommandRunner{}}
}

func NewStringsWithRunner(runner CommandRunner) *Strings {
	return &Strings{runner: runner}
}

func (s *Strings) Name() string { return stringsName }

func (s *Strings) Available() error {
	if err := CheckBinary(stringsTool); err == nil {
		return nil
	}
	return CheckBinary(stringsBin)
}

func (s *Strings) Run(_ context.Context, target string, workdir string) (models.ToolResult, error) {
	start := time.Now()
	result := models.ToolResult{
		ToolName:  s.Name(),
		Version:   toolVersion,
		StartedAt: start,
	}

	root := iosSourceRoot(workdir)
	var all []string
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxScanFileSize*8 {
			return nil
		}
		// Only binaries and text-y resources.
		if !isIOSCodeFile(path) && !isLikelyMachO(path, filepath.Base(path)) {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		strs := extractPrintable(data)
		for _, st := range strs {
			all = append(all, rel+"\x00"+st)
		}
		return nil
	})

	raw, _ := json.Marshal(map[string]interface{}{
		"root":    root,
		"strings": all,
	})
	result.Output = raw
	result.Duration = time.Since(start)
	return result, nil
}

// stringsOutput is the JSON shape written by Strings.Run.
type stringsOutput struct {
	Strings []string `json:"strings"`
}

// ConvertStringsFindings runs the shared secret/pinning regexes over the
// extracted strings.
func ConvertStringsFindings(raw []byte, sessionID string) []models.Finding {
	var out stringsOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}

	var findings []models.Finding
	for _, entry := range out.Strings {
		parts := strings.SplitN(entry, "\x00", 2)
		if len(parts) != 2 {
			continue
		}
		file, text := parts[0], parts[1]
		for _, rule := range scanRules {
			if !rule.Re.MatchString(text) {
				continue
			}
			f := iosFinding(stringsName, rule.Category, file, text,
				rule.Name,
				fmt.Sprintf("Pattern match for %s in %s strings", rule.Name, file),
				rule.Severity, rule.Sensitivity, 0.7)
			findings = append(findings, withSession(f, sessionID))
		}
	}
	return findings
}

// extractPrintable returns runs of at least 4 printable characters.
func extractPrintable(b []byte) []string {
	var out []string
	var cur []byte
	flush := func() {
		if len(cur) >= 4 {
			out = append(out, string(cur))
		}
		cur = cur[:0]
	}
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			cur = append(cur, c)
		} else {
			flush()
		}
		if len(out) >= 5000 {
			return out
		}
	}
	flush()
	return out
}
