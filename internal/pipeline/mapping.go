package pipeline

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/dedek0/mobiscope/internal/models"
)

// maxMappingBytes caps the R8/ProGuard mapping file read. Real mappings are
// a few megabytes; anything larger is refused rather than loaded whole.
const maxMappingBytes = 64 << 20

// Mapping is a reverse R8/ProGuard map: obfuscated class name → original
// class name. Methods and fields are ignored because findings are located by
// class/file, not by member.
type Mapping struct {
	classes map[string]string
	// keys holds the obfuscated names sorted longest-first, so a nested
	// class wins over its outer class when both match a path suffix.
	keys []string
}

// LoadMapping parses an R8/ProGuard mapping.txt.
func LoadMapping(file string) (*Mapping, error) {
	info, err := os.Stat(file)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxMappingBytes {
		return nil, fmt.Errorf("mapping file too large: %d bytes", info.Size())
	}
	data, err := os.ReadFile(file) //nolint:gosec // explicit operator-supplied mapping path
	if err != nil {
		return nil, err
	}

	m := &Mapping{classes: map[string]string{}}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		// Class lines are unindented and look like:
		//   com.example.Foo -> a.a:
		// Member lines are indented and contain a return type/signature.
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		parts := strings.SplitN(line, " -> ", 2)
		if len(parts) != 2 {
			continue
		}
		original := strings.TrimSpace(parts[0])
		obfuscated := strings.TrimSuffix(strings.TrimSpace(parts[1]), ":")
		if original == "" || obfuscated == "" {
			continue
		}
		if _, exists := m.classes[obfuscated]; !exists {
			m.classes[obfuscated] = original
		}
	}
	if len(m.classes) == 0 {
		return nil, fmt.Errorf("no class mappings found in %s", file)
	}
	m.keys = make([]string, 0, len(m.classes))
	for obf := range m.classes {
		m.keys = append(m.keys, obf)
	}
	sort.Slice(m.keys, func(i, j int) bool {
		if len(m.keys[i]) != len(m.keys[j]) {
			return len(m.keys[i]) > len(m.keys[j])
		}
		return m.keys[i] < m.keys[j]
	})
	return m, nil
}

// RewriteFindings replaces obfuscated class paths in finding locations with
// the original names. It returns how many findings were rewritten.
func (m *Mapping) RewriteFindings(findings []models.Finding) int {
	if m == nil {
		return 0
	}
	rewritten := 0
	for i := range findings {
		file := findings[i].Location.File
		if file == "" {
			continue
		}
		if next, ok := m.rewritePath(file); ok {
			findings[i].Location.File = next
			findings[i].Evidence = m.rewriteText(findings[i].Evidence)
			findings[i].Description = m.rewriteText(findings[i].Description)
			rewritten++
		}
	}
	return rewritten
}

// rewritePath maps an obfuscated class path suffix to the original package.
func (m *Mapping) rewritePath(file string) (string, bool) {
	p := strings.ReplaceAll(file, "\\", "/")
	ext := path.Ext(p)
	stem := strings.TrimSuffix(p, ext)

	for _, obf := range m.keys {
		obfPath := strings.ReplaceAll(obf, ".", "/")
		if !strings.HasSuffix(stem, obfPath) {
			continue
		}
		// Avoid matching "aa/b" inside "xaa/b": the suffix must start at a
		// path segment boundary.
		prefix := strings.TrimSuffix(stem, obfPath)
		if prefix != "" && !strings.HasSuffix(prefix, "/") {
			continue
		}
		original := strings.ReplaceAll(m.classes[obf], ".", "/")
		return prefix + original + ext, true
	}
	return file, false
}

// rewriteText replaces obfuscated class names in free text (description,
// evidence) with their original names.
func (m *Mapping) rewriteText(text string) string {
	if text == "" || m == nil {
		return text
	}
	for _, obf := range m.keys {
		original := m.classes[obf]
		text = strings.ReplaceAll(text, obf, original)
		text = strings.ReplaceAll(text, strings.ReplaceAll(obf, ".", "/"), strings.ReplaceAll(original, ".", "/"))
	}
	return text
}
