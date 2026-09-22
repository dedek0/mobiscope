package llm

import (
	_ "embed"
	"strings"
	"text/template"
	"unicode/utf8"
)

//go:embed prompts/triage_json.txt
var triageJSONTemplate string

//go:embed prompts/triage_text.txt
var triageTextTemplate string

// TriageContext holds the data injected into triage prompt templates.
type TriageContext struct {
	ID              string
	Category        string
	Title           string
	Severity        string
	SourceTool      string
	File            string
	Line            int
	Evidence        string
	CodeContext     string
	ManifestContext string
}

// RenderTriagePrompt renders the appropriate triage prompt based on JSON mode support.
func RenderTriagePrompt(ctx TriageContext, jsonMode bool) (string, error) {
	tmplStr := triageJSONTemplate
	if !jsonMode {
		tmplStr = triageTextTemplate
	}

	tmpl, err := template.New("triage").Parse(tmplStr)
	if err != nil {
		return "", err
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// TruncateContext truncates code context to fit within maxChars, keeping
// the relevant line centered and never splitting a UTF-8 rune.
func TruncateContext(code string, maxChars int) (string, bool) {
	if len(code) <= maxChars {
		return code, false
	}
	cut := maxChars
	for cut > 0 && !utf8.RuneStart(code[cut]) {
		cut--
	}
	return code[:cut] + "\n... [truncated]", true
}
