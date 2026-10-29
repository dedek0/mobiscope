package llm

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"
	"text/template"
	"unicode/utf8"
)

//go:embed prompts/triage_json.txt
var triageJSONTemplate string

//go:embed prompts/triage_text.txt
var triageTextTemplate string

// TriageContext holds the data injected into triage prompt templates.
//
// Every field that carries application content is untrusted: the file name,
// the evidence, the code excerpt and the platform configuration all come
// from the artifact under analysis. The renderer escapes them before they
// reach the template.
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
	// Fence is the nonce that opens and closes the untrusted-data block.
	// It is generated per request so a payload cannot close the fence by
	// reproducing a literal tag.
	Fence string
}

// RenderTriagePrompt renders the appropriate triage prompt based on JSON mode support.
//
// The untrusted content is escaped and wrapped in a per-request fence. A
// hostile APK that embeds the closing tag in its source can no longer break
// out of the evidence block.
func RenderTriagePrompt(ctx TriageContext, jsonMode bool) (string, error) {
	tmplStr := triageJSONTemplate
	if !jsonMode {
		tmplStr = triageTextTemplate
	}

	if ctx.Fence == "" {
		fence, err := NewFence()
		if err != nil {
			return "", err
		}
		ctx.Fence = fence
	}

	// The untrusted values are escaped before the template sees them, so
	// the template can interpolate them verbatim.
	ctx.ID = EscapeUntrusted(ctx.ID)
	ctx.Category = EscapeUntrusted(ctx.Category)
	ctx.Title = EscapeUntrusted(ctx.Title)
	ctx.Severity = EscapeUntrusted(ctx.Severity)
	ctx.SourceTool = EscapeUntrusted(ctx.SourceTool)
	ctx.File = EscapeUntrusted(ctx.File)
	ctx.Evidence = EscapeUntrusted(ctx.Evidence)
	ctx.CodeContext = EscapeUntrusted(ctx.CodeContext)
	ctx.ManifestContext = EscapeUntrusted(ctx.ManifestContext)

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

// NewFence returns a random token used to delimit the untrusted block of a
// prompt.
func NewFence() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating prompt fence: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// untrustedReplacements neutralises the sequences that would let application
// content escape the evidence block or impersonate the prompt structure.
var untrustedReplacements = []struct {
	from string
	to   string
}{
	{"</untrusted_data>", "&lt;/untrusted_data&gt;"},
	{"<untrusted_data>", "&lt;untrusted_data&gt;"},
	{"</system>", "&lt;/system&gt;"},
	{"<system>", "&lt;system&gt;"},
	{"</user>", "&lt;/user&gt;"},
	{"</assistant>", "&lt;/assistant&gt;"},
	{"</instructions>", "&lt;/instructions&gt;"},
	{"```", "'''"},
	{"<|im_start|>", "&lt;|im_start|&gt;"},
	{"<|im_end|>", "&lt;|im_end|&gt;"},
	{"<|endoftext|>", "&lt;|endoftext|&gt;"},
}

// EscapeUntrusted neutralises the delimiters an untrusted payload could use
// to break out of the evidence block or to forge a prompt role marker.
func EscapeUntrusted(s string) string {
	for _, r := range untrustedReplacements {
		s = strings.ReplaceAll(s, r.from, r.to)
	}
	return s
}

// TruncateContext truncates code context to fit within maxChars and never
// splits a UTF-8 rune.
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
