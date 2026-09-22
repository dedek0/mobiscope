package llm

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderTriagePrompt_JSONMode(t *testing.T) {
	ctx := TriageContext{
		ID:          "test-001",
		Category:    "secret",
		Title:       "AWS Key",
		Severity:    "critical",
		SourceTool:  "gitleaks",
		File:        "Config.java",
		Line:        42,
		Evidence:    "AKIAIOSFODNN7EXAMPLE",
		CodeContext: "String key = \"AKIA...\";",
	}

	prompt, err := RenderTriagePrompt(ctx, true)
	assert.NoError(t, err)
	assert.Contains(t, prompt, "test-001")
	assert.Contains(t, prompt, "secret")
	assert.Contains(t, prompt, "AWS Key")
	assert.Contains(t, prompt, "AKIAIOSFODNN7EXAMPLE")
	assert.Contains(t, prompt, "Config.java")
	assert.Contains(t, prompt, "```")
}

func TestRenderTriagePrompt_TextMode(t *testing.T) {
	ctx := TriageContext{
		ID:          "test-002",
		Category:    "code_pattern",
		Title:       "Weak Crypto",
		Severity:    "high",
		SourceTool:  "semgrep",
		File:        "Crypto.java",
		Line:        10,
		Evidence:    "MD5",
		CodeContext: "MessageDigest.getInstance(\"MD5\")",
	}

	prompt, err := RenderTriagePrompt(ctx, false)
	assert.NoError(t, err)
	assert.Contains(t, prompt, "test-002")
	assert.Contains(t, prompt, "```json")
}

func TestRenderTriagePrompt_WithManifest(t *testing.T) {
	ctx := TriageContext{
		ID:              "test-003",
		Category:        "manifest_issue",
		Title:           "Debuggable",
		Severity:        "high",
		SourceTool:      "inventory",
		File:            "AndroidManifest.xml",
		Line:            1,
		Evidence:        "android:debuggable=\"true\"",
		CodeContext:     "<application>",
		ManifestContext: "<application android:debuggable=\"true\">",
	}

	prompt, err := RenderTriagePrompt(ctx, true)
	assert.NoError(t, err)
	assert.Contains(t, prompt, "AndroidManifest")
	assert.Contains(t, prompt, "debuggable")
}

func TestTruncateContext_NoTruncation(t *testing.T) {
	code := "short code"
	result, truncated := TruncateContext(code, 1000)
	assert.Equal(t, code, result)
	assert.False(t, truncated)
}

func TestTruncateContext_Truncated(t *testing.T) {
	code := "a very long piece of code that exceeds the limit"
	result, truncated := TruncateContext(code, 20)
	assert.True(t, truncated)
	assert.LessOrEqual(t, len(result), 40) // 20 + truncation marker
	assert.Contains(t, result, "truncated")
}

func TestExtractCodeContext(t *testing.T) {
	source := "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10"
	ctx := ExtractCodeContext(source, 5, 2)
	assert.Contains(t, ctx, "line3")
	assert.Contains(t, ctx, "line5")
	assert.Contains(t, ctx, "line7")
}

func TestExtractCodeContext_StartOfFile(t *testing.T) {
	source := "line1\nline2\nline3"
	ctx := ExtractCodeContext(source, 1, 2)
	assert.Contains(t, ctx, "line1")
}

func TestExtractCodeContext_EndOfFile(t *testing.T) {
	source := "line1\nline2\nline3"
	ctx := ExtractCodeContext(source, 3, 2)
	assert.Contains(t, ctx, "line3")
}

func TestExtractJSONFromText_CodeFence(t *testing.T) {
	text := "Here is the analysis:\n```json\n{\"verdict\":\"confirmed\",\"confidence\":0.9,\"explanation\":\"test\",\"remediation\":\"fix\"}\n```"
	resp, err := extractJSONFromText(text)
	assert.NoError(t, err)
	assert.Equal(t, "confirmed", resp.Verdict)
	assert.InDelta(t, 0.9, resp.Confidence, 0.01)
}

func TestExtractJSONFromText_RawJSON(t *testing.T) {
	text := "Some text before {\"verdict\":\"likely_fp\",\"confidence\":0.7,\"explanation\":\"fp\",\"remediation\":\"none\"} and after"
	resp, err := extractJSONFromText(text)
	assert.NoError(t, err)
	assert.Equal(t, "likely_fp", resp.Verdict)
}

func TestExtractJSONFromText_Invalid(t *testing.T) {
	text := "no json here at all"
	_, err := extractJSONFromText(text)
	assert.Error(t, err)
}

func TestExtractCodeContext_OutOfRange(t *testing.T) {
	source := "line1\nline2\nline3"
	assert.Equal(t, "", ExtractCodeContext(source, 99, 2))
	assert.Equal(t, "", ExtractCodeContext(source, 0, 2))
	assert.Equal(t, "", ExtractCodeContext(source, -1, 2))
}

func TestTruncateContext_UTF8Boundary(t *testing.T) {
	s := "日本語のコードです"                        // multi-byte runes
	out, truncated := TruncateContext(s, 5) // mid-rune cut point
	assert.True(t, truncated)
	assert.True(t, strings.Contains(out, "[truncated]"))
	// Must not contain invalid UTF-8 (replacement char from a broken cut).
	assert.NotContains(t, out, "\uFFFD")
}
