package llm

import (
	"regexp"
	"strings"
)

// triageContextLines is how many lines around the finding are sent to the
// model. The excerpt is centred on the offending line so the model sees the
// code that triggered the finding.
const triageContextLines = 40

// secretPatterns match the shapes of credentials that must not leave the
// machine. They are deliberately conservative: a false positive only costs a
// masked placeholder in the prompt.
var secretPatterns = []*regexp.Regexp{
	// AWS access key id.
	regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`),
	// Google API key.
	regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
	// GitHub token.
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),
	// Slack token.
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
	// JSON web token.
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
	// PEM private key block. The END marker is optional: the BEGIN
	// marker alone already identifies a key block.
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----)?`),
	// Azure storage key inside a connection string.
	regexp.MustCompile(`(AccountKey=)[A-Za-z0-9+/=]{40,}`),
	// Generic assignment of a secret-looking value.
	regexp.MustCompile(`(?i)\b(api[_-]?key|apikey|secret[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|password|passwd|pwd)\b\s*[:=]\s*["'][^"'\s]{8,}["']`),
}

// RedactionMask replaces a redacted value.
const RedactionMask = "[REDACTED]"

// RedactSecrets masks credential-shaped values in a block of text.
//
// The code context sent to the model can contain a second secret that has
// nothing to do with the finding being triaged. Redacting before the text
// leaves the machine keeps the blast radius of a provider compromise at the
// finding under analysis.
func RedactSecrets(text string) string {
	if text == "" {
		return text
	}
	for _, re := range secretPatterns {
		text = re.ReplaceAllStringFunc(text, func(match string) string {
			// Keep the assignment shape so the model still understands
			// what kind of value was there.
			if idx := strings.Index(match, "="); idx > 0 && strings.Contains(match, "=") {
				prefix := match[:idx+1]
				return prefix + " " + RedactionMask
			}
			return RedactionMask
		})
	}
	return text
}
