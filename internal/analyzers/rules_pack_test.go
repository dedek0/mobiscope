package analyzers

import (
	"testing"

	"github.com/dedek0/mobiscope/internal/rules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// rulePack loads one of the shipped semgrep packs from the embedded copy,
// which is what actually reaches the user.
func rulePack(t *testing.T, rel string) map[string]interface{} {
	t.Helper()
	var data []byte
	switch rel {
	case "rules/mastg/rules.yaml":
		data = rules.AndroidYAML()
	case "rules/mastg-ios/rules.yaml":
		data = rules.IOSYAML()
	default:
		t.Fatalf("unknown rule pack %s", rel)
	}
	require.NotEmpty(t, data, "rule pack %s must exist", rel)

	var root map[string]interface{}
	require.NoError(t, yaml.Unmarshal(data, &root), "rule pack %s must be valid YAML", rel)
	return root
}

// ruleEntries returns the "rules" list of a pack, failing with a precise
// message when the pack is not in the format semgrep expects.
func ruleEntries(t *testing.T, root map[string]interface{}) []interface{} {
	t.Helper()
	raw, ok := root["rules"]
	require.True(t, ok,
		"rule pack must use the top-level `rules:` wrapper — bare rule lists "+
			"are rejected by semgrep 1.127.1 with 'was not a mapping'")
	list, ok := raw.([]interface{})
	require.True(t, ok, "`rules` must be a list")
	require.NotEmpty(t, list)
	return list
}

// walkRule inspects every mapping/list node below a rule entry.
func walkRule(rule map[string]interface{}, visit func(key string, value interface{})) {
	for k, v := range rule {
		visit(k, v)
		switch node := v.(type) {
		case map[string]interface{}:
			walkRule(node, visit)
		case []interface{}:
			for _, item := range node {
				if m, ok := item.(map[string]interface{}); ok {
					walkRule(m, visit)
				}
			}
		}
	}
}

func TestRulePacks_SemgrepSchema(t *testing.T) {
	for _, pack := range []string{"rules/mastg/rules.yaml", "rules/mastg-ios/rules.yaml"} {
		t.Run(pack, func(t *testing.T) {
			root := rulePack(t, pack)
			for i, raw := range ruleEntries(t, root) {
				rule, ok := raw.(map[string]interface{})
				require.True(t, ok, "rule #%d must be a mapping", i)

				id, _ := rule["id"].(string)
				require.NotEmpty(t, id, "rule #%d needs an id", i)
				for _, field := range []string{"message", "severity", "languages"} {
					assert.NotEmpty(t, rule[field], "rule %q: missing %q", id, field)
				}
				require.NotEmpty(t, rule["languages"], "rule %q: languages must be non-empty", id)

				meta, ok := rule["metadata"].(map[string]interface{})
				require.True(t, ok, "rule %q: metadata block required (feeds Finding fields)", id)
				assert.NotEmpty(t, meta["category"], "rule %q: metadata.category required", id)
				assert.NotEmpty(t, meta["masvs"], "rule %q: metadata.masvs required", id)

				walkRule(rule, func(key string, value interface{}) {
					if key == "pattern-regex" {
						re, _ := value.(string)
						assert.NotEmpty(t, re, "rule %q: empty pattern-regex", id)
						assert.False(t, re[len(re)-1] == '\n',
							"rule %q: pattern-regex must not end with a newline "+
								"(use `|-`, a trailing \\n silently kills every match)", id)
					}
					if key == "languages" {
						if langs, ok := value.([]interface{}); ok {
							for _, l := range langs {
								assert.NotEqual(t, "objc", l,
									"rule %q: semgrep has no objc parser — the whole pack "+
										"fails to load with 'unsupported language: objc'", id)
							}
						}
					}
				})
			}
		})
	}
}

func TestRulePacks_ExpectedRuleIDs(t *testing.T) {
	android := rulePack(t, "rules/mastg/rules.yaml")
	entries := ruleEntries(t, android)
	ids := make([]string, 0, len(entries))
	for _, raw := range entries {
		rule := raw.(map[string]interface{})
		ids = append(ids, rule["id"].(string))
	}
	for _, want := range []string{
		"mastg-hardcoded-api-key",
		"mastg-ecb-mode",
		"mastg-trustmanager-bypass",
		"mastg-hostname-verifier-bypass",
		"mastg-webview-addjsinterface",
		"mastg-dexclassloader",
		"mastg-log-sensitive",
		"mastg-weak-cipher-des-rc4",
		"mastg-aes-ecb-default",
	} {
		assert.Contains(t, ids, want)
	}
}
