package analyzers

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSemgrep_Name(t *testing.T) {
	s := NewSemgrep("/rules")
	assert.Equal(t, "semgrep", s.Name())
}

func TestSemgrep_Run_Success(t *testing.T) {
	sarif := SARIFLog{
		Runs: []SARIFRun{{
			Results: []SARIFResult{
				{
					RuleID:  "mastg-hardcoded-api-key",
					Level:   "error",
					Message: SARIFMessage{Text: "Hardcoded key"},
					Locations: []SARIFLocation{{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{URI: "src/Main.java"},
							Region: SARIFRegion{
								StartLine: 10,
								Snippet:   SARIFSnippet{Text: `String key = "AKIA..."`},
							},
						},
					}},
				},
			},
			Tool: SARIFTool{Driver: SARIFDriver{
				Rules: []SARIFRule{
					{
						ID:                   "mastg-hardcoded-api-key",
						ShortDescription:     SARIFDescription{Text: "Hardcoded API key"},
						DefaultConfiguration: SARIFConfig{Level: "error"},
					},
				},
			}},
		}},
	}
	raw, _ := json.Marshal(sarif)

	runner := NewMockRunner(string(raw), "", 0)
	s := NewSemgrepWithRunner("/rules", runner)

	result, err := s.Run(context.Background(), "test.apk", t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, "semgrep", result.ToolName)
}

func TestConvertSemgrepFindings(t *testing.T) {
	sarif := SARIFLog{
		Runs: []SARIFRun{{
			Results: []SARIFResult{
				{
					RuleID:  "mastg-weak-crypto",
					Level:   "error",
					Message: SARIFMessage{Text: "Weak crypto"},
					Locations: []SARIFLocation{{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{URI: "Crypto.java"},
							Region: SARIFRegion{
								StartLine:   5,
								StartColumn: 1,
								Snippet:     SARIFSnippet{Text: "MessageDigest.getInstance(\"MD5\")"},
							},
						},
					}},
				},
			},
			Tool: SARIFTool{Driver: SARIFDriver{
				Rules: []SARIFRule{
					{
						ID:                   "mastg-weak-crypto",
						ShortDescription:     SARIFDescription{Text: "Weak crypto algorithm"},
						DefaultConfiguration: SARIFConfig{Level: "error"},
					},
				},
			}},
		}},
	}
	raw, _ := json.Marshal(sarif)

	findings := ConvertSemgrepFindings(raw, "sess-1")
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "code_pattern", string(f.Category))
	assert.Equal(t, "critical", string(f.Severity))
	assert.Equal(t, "internal", string(f.Sensitivity))
	assert.Equal(t, "Crypto.java", f.Location.File)
	assert.Equal(t, 5, f.Location.Line)
}

func TestConvertSemgrepFindings_SecretRule(t *testing.T) {
	sarif := SARIFLog{
		Runs: []SARIFRun{{
			Results: []SARIFResult{
				{
					RuleID:  "mastg-hardcoded-api-key",
					Level:   "warning",
					Message: SARIFMessage{Text: "Hardcoded key"},
					Locations: []SARIFLocation{{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{URI: "src/Key.java"},
							Region:           SARIFRegion{StartLine: 3, Snippet: SARIFSnippet{Text: "AKIA..."}},
						},
					}},
				},
			},
			Tool: SARIFTool{Driver: SARIFDriver{
				Rules: []SARIFRule{{
					ID:                   "mastg-hardcoded-api-key",
					ShortDescription:     SARIFDescription{Text: "Hardcoded API key"},
					DefaultConfiguration: SARIFConfig{Level: "warning"},
					Properties:           map[string]interface{}{"category": "secret", "masvs": "MSTG-STORAGE-14"},
				}},
			}},
		}},
	}
	raw, _ := json.Marshal(sarif)

	findings := ConvertSemgrepFindings(raw, "s")
	require.Len(t, findings, 1)
	assert.Equal(t, "secret", string(findings[0].Category))
	assert.Equal(t, "secret", string(findings[0].Sensitivity))
}

func TestConvertSemgrepFindings_MissingLevelUsesRuleDefault(t *testing.T) {
	sarif := SARIFLog{
		Runs: []SARIFRun{{
			Results: []SARIFResult{
				{
					RuleID:  "mastg-weak-crypto",
					Message: SARIFMessage{Text: "Weak crypto"},
					Locations: []SARIFLocation{{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{URI: "a.java"},
							Region:           SARIFRegion{StartLine: 1},
						},
					}},
				},
			},
			Tool: SARIFTool{Driver: SARIFDriver{
				Rules: []SARIFRule{{
					ID:                   "mastg-weak-crypto",
					ShortDescription:     SARIFDescription{Text: "Weak crypto"},
					DefaultConfiguration: SARIFConfig{Level: "error"},
				}},
			}},
		}},
	}
	raw, _ := json.Marshal(sarif)

	findings := ConvertSemgrepFindings(raw, "s")
	require.Len(t, findings, 1)
	assert.Equal(t, "critical", string(findings[0].Severity))
	assert.Equal(t, "Weak crypto", findings[0].Title)
}

func TestNormalizeSarifURI(t *testing.T) {
	assert.Equal(t, "/home/user/app/src/Main.java", normalizeSarifURI("file:///home/user/app/src/Main.java"))
	assert.Equal(t, "src/Main.java", normalizeSarifURI("./src/Main.java"))
	assert.Equal(t, "src/Main.java", normalizeSarifURI("src/Main.java"))
	assert.Equal(t, "", normalizeSarifURI(""))
}

func TestConvertSemgrepFindings_WarningLevel(t *testing.T) {
	sarif := SARIFLog{
		Runs: []SARIFRun{{
			Results: []SARIFResult{
				{
					RuleID:  "mastg-insecure-random",
					Level:   "warning",
					Message: SARIFMessage{Text: "Insecure random"},
					Locations: []SARIFLocation{{
						PhysicalLocation: SARIFPhysicalLocation{
							ArtifactLocation: SARIFArtifactLocation{URI: "Util.java"},
							Region:           SARIFRegion{StartLine: 8, Snippet: SARIFSnippet{Text: "new Random()"}},
						},
					}},
				},
			},
			Tool: SARIFTool{Driver: SARIFDriver{
				Rules: []SARIFRule{
					{
						ID:                   "mastg-insecure-random",
						ShortDescription:     SARIFDescription{Text: "Insecure random"},
						DefaultConfiguration: SARIFConfig{Level: "warning"},
					},
				},
			}},
		}},
	}
	raw, _ := json.Marshal(sarif)

	findings := ConvertSemgrepFindings(raw, "s")
	require.Len(t, findings, 1)
	assert.Equal(t, "medium", string(findings[0].Severity))
	assert.Equal(t, "internal", string(findings[0].Sensitivity))
}

func TestConvertSemgrepFindings_InvalidJSON(t *testing.T) {
	assert.Nil(t, ConvertSemgrepFindings(json.RawMessage(`{bad`), "s"))
}

func TestConvertSemgrepFindings_Empty(t *testing.T) {
	sarif := SARIFLog{Runs: []SARIFRun{{}}}
	raw, _ := json.Marshal(sarif)
	assert.Empty(t, ConvertSemgrepFindings(raw, "s"))
}

func TestSARIFLevelToSeverity(t *testing.T) {
	assert.Equal(t, "critical", string(sarifLevelToSeverity("error")))
	assert.Equal(t, "medium", string(sarifLevelToSeverity("warning")))
	assert.Equal(t, "info", string(sarifLevelToSeverity("note")))
	assert.Equal(t, "info", string(sarifLevelToSeverity("info")))
	assert.Equal(t, "low", string(sarifLevelToSeverity("unknown")))
}

func TestCategorySensitivity(t *testing.T) {
	assert.Equal(t, "secret", string(categorySensitivity(models.CategorySecret)))
	assert.Equal(t, "internal", string(categorySensitivity(models.CategoryCodePattern)))
	assert.Equal(t, "internal", string(categorySensitivity(models.CategoryNetworkConfig)))
}

func TestSemgrep_DeterministicID(t *testing.T) {
	sarif := SARIFLog{
		Runs: []SARIFRun{{
			Results: []SARIFResult{
				{
					RuleID: "r1", Level: "error", Message: SARIFMessage{Text: "x"},
					Locations: []SARIFLocation{{PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: "a.java"},
						Region:           SARIFRegion{StartLine: 1, Snippet: SARIFSnippet{Text: "snippet"}},
					}}},
				},
			},
			Tool: SARIFTool{Driver: SARIFDriver{Rules: []SARIFRule{
				{ID: "r1", ShortDescription: SARIFDescription{Text: "r1"}, DefaultConfiguration: SARIFConfig{Level: "error"}},
			}}},
		}},
	}
	raw, _ := json.Marshal(sarif)
	f1 := ConvertSemgrepFindings(raw, "s1")
	f2 := ConvertSemgrepFindings(raw, "s1")
	assert.Equal(t, f1[0].ID, f2[0].ID)
}
