package analyzers

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
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

// Unlike gitleaks (exit 1 = leaks found = success), semgrep has no
// "findings found" exit code in this wrapper: every non-zero exit is a tool
// failure. See gitleaks_test.go TestGitleaks_Run_AcceptsExitCode1 for the
// contrasting contract.
func TestSemgrep_Run_RejectsExitCode1(t *testing.T) {
	runner := NewMockRunner(`{"runs":[]}`, "ran with -sarif", 1)
	s := NewSemgrepWithRunner("/rules", runner)

	result, err := s.Run(context.Background(), "a.apk", t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "semgrep execution failed")
	assert.Equal(t, 1, result.ExitCode)
	assert.NotEmpty(t, result.Error)
}

func TestSemgrep_Run_RejectsExitCode2(t *testing.T) {
	runner := NewMockRunner("", "config load failed", 2)
	s := NewSemgrepWithRunner("/rules", runner)

	result, err := s.Run(context.Background(), "a.apk", t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "semgrep execution failed")
	assert.Equal(t, 2, result.ExitCode)
	assert.Contains(t, result.Error, "exited with code 2")
}

// The SARIF file written via --output wins over stdout, so noisy tool logs
// cannot corrupt the parsed output.
func TestSemgrep_Run_PrefersSARIFFileOverStdout(t *testing.T) {
	workdir := t.TempDir()
	sarif := `{"runs":[{"results":[{"ruleId":"r1","level":"error","message":{"text":"m"}}]}]}`
	require.NoError(t, os.WriteFile(filepath.Join(workdir, "semgrep.sarif"), []byte(sarif), 0o600))

	runner := NewMockRunner("WARNING: noisy stdout that is not JSON", "", 0)
	s := NewSemgrepWithRunner("/rules", runner)

	result, err := s.Run(context.Background(), "a.apk", workdir)
	require.NoError(t, err)
	require.NotNil(t, result.Output)
	assert.JSONEq(t, sarif, string(result.Output))

	findings := ConvertSemgrepFindings(result.Output, "s")
	require.Len(t, findings, 1)
	assert.Equal(t, "r1", findings[0].RuleID)
}

// When the SARIF file is missing, valid JSON on stdout is used as a fallback
// and must pass through as an object (SARIF), not be wrapped into an array.
func TestSemgrep_Run_StdoutJSONFallback(t *testing.T) {
	runner := NewMockRunner(`{"runs":[{"results":[]}]}`, "log line", 0)
	s := NewSemgrepWithRunner("/rules", runner)

	result, err := s.Run(context.Background(), "a.apk", t.TempDir())
	require.NoError(t, err)
	require.NotNil(t, result.Output)
	assert.True(t, json.Valid(result.Output))
	assert.True(t, bytes.HasPrefix(bytes.TrimSpace(result.Output), []byte("{")),
		"SARIF object must not be rewrapped into an array")

	// The converter must see real SARIF from the fallback.
	findings := ConvertSemgrepFindings(result.Output, "s")
	require.Len(t, findings, 0)
}

// Mock-binary variant: a real semgrep stub on PATH exiting 1 must fail,
// exiting 0 must succeed — mirroring TestMockToolchain_GitleaksExitCodes.
func TestMockToolchain_SemgrepExitCodes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs")
	}
	dir := t.TempDir()
	writeMockTool(t, dir, "semgrep", "1.127.1", 1)
	withMockBinaries(t, dir)

	s := NewSemgrep("rules/mastg")
	res, err := s.Run(context.Background(), "test.apk", t.TempDir())
	require.Error(t, err)
	assert.Equal(t, 1, res.ExitCode)
	assert.NotEmpty(t, res.Error)

	writeMockTool(t, dir, "semgrep", "1.127.1", 0)
	res, err = s.Run(context.Background(), "test.apk", t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, 0, res.ExitCode)
}
