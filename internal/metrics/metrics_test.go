package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordAnalyzerAndFindings(t *testing.T) {
	RecordAnalyzer("jadx", 1500*time.Millisecond, false)
	RecordAnalyzer("jadx", 2*time.Second, true)
	RecordAnalyzer("gitleaks", 100*time.Millisecond, false)
	RecordFindings("high", "secret")
	RecordFindings("high", "secret")
	RecordFindings("info", "code_pattern")

	var b strings.Builder
	WriteProm(&b)
	out := b.String()

	assert.Contains(t, out, `mobiscope_analyzer_runs_total{tool="jadx"} 2`)
	assert.Contains(t, out, `mobiscope_analyzer_errors_total{tool="jadx"} 1`)
	assert.Contains(t, out, `mobiscope_analyzer_duration_seconds_total{tool="jadx"} 3.500`)
	assert.Contains(t, out, `mobiscope_findings_total{severity="high"} 2`)
	assert.Contains(t, out, `mobiscope_findings_by_category_total{category="secret"} 2`)
	assert.Contains(t, out, `mobiscope_analyses_total 0`)
}

func TestRecordLLMCallAndCache(t *testing.T) {
	RecordLLMCall("ollama", true, 0)
	RecordLLMCall("openai", true, 0.0125)
	RecordLLMCall("openai", false, 0)
	RecordCacheLookup(true)
	RecordCacheLookup(false)

	var b strings.Builder
	WriteProm(&b)
	out := b.String()

	assert.Contains(t, out, `mobiscope_llm_calls_total{provider="openai",result="ok"} 1`)
	assert.Contains(t, out, `mobiscope_llm_calls_total{provider="openai",result="err"} 1`)
	assert.Contains(t, out, `mobiscope_llm_calls_total{provider="ollama",result="ok"} 1`)
	assert.Contains(t, out, "mobiscope_llm_cost_usd_total 0.012500")
	assert.Contains(t, out, `mobiscope_llm_cache_lookups_total{result="hit"} 1`)
	assert.Contains(t, out, `mobiscope_llm_cache_lookups_total{result="miss"} 1`)
}

func TestWriteProm_EmptyRegistryRendersZeroes(t *testing.T) {
	r := newRegistry()
	require.NotNil(t, r)

	var b strings.Builder
	WriteProm(&b)
	out := b.String()
	assert.Contains(t, out, "mobiscope_analyses_total")
	assert.NotContains(t, out, "NaN")
}
