// Package metrics keeps a process-wide set of atomic counters describing
// analysis runs, findings, LLM calls and cache activity. Counters are
// rendered as Prometheus text exposition format on /metrics without pulling
// in a client library.
package metrics

import (
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type analyzerCounter struct {
	runs    atomic.Int64
	errors  atomic.Int64
	totalNS atomic.Int64
}

type labelCounter struct {
	mu     sync.Mutex
	counts map[string]*atomic.Int64
}

func (lc *labelCounter) inc(key string) {
	lc.mu.Lock()
	c, ok := lc.counts[key]
	if !ok {
		c = &atomic.Int64{}
		lc.counts[key] = c
	}
	lc.mu.Unlock()
	c.Add(1)
}

func (lc *labelCounter) snapshot() map[string]int64 {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	out := make(map[string]int64, len(lc.counts))
	for k, v := range lc.counts {
		out[k] = v.Load()
	}
	return out
}

type registry struct {
	analyses     atomic.Int64
	analyzers    sync.Map // tool string -> *analyzerCounter
	findingsSev  labelCounter
	findingsCat  labelCounter
	llmCallsOK   labelCounter
	llmCallsFail labelCounter
	llmCostBits  atomic.Uint64 // float64 bits
	cacheHits    atomic.Int64
	cacheMisses  atomic.Int64
}

func newRegistry() *registry {
	r := &registry{}
	r.findingsSev.counts = make(map[string]*atomic.Int64)
	r.findingsCat.counts = make(map[string]*atomic.Int64)
	r.llmCallsOK.counts = make(map[string]*atomic.Int64)
	r.llmCallsFail.counts = make(map[string]*atomic.Int64)
	return r
}

// Default is the process-wide registry.
var Default = newRegistry()

// RecordAnalysis counts one completed analysis session.
func RecordAnalysis() { Default.analyses.Add(1) }

// RecordAnalyzer records one analyzer execution: run count, error flag and
// duration.
func RecordAnalyzer(tool string, d time.Duration, failed bool) {
	e, _ := Default.analyzers.LoadOrStore(tool, &analyzerCounter{})
	ac := e.(*analyzerCounter)
	ac.runs.Add(1)
	ac.totalNS.Add(d.Nanoseconds())
	if failed {
		ac.errors.Add(1)
	}
}

// RecordFindings counts findings by severity and category.
func RecordFindings(severity, category string) {
	Default.findingsSev.inc(severity)
	Default.findingsCat.inc(category)
}

// RecordLLMCall counts one LLM call and accumulates its cost.
func RecordLLMCall(provider string, ok bool, costUSD float64) {
	if ok {
		Default.llmCallsOK.inc(provider)
	} else {
		Default.llmCallsFail.inc(provider)
	}
	if costUSD > 0 {
		for {
			old := Default.llmCostBits.Load()
			newBits := float64ToBits(bitsToFloat64(old) + costUSD)
			if Default.llmCostBits.CompareAndSwap(old, newBits) {
				break
			}
		}
	}
}

// RecordCacheLookup counts one cache Get: hit or miss.
func RecordCacheLookup(hit bool) {
	if hit {
		Default.cacheHits.Add(1)
	} else {
		Default.cacheMisses.Add(1)
	}
}

// WriteProm renders all counters in Prometheus text exposition format.
func WriteProm(w io.Writer) {
	r := Default

	fmt.Fprintf(w, "# HELP mobiscope_analyses_total Completed analysis sessions.\n")
	fmt.Fprintf(w, "# TYPE mobiscope_analyses_total counter\n")
	fmt.Fprintf(w, "mobiscope_analyses_total %d\n", r.analyses.Load())

	fmt.Fprintf(w, "# HELP mobiscope_analyzer_runs_total Analyzer executions by tool.\n")
	fmt.Fprintf(w, "# TYPE mobiscope_analyzer_runs_total counter\n")
	fmt.Fprintf(w, "# HELP mobiscope_analyzer_errors_total Analyzer failures by tool.\n")
	fmt.Fprintf(w, "# TYPE mobiscope_analyzer_errors_total counter\n")
	fmt.Fprintf(w, "# HELP mobiscope_analyzer_duration_seconds_total Cumulative analyzer duration by tool.\n")
	fmt.Fprintf(w, "# TYPE mobiscope_analyzer_duration_seconds_total counter\n")
	var tools []string
	r.analyzers.Range(func(k, _ any) bool {
		tools = append(tools, k.(string))
		return true
	})
	sort.Strings(tools)
	for _, tool := range tools {
		e, _ := r.analyzers.Load(tool)
		ac := e.(*analyzerCounter)
		fmt.Fprintf(w, "mobiscope_analyzer_runs_total{tool=%q} %d\n", tool, ac.runs.Load())
		fmt.Fprintf(w, "mobiscope_analyzer_errors_total{tool=%q} %d\n", tool, ac.errors.Load())
		fmt.Fprintf(w, "mobiscope_analyzer_duration_seconds_total{tool=%q} %.3f\n",
			tool, float64(ac.totalNS.Load())/1e9)
	}

	writeLabelCounter(w, "mobiscope_findings_total", "Findings by severity.", "severity", r.findingsSev.snapshot())
	writeLabelCounter(w, "mobiscope_findings_by_category_total", "Findings by category.", "category", r.findingsCat.snapshot())
	writeLabelCounter(w, "mobiscope_llm_calls_total", "LLM calls by provider and result.", "result",
		mergeResults(r.llmCallsOK.snapshot(), r.llmCallsFail.snapshot()))

	fmt.Fprintf(w, "# HELP mobiscope_llm_cost_usd_total Cumulative LLM cost in USD.\n")
	fmt.Fprintf(w, "# TYPE mobiscope_llm_cost_usd_total counter\n")
	fmt.Fprintf(w, "mobiscope_llm_cost_usd_total %.6f\n", bitsToFloat64(r.llmCostBits.Load()))

	fmt.Fprintf(w, "# HELP mobiscope_llm_cache_lookups_total LLM cache lookups.\n")
	fmt.Fprintf(w, "# TYPE mobiscope_llm_cache_lookups_total counter\n")
	fmt.Fprintf(w, "mobiscope_llm_cache_lookups_total{result=\"hit\"} %d\n", r.cacheHits.Load())
	fmt.Fprintf(w, "mobiscope_llm_cache_lookups_total{result=\"miss\"} %d\n", r.cacheMisses.Load())
}

// mergeResults folds provider -> count maps into provider="x",result="ok|err"
// keys so a single label counter can render both series.
func mergeResults(ok, fail map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(ok)+len(fail))
	for k, v := range ok {
		out[k+"|ok"] = v
	}
	for k, v := range fail {
		out[k+"|err"] = v
	}
	return out
}

func writeLabelCounter(w io.Writer, name, help, label string, values map[string]int64) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s counter\n", name)
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "" {
			fmt.Fprintf(w, "%s %d\n", name, values[k])
			continue
		}
		if label == "result" && len(k) > 3 && k[len(k)-3:] == "|ok" {
			fmt.Fprintf(w, "%s{provider=%q,result=\"ok\"} %d\n", name, k[:len(k)-3], values[k])
			continue
		}
		if label == "result" && len(k) > 4 && k[len(k)-4:] == "|err" {
			fmt.Fprintf(w, "%s{provider=%q,result=\"err\"} %d\n", name, k[:len(k)-4], values[k])
			continue
		}
		fmt.Fprintf(w, "%s{%s=%q} %d\n", name, label, k, values[k])
	}
}

func float64ToBits(f float64) uint64 { return math.Float64bits(f) }
func bitsToFloat64(b uint64) float64 { return math.Float64frombits(b) }
