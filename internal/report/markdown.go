package report

import (
	_ "embed"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/template"

	"github.com/dedek0/mobiscope/internal/models"
)

//go:embed templates/report.md.tmpl
var markdownTemplate string

type mdData struct {
	SessionID string
	APKPath   string
	Platform  string
	Status    string
	Total     int
	Counts    map[string]int
	Groups    []mdGroup

	// Executive summary fields.
	ClusterTotal  int
	TopClusters   []mdClusterRow
	TopCategories []mdCatRow
	ToolsRun      int
	Triaged       int
	CostUSD       float64
	LLMRun        bool
}

type mdClusterRow struct {
	ID    string
	Size  int
	Title string
}

type mdCatRow struct {
	Name  string
	Count int
}

type mdGroup struct {
	Severity string
	Findings []mdFindingRow
}

type mdFindingRow struct {
	ID             string
	Title          string
	Category       string
	File           string
	Line           int
	Sensitivity    string
	Confidence     float64
	ClusterID      string
	Representative string
	ExtraCount     int
	Snippet        string
}

// MarkdownReporter renders a human-readable markdown report.
type MarkdownReporter struct{}

func (r *MarkdownReporter) Render(session *models.AnalysisSession, w io.Writer) error {
	funcMap := template.FuncMap{
		"mul": func(a, b float64) float64 { return a * b },
	}
	tmpl, err := template.New("report").Funcs(funcMap).Parse(markdownTemplate)
	if err != nil {
		return fmt.Errorf("parsing markdown template: %w", err)
	}

	data := buildMDData(session)
	return tmpl.Execute(w, data)
}

func buildMDData(session *models.AnalysisSession) mdData {
	counts := make(map[string]int)
	clusterCounts := make(map[string]int)
	for _, f := range session.Findings {
		counts[string(f.Severity)]++
		if f.ClusterID != "" {
			clusterCounts[f.ClusterID]++
		}
	}

	bySev := make(map[string][]mdFindingRow)
	for _, f := range session.Findings {
		extra := 0
		if f.ClusterID != "" {
			extra = clusterCounts[f.ClusterID] - 1
		}
		row := mdFindingRow{
			ID:             shortID(f.ID),
			Title:          f.Title,
			Category:       string(f.Category),
			File:           f.Location.File,
			Line:           f.Location.Line,
			Sensitivity:    string(f.Sensitivity),
			Confidence:     f.Confidence,
			ClusterID:      f.ClusterID,
			Representative: boolStr(f.Representative),
			ExtraCount:     extra,
			Snippet:        truncate(f.Location.Snippet, 80),
		}
		bySev[string(f.Severity)] = append(bySev[string(f.Severity)], row)
	}

	sevOrder := []string{"critical", "high", "medium", "low", "info"}
	var groups []mdGroup
	seen := make(map[string]bool, len(sevOrder))
	for _, sev := range sevOrder {
		if rows, ok := bySev[sev]; ok {
			groups = append(groups, mdGroup{Severity: sev, Findings: rows})
			seen[sev] = true
		}
	}
	// Catch empty/unknown severities so they are not silently dropped.
	unknown := make([]string, 0)
	for sev := range bySev {
		if !seen[sev] {
			unknown = append(unknown, sev)
		}
	}
	sort.Strings(unknown)
	for _, sev := range unknown {
		groups = append(groups, mdGroup{Severity: sev, Findings: bySev[sev]})
	}

	// Executive summary: clusters, categories, triage state.
	type clusterInfo struct {
		size  int
		title string
	}
	clusters := make(map[string]*clusterInfo)
	catCounts := make(map[string]int)
	triaged := 0
	for _, f := range session.Findings {
		catCounts[string(f.Category)]++
		if f.LLMVerdict == models.VerdictConfirmed || f.LLMVerdict == models.VerdictLikelyFP {
			triaged++
		}
		if f.ClusterID == "" {
			continue
		}
		ci, ok := clusters[f.ClusterID]
		if !ok {
			ci = &clusterInfo{title: f.Title}
			clusters[f.ClusterID] = ci
		}
		ci.size++
	}

	topClusters := make([]mdClusterRow, 0, len(clusters))
	for id, ci := range clusters {
		topClusters = append(topClusters, mdClusterRow{ID: shortID(id), Size: ci.size, Title: ci.title})
	}
	sort.Slice(topClusters, func(i, j int) bool {
		if topClusters[i].Size != topClusters[j].Size {
			return topClusters[i].Size > topClusters[j].Size
		}
		return topClusters[i].ID < topClusters[j].ID
	})
	if len(topClusters) > 5 {
		topClusters = topClusters[:5]
	}

	topCats := make([]mdCatRow, 0, len(catCounts))
	for name, n := range catCounts {
		topCats = append(topCats, mdCatRow{Name: name, Count: n})
	}
	sort.Slice(topCats, func(i, j int) bool {
		if topCats[i].Count != topCats[j].Count {
			return topCats[i].Count > topCats[j].Count
		}
		return topCats[i].Name < topCats[j].Name
	})
	if len(topCats) > 5 {
		topCats = topCats[:5]
	}

	return mdData{
		SessionID: session.ID,
		APKPath:   session.APKPath,
		Platform:  string(session.Platform),
		Status:    string(session.Status),
		Total:     len(session.Findings),
		Counts:    counts,
		Groups:    groups,

		ClusterTotal:  len(clusters),
		TopClusters:   topClusters,
		TopCategories: topCats,
		ToolsRun:      len(session.ToolResults),
		Triaged:       triaged,
		CostUSD:       session.LLMCostUSD,
		LLMRun:        triaged > 0 || session.LLMCostUSD > 0,
	}
}

// shortID returns at most 8 characters of id without panicking on short ids.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// SeverityRank returns a numeric rank for sorting (lower = more severe).
func SeverityRank(s models.Severity) int {
	switch s {
	case models.SeverityCritical:
		return 0
	case models.SeverityHigh:
		return 1
	case models.SeverityMedium:
		return 2
	case models.SeverityLow:
		return 3
	case models.SeverityInfo:
		return 4
	default:
		return 5
	}
}

// SortFindingsBySeverity sorts findings from most to least severe.
func SortFindingsBySeverity(findings []models.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		ri, rj := SeverityRank(findings[i].Severity), SeverityRank(findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if findings[i].Location.File != findings[j].Location.File {
			return findings[i].Location.File < findings[j].Location.File
		}
		return findings[i].Location.Line < findings[j].Location.Line
	})
}
