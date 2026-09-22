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
	Status    string
	Total     int
	Counts    map[string]int
	Groups    []mdGroup
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
	for _, f := range session.Findings {
		counts[string(f.Severity)]++
	}

	bySev := make(map[string][]mdFindingRow)
	for _, f := range session.Findings {
		extra := clusterExtraCount(f, session.Findings)
		row := mdFindingRow{
			ID:             f.ID[:8],
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
	for _, sev := range sevOrder {
		if rows, ok := bySev[sev]; ok {
			groups = append(groups, mdGroup{Severity: sev, Findings: rows})
		}
	}

	return mdData{
		SessionID: session.ID,
		APKPath:   session.APKPath,
		Status:    string(session.Status),
		Total:     len(session.Findings),
		Counts:    counts,
		Groups:    groups,
	}
}

func clusterExtraCount(f models.Finding, all []models.Finding) int {
	if f.ClusterID == "" {
		return 0
	}
	count := 0
	for _, other := range all {
		if other.ClusterID == f.ClusterID && other.ID != f.ID {
			count++
		}
	}
	return count
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
