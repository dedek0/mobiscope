package pipeline

import (
	"log/slog"
	"os"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
)

func benchFindings(n int) []models.Finding {
	out := make([]models.Finding, 0, n)
	for i := 0; i < n; i++ {
		sev := models.SeverityHigh
		if i%5 == 0 {
			sev = models.SeverityCritical
		}
		out = append(out, models.Finding{
			ID:         string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)),
			SessionID:  "bench",
			SourceTool: "semgrep",
			Category:   models.CategoryCodePattern,
			Title:      "Finding type " + string(rune('A'+i%3)),
			Severity:   sev,
			Location:   models.Location{File: "f" + string(rune('0'+i%10)) + ".java", Line: i},
		})
	}
	return out
}

func BenchmarkDedup(b *testing.B) {
	findings := benchFindings(10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Dedup(findings)
	}
}

func BenchmarkCluster(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	findings := benchFindings(10000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Cluster(findings, logger)
	}
}
