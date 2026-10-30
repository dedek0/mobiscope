package main

import (
	"log/slog"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/dedek0/mobiscope/internal/pipeline"
	"github.com/dedek0/mobiscope/internal/report"
)

// applyAllowlist suppresses findings matched by a documented allowlist and
// re-clusters the remainder.
func applyAllowlist(session *models.AnalysisSession, path string, logger *slog.Logger) error {
	rules, err := pipeline.LoadAllowlist(path)
	if err != nil {
		return err
	}
	filtered, suppressed := pipeline.FilterAllowlist(session.Findings, rules)
	if suppressed == 0 {
		return nil
	}

	session.Findings = pipeline.Dedup(filtered)
	session.Findings, _ = pipeline.Cluster(session.Findings, logger)
	report.SortFindingsBySeverity(session.Findings)
	session.AllowlistSuppressed = suppressed
	logger.Info("allowlist applied", "suppressed", suppressed, "remaining", len(session.Findings))
	return nil
}
