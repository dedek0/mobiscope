package main

import (
	"log/slog"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/dedek0/mobiscope/internal/pipeline"
	"github.com/dedek0/mobiscope/internal/report"
)

// applyMapping rewrites obfuscated class paths through an R8/ProGuard mapping
// and re-clusters the findings so representatives stay correct.
func applyMapping(session *models.AnalysisSession, path string, logger *slog.Logger) error {
	mapping, err := pipeline.LoadMapping(path)
	if err != nil {
		return err
	}
	rewritten := mapping.RewriteFindings(session.Findings)
	if rewritten == 0 {
		return nil
	}

	session.Findings = pipeline.Dedup(session.Findings)
	session.Findings, _ = pipeline.Cluster(session.Findings, logger)
	report.SortFindingsBySeverity(session.Findings)
	session.FindingsMapped = rewritten
	logger.Info("mapping applied", "rewritten", rewritten)
	return nil
}
