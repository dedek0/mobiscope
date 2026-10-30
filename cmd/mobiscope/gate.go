package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/dedek0/mobiscope/internal/pipeline"
	"github.com/dedek0/mobiscope/internal/report"
)

// ErrFindingsAboveThreshold is returned by --fail-on when at least one finding
// reaches the selected severity. classifyExit maps it to ExitFindings.
var ErrFindingsAboveThreshold = errors.New("findings at or above the fail-on threshold")

// severityRank orders the severity enum from most to least severe.
var severityRank = map[models.Severity]int{
	models.SeverityCritical: 5,
	models.SeverityHigh:     4,
	models.SeverityMedium:   3,
	models.SeverityLow:      2,
	models.SeverityInfo:     1,
}

// parseFailOn validates the --fail-on value. An empty value or "off"/"none"
// disables the gate.
func parseFailOn(value string) (models.Severity, bool, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" || v == "off" || v == "none" {
		return "", false, nil
	}
	sev := models.Severity(v)
	if _, ok := severityRank[sev]; !ok {
		return "", false, fmt.Errorf("invalid --fail-on value %q (use critical, high, medium, low, info or off)", value)
	}
	return sev, true, nil
}

// countAtOrAbove returns how many findings have at least the threshold
// severity.
func countAtOrAbove(findings []models.Finding, threshold models.Severity) int {
	min := severityRank[threshold]
	n := 0
	for _, f := range findings {
		if severityRank[f.Severity] >= min {
			n++
		}
	}
	return n
}

// applyBaseline removes findings that match a previous findings.json (or a
// session.json containing a findings array) and re-clusters the remainder so
// representatives stay correct.
func applyBaseline(session *models.AnalysisSession, path string, logger *slog.Logger) error {
	base, err := loadBaselineFindings(path)
	if err != nil {
		return err
	}
	filtered, suppressed := pipeline.FilterBaseline(session.Findings, pipeline.BaselineFingerprints(base))
	if suppressed == 0 {
		return nil
	}

	session.Findings = pipeline.Dedup(filtered)
	session.Findings, _ = pipeline.Cluster(session.Findings, logger)
	report.SortFindingsBySeverity(session.Findings)
	session.BaselineSuppressed = suppressed
	logger.Info("baseline applied", "suppressed", suppressed, "remaining", len(session.Findings))
	return nil
}

// loadBaselineFindings accepts both a findings.json array and an object with a
// findings field (for example a session.json) so operators can point at either
// artifact.
func loadBaselineFindings(path string) ([]models.Finding, error) {
	data, err := os.ReadFile(path) //nolint:gosec // explicit operator-supplied baseline path
	if err != nil {
		return nil, fmt.Errorf("reading baseline %s: %w", path, err)
	}

	var findings []models.Finding
	if err := json.Unmarshal(data, &findings); err == nil {
		return findings, nil
	}

	var session struct {
		Findings []models.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("decoding baseline %s: %w", path, err)
	}
	return session.Findings, nil
}
