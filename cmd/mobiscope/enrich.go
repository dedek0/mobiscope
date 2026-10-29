package main

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/dedek0/mobiscope/internal/osv"
	"github.com/dedek0/mobiscope/internal/sbom"
	"github.com/dedek0/mobiscope/internal/utils"
)

// lookupOSV queries the vulnerability database for the libraries detected in
// the app. The call is opt-in: without --osv the tool never touches the
// network.
func lookupOSV(ctx context.Context, session *models.AnalysisSession, logger *slog.Logger) ([]models.Vulnerability, error) {
	if len(session.App.SDKs) == 0 {
		logger.Info("no third-party libraries detected, skipping the vulnerability lookup")
		return nil, nil
	}

	client := osv.NewClient()
	vulns, err := client.Lookup(ctx, session.App.SDKs)
	if err != nil {
		return nil, err
	}
	logger.Info("vulnerability lookup complete", "libraries", len(session.App.SDKs), "advisories", len(vulns))
	return vulns, nil
}

// vulnerabilityFindings turns the advisories into findings so they show up in
// the report and in the SARIF export.
func vulnerabilityFindings(session *models.AnalysisSession, vulns []models.Vulnerability) []models.Finding {
	var out []models.Finding
	for _, v := range vulns {
		severity := models.SeverityHigh
		switch {
		case v.Severity == "":
			severity = models.SeverityHigh
		case cvssScore(v.Severity) >= 9.0:
			severity = models.SeverityCritical
		case cvssScore(v.Severity) >= 7.0:
			severity = models.SeverityHigh
		case cvssScore(v.Severity) >= 4.0:
			severity = models.SeverityMedium
		default:
			severity = models.SeverityLow
		}

		fixed := "no fix published"
		if len(v.FixedIn) > 0 {
			fixed = "fixed in " + v.FixedIn[0]
		}
		desc := fmt.Sprintf("The app bundles %s %s, which is affected by %s (%s).", v.Package, v.Version, v.ID, fixed)
		if v.Summary != "" {
			desc += " " + v.Summary
		}

		out = append(out, models.Finding{
			ID:          models.GenerateID("osv", models.CategoryManifestIssue, v.Package, 0, v.ID),
			SessionID:   session.ID,
			SourceTool:  "osv",
			Category:    models.CategoryManifestIssue,
			Platform:    session.Platform,
			Title:       fmt.Sprintf("Known vulnerability in %s: %s", v.Package, v.ID),
			Description: desc,
			Evidence:    v.ID,
			Location:    models.Location{File: v.Package, Line: 0, Snippet: v.ID},
			Severity:    severity,
			Sensitivity: models.SensitivityPublic,
			Confidence:  0.9,
		})
	}
	return out
}

// cvssScore parses a CVSS vector or score into a number. A vector string
// such as "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" yields 0 because the
// base score is not part of the vector; the database usually reports a
// numeric score, which is what this handles.
func cvssScore(s string) float64 {
	var score float64
	if _, err := fmt.Sscanf(s, "%f", &score); err != nil {
		return 0
	}
	return score
}

// writeSBOMFile writes the CycloneDX document next to the other artifacts.
func writeSBOMFile(sessionDir string, session *models.AnalysisSession) error {
	doc := sbom.Build(session)
	data, err := doc.JSON()
	if err != nil {
		return err
	}
	path := filepath.Join(sessionDir, "sbom.cdx.json")
	if err := utils.WriteFile(path, data); err != nil {
		return err
	}
	return nil
}
