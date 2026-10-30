package pipeline

import "github.com/dedek0/mobiscope/internal/models"

// DiffResult is the outcome of comparing two finding sets.
type DiffResult struct {
	// New lists findings present in the new artifact and absent from the
	// baseline (by fingerprint, respecting occurrence counts).
	New []models.Finding `json:"new"`
	// Resolved lists findings present in the baseline and absent from the
	// new artifact.
	Resolved []models.Finding `json:"resolved"`
	// Unchanged is the number of findings matched on both sides.
	Unchanged int `json:"unchanged"`
}

// FindingFingerprint identifies the same issue across two runs. Line numbers
// are deliberately excluded: a source edit that shifts a finding down should
// not turn it into a new finding. Semgrep findings use the rule id; every
// other finding uses category + title + file + evidence.
func FindingFingerprint(f models.Finding) string {
	if f.RuleID != "" {
		return f.SourceTool + "|" + f.RuleID + "|" + f.Location.File
	}
	return string(f.Category) + "|" + f.Title + "|" + f.Location.File + "|" + f.Evidence
}

// DiffFindings compares two finding sets and returns the new, resolved and
// unchanged findings. Duplicate fingerprints are matched by occurrence count,
// so a second occurrence of the same issue is reported as new.
func DiffFindings(oldFindings, newFindings []models.Finding) DiffResult {
	oldCounts := make(map[string]int, len(oldFindings))
	for _, f := range oldFindings {
		oldCounts[FindingFingerprint(f)]++
	}
	newCounts := make(map[string]int, len(newFindings))
	for _, f := range newFindings {
		newCounts[FindingFingerprint(f)]++
	}

	result := DiffResult{New: []models.Finding{}, Resolved: []models.Finding{}}
	seenNew := make(map[string]int, len(newFindings))
	for _, f := range newFindings {
		fp := FindingFingerprint(f)
		seenNew[fp]++
		if seenNew[fp] > oldCounts[fp] {
			result.New = append(result.New, f)
		}
	}

	seenOld := make(map[string]int, len(oldFindings))
	for _, f := range oldFindings {
		fp := FindingFingerprint(f)
		seenOld[fp]++
		if seenOld[fp] > newCounts[fp] {
			result.Resolved = append(result.Resolved, f)
		}
	}

	for fp, count := range oldCounts {
		if n := newCounts[fp]; n < count {
			result.Unchanged += n
			continue
		}
		result.Unchanged += count
	}
	return result
}

// FilterBaseline removes findings whose fingerprint is present in the
// baseline. It returns the surviving findings and how many were suppressed.
func FilterBaseline(findings []models.Finding, baseline map[string]bool) ([]models.Finding, int) {
	if len(baseline) == 0 {
		return findings, 0
	}
	out := make([]models.Finding, 0, len(findings))
	suppressed := 0
	for _, f := range findings {
		if baseline[FindingFingerprint(f)] {
			suppressed++
			continue
		}
		out = append(out, f)
	}
	return out, suppressed
}

// BaselineFingerprints builds the lookup used by FilterBaseline.
func BaselineFingerprints(findings []models.Finding) map[string]bool {
	out := make(map[string]bool, len(findings))
	for _, f := range findings {
		out[FindingFingerprint(f)] = true
	}
	return out
}
