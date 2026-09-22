package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/dedek0/mobiscope/internal/models"
)

// Dedup removes exact-duplicate findings (same Category, File, Line, snippet hash).
func Dedup(findings []models.Finding) []models.Finding {
	seen := make(map[string]bool, len(findings))
	result := make([]models.Finding, 0, len(findings))

	for _, f := range findings {
		key := dedupKey(f)
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, f)
	}

	return result
}

func dedupKey(f models.Finding) string {
	snippetHash := sha256.Sum256([]byte(f.Location.Snippet))
	return fmt.Sprintf("%s|%s|%d|%s", f.Category, f.Location.File, f.Location.Line, hex.EncodeToString(snippetHash[:8]))
}

// Cluster groups findings by (Category, PatternSignature) and marks representatives.
// Returns the clustered findings and the number of clusters formed.
func Cluster(findings []models.Finding, logger *slog.Logger) ([]models.Finding, int) {
	if len(findings) == 0 {
		return findings, 0
	}

	groups := make(map[string][]int)
	for i, f := range findings {
		sig := patternSignature(f)
		groups[sig] = append(groups[sig], i)
	}

	clusterCount := 0
	totalFindings := len(findings)

	for sig, indices := range groups {
		clusterID := computeClusterID(sig)

		sort.Slice(indices, func(a, b int) bool {
			fa, fb := findings[indices[a]], findings[indices[b]]
			if fa.Location.File != fb.Location.File {
				return fa.Location.File < fb.Location.File
			}
			return fa.Location.Line < fb.Location.Line
		})

		for seq, idx := range indices {
			findings[idx].ClusterID = clusterID
			if seq == 0 {
				findings[idx].Representative = true
				findings[idx].NeedsLLMTriage = true
			} else {
				findings[idx].Representative = false
				findings[idx].NeedsLLMTriage = false
			}
		}

		if len(indices) > 1 {
			clusterCount++
		}
	}

	singletonCount := 0
	for _, indices := range groups {
		if len(indices) > 1 {
			singletonCount++
		}
	}

	economyPct := 0
	if totalFindings > 0 {
		nonRepresentative := 0
		for _, f := range findings {
			if !f.NeedsLLMTriage {
				nonRepresentative++
			}
		}
		economyPct = (nonRepresentative * 100) / totalFindings
	}

	logger.Info("clustering complete",
		"total_findings", totalFindings,
		"clusters", clusterCount,
		"estimated_savings_pct", economyPct,
	)

	return findings, clusterCount
}

func patternSignature(f models.Finding) string {
	firstToken := firstNormalizedToken(f.Title)
	ext := fileExt(f.Location.File)
	return fmt.Sprintf("%s|%s|%s|%s", f.Category, firstToken, ext, f.Severity)
}

func firstNormalizedToken(title string) string {
	title = strings.TrimSpace(title)
	fields := strings.Fields(title)
	if len(fields) == 0 {
		return ""
	}
	return strings.ToLower(fields[0])
}

func fileExt(path string) string {
	idx := strings.LastIndex(path, ".")
	if idx < 0 {
		return ""
	}
	return strings.ToLower(path[idx:])
}

func computeClusterID(sig string) string {
	h := sha256.Sum256([]byte(sig))
	return "cl-" + hex.EncodeToString(h[:8])
}
