package analyzers

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findingConverter mirrors pipeline.FindingConverter without importing the
// pipeline package (which would create an import cycle).
type findingConverter interface {
	ConvertFindings(raw json.RawMessage, sessionID string) []models.Finding
}

func TestRepack_ConvertFindingsWired(t *testing.T) {
	var _ findingConverter = (*Repack)(nil)
	var _ findingConverter = (*SDK)(nil)
}

func TestRepack_MultidexAndMissingV1AreNotIndicators(t *testing.T) {
	path := buildZipFile(t, filepath.Join(t.TempDir(), "app.apk"), map[string]string{
		"classes.dex":         "dex",
		"classes2.dex":        "dex",
		"classes3.dex":        "dex",
		"classes4.dex":        "dex",
		"classes5.dex":        "dex",
		"classes6.dex":        "dex",
		"AndroidManifest.xml": "manifest",
		"resources.arsc":      "arsc",
	})

	summary := NewRepack().analyze(path)
	assert.Empty(t, summary.Indicators, "multidex and a v2/v3-only signature are normal")
}

func TestRepack_AssetExecutable(t *testing.T) {
	path := buildZipFile(t, filepath.Join(t.TempDir(), "app.apk"), map[string]string{
		"classes.dex":        "dex",
		"assets/payload.dex": "dex",
		"assets/plugin.jar":  "jar",
		"assets/native/x.so": "so",
	})

	summary := NewRepack().analyze(path)
	require.Len(t, summary.Indicators, 2, "one executable payload and one native payload")

	kinds := map[string]models.Severity{}
	for _, ind := range summary.Indicators {
		kinds[ind.Kind] = ind.Severity
	}
	assert.Equal(t, models.SeverityHigh, kinds["asset-payload"])
	assert.Equal(t, models.SeverityLow, kinds["asset-native-library"])
}

func TestRepack_ConvertFindings(t *testing.T) {
	raw, err := json.Marshal(repackSummary{
		Indicators: []repackIndicator{{
			Kind: "asset-payload", Title: "payload", Description: "d",
			Evidence: "assets/x.dex", Severity: models.SeverityHigh, Confidence: 0.7,
		}},
		ExpectedCert: "aa", ActualCert: "bb",
	})
	require.NoError(t, err)

	findings := NewRepack().ConvertFindings(raw, "s")
	require.Len(t, findings, 2, "indicator plus certificate mismatch")
	assert.Equal(t, models.PlatformAndroid, findings[0].Platform)
	assert.Equal(t, models.SeverityCritical, findings[1].Severity)
}
