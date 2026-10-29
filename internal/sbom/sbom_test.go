package sbom

import (
	"encoding/json"
	"testing"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildIncludesMetadataAndComponents(t *testing.T) {
	session := &models.AnalysisSession{
		PackageName:   "com.example.app",
		VersionName:   "1.2.3",
		APKHash:       "abc123",
		SigningCertFP: "DEADBEEF",
		App: models.AppInventory{
			SDKs: []models.SDK{
				{Name: "Gson", Group: "com.google.code.gson", Artifact: "gson", Version: "2.10.1"},
				{Name: "No coordinates"},
			},
			NativeLibs: []models.NativeLib{
				{Path: "lib/x86/libfoo.so", Version: "1.0", Archs: []string{"x86", "x86_64"}},
			},
		},
	}

	doc := Build(session)
	assert.Equal(t, "CycloneDX", doc.BOMFormat)
	assert.Equal(t, SpecVersion, doc.SpecVersion)
	assert.Equal(t, 1, doc.Version)
	assert.NotEmpty(t, doc.Metadata.Timestamp)
	require.NotNil(t, doc.Metadata.Component)
	assert.Equal(t, "com.example.app", doc.Metadata.Component.Name)
	assert.Equal(t, "1.2.3", doc.Metadata.Component.Version)
	assert.Contains(t, doc.Metadata.Component.Properties, Property{Name: "mobiscope:apk_sha256", Value: "abc123"})
	assert.Contains(t, doc.Metadata.Component.Properties, Property{Name: "mobiscope:signing_cert", Value: "DEADBEEF"})

	require.Len(t, doc.Components, 3)
	assert.Equal(t, "library", doc.Components[0].Type)
	assert.Equal(t, "pkg:maven/com.google.code.gson/gson@2.10.1", doc.Components[0].PURL)
	assert.Equal(t, "No coordinates", doc.Components[1].Name)
	assert.Empty(t, doc.Components[1].PURL)
	assert.Equal(t, "lib/x86/libfoo.so", doc.Components[2].Name)
	require.Len(t, doc.Components[2].Properties, 1)
	assert.Equal(t, "mobiscope:architectures", doc.Components[2].Properties[0].Name)
	assert.Equal(t, "x86,x86_64", doc.Components[2].Properties[0].Value)
}

func TestBuildWithoutSDKsOrNativeLibs(t *testing.T) {
	doc := Build(&models.AnalysisSession{PackageName: "com.example.app"})
	assert.NotNil(t, doc.Components)
	assert.Empty(t, doc.Components)
	assert.NotNil(t, doc.Metadata.Component)
}

func TestAppNameFallsBackToBundleIDThenUnknown(t *testing.T) {
	assert.Equal(t, "com.x", appName(&models.AnalysisSession{PackageName: "com.x"}))
	assert.Equal(t, "com.y", appName(&models.AnalysisSession{App: models.AppInventory{BundleID: "com.y"}}))
	assert.Equal(t, "unknown", appName(&models.AnalysisSession{}))
}

func TestPURL(t *testing.T) {
	assert.Equal(t, "pkg:maven/g/a@1.0", purl(models.SDK{Group: "g", Artifact: "a", Version: "1.0"}))
	assert.Equal(t, "pkg:maven/g/a", purl(models.SDK{Group: "g", Artifact: "a"}))
	assert.Empty(t, purl(models.SDK{Name: "only a name"}))
	assert.Empty(t, purl(models.SDK{Group: "g"}))
}

func TestJSONIsValidAndIndented(t *testing.T) {
	data, err := Build(&models.AnalysisSession{PackageName: "com.x"}).JSON()
	require.NoError(t, err)
	assert.Contains(t, string(data), "\n  \"bomFormat\"")

	var round map[string]any
	require.NoError(t, json.Unmarshal(data, &round))
	assert.Equal(t, "CycloneDX", round["bomFormat"])
	assert.Equal(t, SpecVersion, round["specVersion"])
}
