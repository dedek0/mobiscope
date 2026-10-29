package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClientDefaults(t *testing.T) {
	c := NewClient()
	assert.Equal(t, DefaultBaseURL, c.BaseURL)
	require.NotNil(t, c.HTTP)
	assert.Equal(t, 30*time.Second, c.HTTP.Timeout)
}

func TestQueryBatchSendsNormalizedQueries(t *testing.T) {
	var gotMethod, gotPath, gotContentType string
	var got batchRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-1"}]},{"vulns":[]}]}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	results, err := c.QueryBatch(context.Background(), []Query{
		{Package: "com.x:y", Version: "1.0"},
		{Package: "org.a:b", Ecosystem: EcosystemMaven},
	})
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, "GHSA-1", results[0].Vulns[0].ID)
	assert.Empty(t, results[1].Vulns)

	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/v1/querybatch", gotPath)
	assert.Equal(t, "application/json", gotContentType)
	require.Len(t, got.Queries, 2)
	// An empty ecosystem is defaulted to Maven.
	assert.Equal(t, EcosystemMaven, got.Queries[0].Ecosystem)
	assert.Equal(t, EcosystemMaven, got.Queries[1].Ecosystem)
}

func TestQueryBatchEmptyReturnsNil(t *testing.T) {
	// A client with an unusable URL proves the call does not reach the
	// network when there is nothing to look up.
	c := &Client{BaseURL: "http://127.0.0.1:1"}
	results, err := c.QueryBatch(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestQueryBatchHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	_, err := c.QueryBatch(context.Background(), []Query{{Package: "a:b"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OSV returned 500")
}

func TestQueryBatchRejectsResultCountMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	_, err := c.QueryBatch(context.Background(), []Query{{Package: "a:b"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "0 results for 1 queries")
}

func TestLookupMapsAdvisoriesAndSkipsIncompleteSDKs(t *testing.T) {
	var got batchRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"results":[
			{"vulns":[{
				"id":"GHSA-1","summary":"bad thing","aliases":["CVE-1"],
				"severity":[{"type":"CVSS_V3","score":"9.8"}],
				"affected":[{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}],
				"references":[{"type":"WEB","url":"https://example.com/1"}]
			}]},
			{"vulns":[]}
		]}`))
	}))
	defer srv.Close()

	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	sdks := []models.SDK{
		{Package: "com.x:y", Version: "1.0"},
		{Package: "", Version: "1.0"},
		{Package: "org.a:b", Version: ""},
		{Package: "org.c:d", Version: "3.2.1"},
	}
	vulns, err := c.Lookup(context.Background(), sdks)
	require.NoError(t, err)
	require.Len(t, vulns, 1)
	assert.Equal(t, "GHSA-1", vulns[0].ID)
	assert.Equal(t, "com.x:y", vulns[0].Package)
	assert.Equal(t, "1.0", vulns[0].Version)
	assert.Equal(t, "9.8", vulns[0].Severity)
	assert.Equal(t, []string{"2.0.0"}, vulns[0].FixedIn)
	assert.Equal(t, []string{"CVE-1"}, vulns[0].Aliases)
	assert.Equal(t, "https://example.com/1", vulns[0].Reference)

	// Only libraries with both a package and a version are queried.
	require.Len(t, got.Queries, 2)
	assert.Equal(t, "com.x:y", got.Queries[0].Package)
	assert.Equal(t, "org.c:d", got.Queries[1].Package)
}

func TestLookupWithoutQueryableSDKs(t *testing.T) {
	c := &Client{BaseURL: "http://127.0.0.1:1"}
	vulns, err := c.Lookup(context.Background(), []models.SDK{{Package: "a:b"}})
	require.NoError(t, err)
	assert.Nil(t, vulns)
}

func TestFixedVersions(t *testing.T) {
	v := Vuln{Affected: []Affected{{Ranges: []Range{{Events: []Event{
		{Fixed: "1.2.3"},
		{Introduced: "0"},
		{Fixed: "1.4.0"},
	}}}}}}
	assert.Equal(t, []string{"1.2.3", "1.4.0"}, FixedVersions(v))
	assert.Empty(t, FixedVersions(Vuln{}))
}

func TestCVSS(t *testing.T) {
	assert.Equal(t, "7.5", CVSS(Vuln{Severity: []Severity{{Type: "CVSS_V3"}, {Score: "7.5"}}}))
	assert.Empty(t, CVSS(Vuln{}))
}
