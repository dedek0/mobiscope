// Package osv queries the OSV.dev vulnerability database.
//
// The lookup is opt-in: mobiscope never reaches the network unless the
// operator asks for it, which keeps the "local-first" promise of the tool.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dedek0/mobiscope/internal/models"
)

// DefaultBaseURL is the public OSV.dev API.
const DefaultBaseURL = "https://api.osv.dev"

// EcosystemMaven is the OSV ecosystem name for Maven artifacts.
const EcosystemMaven = "Maven"

// Query is one package to look up.
type Query struct {
	// Package is the package name, e.g. "com.google.code.gson:gson".
	Package string `json:"name"`
	// Version is the version to check. It may be empty, in which case
	// every advisory for the package is returned.
	Version string `json:"version,omitempty"`
	// Ecosystem is the OSV ecosystem. It defaults to Maven.
	Ecosystem string `json:"ecosystem,omitempty"`
}

// Result is the outcome of one query.
type Result struct {
	// Vulns lists the advisories that affect the queried package.
	Vulns []Vuln `json:"vulns,omitempty"`
}

// Vuln is a single advisory.
type Vuln struct {
	ID         string      `json:"id"`
	Summary    string      `json:"summary,omitempty"`
	Details    string      `json:"details,omitempty"`
	Aliases    []string    `json:"aliases,omitempty"`
	Severity   []Severity  `json:"severity,omitempty"`
	Affected   []Affected  `json:"affected,omitempty"`
	References []Reference `json:"references,omitempty"`
}

// Severity is the CVSS score of an advisory.
type Severity struct {
	Type  string `json:"type,omitempty"`
	Score string `json:"score,omitempty"`
}

// Affected is one affected version range.
type Affected struct {
	Package           Package  `json:"package"`
	Ranges            []Range  `json:"ranges,omitempty"`
	Versions          []string `json:"versions,omitempty"`
	EcosystemSpecific any      `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  any      `json:"database_specific,omitempty"`
}

// Package identifies the affected package.
type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// Range is a version range.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events,omitempty"`
}

// Event is a range boundary.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Reference is a link to the advisory.
type Reference struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url,omitempty"`
}

// Client queries the OSV.dev API.
type Client struct {
	// BaseURL is the API root. It defaults to DefaultBaseURL.
	BaseURL string
	// HTTP is the client used for the requests. It defaults to a client
	// with a 30 second timeout.
	HTTP *http.Client
}

// NewClient returns a client with sensible defaults.
func NewClient() *Client {
	return &Client{
		BaseURL: DefaultBaseURL,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// batchRequest is the body of POST /v1/querybatch.
type batchRequest struct {
	Queries []Query `json:"queries"`
}

// batchResponse is the body of the POST /v1/querybatch response.
type batchResponse struct {
	Results []Result `json:"results"`
}

// QueryBatch looks up several packages in one request. The results are
// returned in the same order as the queries.
func (c *Client) QueryBatch(ctx context.Context, queries []Query) ([]Result, error) {
	if len(queries) == 0 {
		return nil, nil
	}

	normalized := make([]Query, len(queries))
	for i, q := range queries {
		if q.Ecosystem == "" {
			q.Ecosystem = EcosystemMaven
		}
		normalized[i] = q
	}

	body, err := json.Marshal(batchRequest{Queries: normalized})
	if err != nil {
		return nil, fmt.Errorf("encoding query: %w", err)
	}

	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(base, "/")+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("querying OSV: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("reading OSV response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned %s: %s", resp.Status, strings.TrimSpace(string(data)))
	}

	var out batchResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decoding OSV response: %w", err)
	}
	if len(out.Results) != len(normalized) {
		// The API is expected to answer one result per query; a mismatch
		// would silently misalign the results.
		return nil, fmt.Errorf("OSV returned %d results for %d queries", len(out.Results), len(normalized))
	}
	return out.Results, nil
}

// FixedVersions returns the versions that carry the fix for an advisory.
func FixedVersions(v Vuln) []string {
	var out []string
	for _, aff := range v.Affected {
		for _, r := range aff.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					out = append(out, e.Fixed)
				}
			}
		}
	}
	return out
}

// CVSS returns the CVSS score of an advisory, if the database reports one.
func CVSS(v Vuln) string {
	for _, s := range v.Severity {
		if s.Score != "" {
			return s.Score
		}
	}
	return ""
}

// Lookup checks the given libraries against the database and returns the
// advisories that affect them. Libraries whose version could not be
// recovered are skipped: an advisory without a version cannot be attributed
// to a specific build.
func (c *Client) Lookup(ctx context.Context, sdks []models.SDK) ([]models.Vulnerability, error) {
	queries := make([]Query, 0, len(sdks))
	owners := make([]models.SDK, 0, len(sdks))
	for _, sdk := range sdks {
		if sdk.Package == "" || sdk.Version == "" {
			continue
		}
		queries = append(queries, Query{Package: sdk.Package, Version: sdk.Version, Ecosystem: EcosystemMaven})
		owners = append(owners, sdk)
	}
	if len(queries) == 0 {
		return nil, nil
	}

	results, err := c.QueryBatch(ctx, queries)
	if err != nil {
		return nil, err
	}

	var out []models.Vulnerability
	for i, res := range results {
		for _, v := range res.Vulns {
			out = append(out, models.Vulnerability{
				ID:        v.ID,
				Summary:   v.Summary,
				Severity:  CVSS(v),
				Package:   owners[i].Package,
				Version:   owners[i].Version,
				FixedIn:   FixedVersions(v),
				Aliases:   v.Aliases,
				Reference: referenceURL(v),
			})
		}
	}
	return out, nil
}

// referenceURL returns the first advisory reference that points at a human
// readable page.
func referenceURL(v Vuln) string {
	for _, r := range v.References {
		if r.URL != "" {
			return r.URL
		}
	}
	return ""
}
