package llm

import (
	"context"
	"net/http"
	"time"
)

var probeHTTPClient = &http.Client{Timeout: 2 * time.Second}

// probeHTTPEndpoint checks if a local HTTP endpoint is reachable.
func probeHTTPEndpoint(ctx context.Context, baseURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return false
	}
	resp, err := probeHTTPClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 500
}
