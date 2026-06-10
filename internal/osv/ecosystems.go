package osv

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const defaultEcosystemsHTTPTimeout = 10 * time.Second

// EcosystemsFetcher retrieves the canonical OSV ecosystem list over HTTP.
// Consumers should depend on a locally-defined interface; this concrete type
// satisfies them structurally.
type EcosystemsFetcher struct {
	url        string
	httpClient *http.Client
}

// NewEcosystemsFetcher creates a fetcher that retrieves ecosystems from the given URL.
func NewEcosystemsFetcher(url string, client *http.Client) *EcosystemsFetcher {
	if client == nil {
		client = &http.Client{Timeout: defaultEcosystemsHTTPTimeout}
	}
	return &EcosystemsFetcher{url: url, httpClient: client}
}

// FetchEcosystems downloads the ecosystem list and returns the parsed names.
func (f *EcosystemsFetcher) FetchEcosystems(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch ecosystems: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return ParseEcosystemsTxt(body), nil
}

// ParseEcosystemsTxt parses a newline-separated list of ecosystem names.
// Empty lines are skipped.
func ParseEcosystemsTxt(data []byte) []string {
	var ecosystems []string
	for _, line := range bytes.Split(data, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			ecosystems = append(ecosystems, string(trimmed))
		}
	}
	return ecosystems
}
