package osv

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/pHo9UBenaA/osv-report/internal/model"
)

const defaultSitemapHTTPTimeout = 30 * time.Second

// vulnIDPattern extracts vulnerability IDs from sitemap URLs.
// Compiled once at package level to avoid per-call overhead.
var vulnIDPattern = regexp.MustCompile(`/vulnerability/([A-Za-z0-9]+-[A-Za-z0-9-]+)`)

// sitemapURL represents a URL entry in the sitemap.
type sitemapURL struct {
	Loc     string `xml:"loc"`
	LastMod string `xml:"lastmod"`
}

// sitemapURLSet represents the root element of a sitemap XML.
type sitemapURLSet struct {
	XMLName xml.Name     `xml:"urlset"`
	URLs    []sitemapURL `xml:"url"`
}

// SitemapFetcher fetches vulnerability list from OSV sitemap.
type SitemapFetcher struct {
	url        string
	httpClient *http.Client
	cursor     time.Time
}

// SitemapFetcherOption configures a SitemapFetcher.
type SitemapFetcherOption func(*SitemapFetcher)

// WithSitemapHTTPClient sets a custom HTTP client on the sitemap fetcher.
func WithSitemapHTTPClient(client *http.Client) SitemapFetcherOption {
	return func(f *SitemapFetcher) {
		f.httpClient = client
	}
}

// WithSitemapCursor sets the cursor used to filter sitemap entries.
func WithSitemapCursor(cursor time.Time) SitemapFetcherOption {
	return func(f *SitemapFetcher) {
		f.cursor = cursor
	}
}

// NewSitemapFetcher creates a new sitemap fetcher with optional configuration.
func NewSitemapFetcher(url string, opts ...SitemapFetcherOption) *SitemapFetcher {
	f := &SitemapFetcher{
		url:        url,
		httpClient: &http.Client{Timeout: defaultSitemapHTTPTimeout},
	}

	for _, opt := range opts {
		opt(f)
	}

	if f.httpClient == nil {
		f.httpClient = &http.Client{Timeout: defaultSitemapHTTPTimeout}
	} else if f.httpClient.Timeout == 0 {
		f.httpClient.Timeout = defaultSitemapHTTPTimeout
	}

	return f
}

// Fetch downloads and parses the sitemap XML to extract vulnerability IDs and lastmod.
func (f *SitemapFetcher) Fetch(ctx context.Context) ([]model.Entry, error) {
	body, err := sitemapHTTPGet(ctx, f.httpClient, f.url)
	if err != nil {
		return nil, err
	}

	return f.parseSitemap(body)
}

// HTTPClientTimeout returns the configured HTTP client timeout.
func (f *SitemapFetcher) HTTPClientTimeout() time.Duration {
	if f.httpClient == nil {
		return 0
	}
	return f.httpClient.Timeout
}

func (f *SitemapFetcher) parseSitemap(xmlData []byte) ([]model.Entry, error) {
	var urlset sitemapURLSet
	if err := xml.Unmarshal(xmlData, &urlset); err != nil {
		return nil, fmt.Errorf("unmarshal sitemap: %w", err)
	}

	var entries []model.Entry
	for _, u := range urlset.URLs {
		lastmod, err := time.Parse(time.RFC3339, u.LastMod)
		if err != nil {
			// Skip entries with invalid lastmod
			continue
		}

		// Filter by cursor
		if !f.cursor.IsZero() && !lastmod.After(f.cursor) {
			continue
		}

		// Extract vulnerability ID from URL
		matches := vulnIDPattern.FindStringSubmatch(u.Loc)
		if len(matches) < 2 {
			continue
		}

		entries = append(entries, model.Entry{
			ID:       matches[1],
			Modified: lastmod,
		})
	}

	return entries, nil
}

func sitemapHTTPGet(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: defaultSitemapHTTPTimeout}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return body, nil
}
