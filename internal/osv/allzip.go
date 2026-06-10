package osv

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"os"
	"time"
)

// UnifiedAllZipURL is the OSV-published mirror that aggregates every
// ecosystem's records into a single zip with per-vulnerability JSON
// files. Documented at https://google.github.io/osv.dev/data/.
const UnifiedAllZipURL = "https://osv-vulnerabilities.storage.googleapis.com/all.zip"

// UnifiedSourceCursorKey is the source_cursor row this Source owns.
// A single global key (rather than one per ecosystem) reflects that
// the zip is canonical across all ecosystems.
const UnifiedSourceCursorKey = "__unified__"

const defaultAllZipHTTPTimeout = 30 * time.Minute

// ETagStorage is the persistence dependency UnifiedAllZipSource needs
// to drive its If-None-Match optimization. A real implementation lives
// in the store package, but the Source itself doesn't import it — any
// type providing these two methods works, which keeps the dependency
// graph store→osv-free.
type ETagStorage interface {
	GetETag(ctx context.Context, source string) (string, error)
	SaveETag(ctx context.Context, source, etag string) error
}

// UnifiedAllZipSource downloads the OSV unified all.zip, sends an
// If-None-Match request to avoid re-downloading unchanged data, and
// yields one SourceEvent per JSON entry. The download lands in a temp
// file (~1.2 GiB as of the 0-S spike) because random-access reading of
// the zip's central directory is the only practical way to iterate it.
type UnifiedAllZipSource struct {
	url        string
	httpClient *http.Client
	etagStore  ETagStorage
	cursorKey  string
}

// NewUnifiedAllZipSource constructs a source pointing at the canonical
// unified all.zip URL. Override the URL via UnifiedSourceOptions for
// tests.
func NewUnifiedAllZipSource(etagStore ETagStorage, opts ...UnifiedSourceOption) *UnifiedAllZipSource {
	s := &UnifiedAllZipSource{
		url:        UnifiedAllZipURL,
		httpClient: &http.Client{Timeout: defaultAllZipHTTPTimeout},
		etagStore:  etagStore,
		cursorKey:  UnifiedSourceCursorKey,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// UnifiedSourceOption customizes a UnifiedAllZipSource for tests.
type UnifiedSourceOption func(*UnifiedAllZipSource)

// WithUnifiedURL overrides the upstream URL. Used by httptest-based tests.
func WithUnifiedURL(url string) UnifiedSourceOption {
	return func(s *UnifiedAllZipSource) { s.url = url }
}

// WithUnifiedHTTPClient overrides the HTTP client. Used by tests that
// need to pin timeouts or inspect requests.
func WithUnifiedHTTPClient(client *http.Client) UnifiedSourceOption {
	return func(s *UnifiedAllZipSource) { s.httpClient = client }
}

// Fetch downloads (or skips, on 304) the unified all.zip and returns an
// iterator over its records. Records with modified <= cursor are
// filtered out; the caller can ignore the cursor argument by passing
// time.Time{}.
//
// The returned iterator owns the temp file: it deletes the file when
// iteration completes. Callers must consume the iterator to completion
// (or abandon it via early return — the file is still cleaned up at
// process exit if the temp dir is cleaned).
func (s *UnifiedAllZipSource) Fetch(ctx context.Context, cursor time.Time) (iter.Seq2[SourceEvent, error], error) {
	prevETag, err := s.etagStore.GetETag(ctx, s.cursorKey)
	if err != nil {
		return nil, fmt.Errorf("get previous etag: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if prevETag != "" {
		req.Header.Set("If-None-Match", prevETag)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusNotModified:
		resp.Body.Close() //nolint:errcheck
		// 304 means "nothing changed"; the iterator emits nothing.
		return emptySeq, nil
	case http.StatusOK:
		// fall through
	default:
		resp.Body.Close() //nolint:errcheck
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	tmp, size, err := drainToTemp(resp.Body)
	resp.Body.Close() //nolint:errcheck
	if err != nil {
		return nil, fmt.Errorf("drain body: %w", err)
	}

	newETag := resp.Header.Get("ETag")
	if newETag != "" {
		if err := s.etagStore.SaveETag(ctx, s.cursorKey, newETag); err != nil {
			os.Remove(tmp.Name()) //nolint:errcheck
			tmp.Close()           //nolint:errcheck
			return nil, fmt.Errorf("save etag: %w", err)
		}
	}

	return newZipSeq(tmp, size, cursor), nil
}

// emptySeq is the no-event iterator used when the server returns 304.
func emptySeq(yield func(SourceEvent, error) bool) {}

// drainToTemp copies r into a unique temp file in the OS temp dir,
// returning the open *os.File rewound to offset 0 ready for reading
// and the byte count. The caller owns the file: close and remove it
// when done.
func drainToTemp(r io.Reader) (*os.File, int64, error) {
	tmp, err := os.CreateTemp("", "osv-allzip-*.zip")
	if err != nil {
		return nil, 0, fmt.Errorf("create temp file: %w", err)
	}
	n, err := io.Copy(tmp, r)
	if err != nil {
		tmp.Close()           //nolint:errcheck
		os.Remove(tmp.Name()) //nolint:errcheck
		return nil, 0, fmt.Errorf("copy body: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		tmp.Close()           //nolint:errcheck
		os.Remove(tmp.Name()) //nolint:errcheck
		return nil, 0, fmt.Errorf("rewind temp file: %w", err)
	}
	return tmp, n, nil
}

// newZipSeq returns an iterator that decodes one rawVulnerability per
// zip entry, filters by cursor, and yields SourceEvents. The temp file
// is deleted when iteration finishes (or when the iterator is closed
// early via break).
func newZipSeq(tmp *os.File, size int64, cursor time.Time) iter.Seq2[SourceEvent, error] {
	return func(yield func(SourceEvent, error) bool) {
		defer func() {
			tmp.Close()           //nolint:errcheck
			os.Remove(tmp.Name()) //nolint:errcheck
		}()

		zr, err := zip.NewReader(tmp, size)
		if err != nil {
			yield(SourceEvent{}, fmt.Errorf("open zip: %w", err))
			return
		}

		for _, file := range zr.File {
			if file.FileInfo().IsDir() {
				continue
			}
			ev, err := decodeZipEntry(file, cursor)
			if err != nil {
				if !yield(SourceEvent{}, err) {
					return
				}
				continue
			}
			if ev.ID == "" {
				// Below-cursor entry; skipped without notification.
				continue
			}
			if !yield(ev, nil) {
				return
			}
		}
	}
}

// decodeZipEntry reads a single JSON file from the zip and converts it
// to a SourceEvent. Returns ev with zero ID if the record is filtered
// out by cursor (so the caller can distinguish "skip" from "emit").
func decodeZipEntry(file *zip.File, cursor time.Time) (SourceEvent, error) {
	rc, err := file.Open()
	if err != nil {
		return SourceEvent{}, fmt.Errorf("open %s: %w", file.Name, err)
	}
	defer rc.Close() //nolint:errcheck

	var raw rawVulnerability
	if err := json.NewDecoder(rc).Decode(&raw); err != nil {
		return SourceEvent{}, fmt.Errorf("decode %s: %w", file.Name, err)
	}

	// Cursor filter: drop records whose modified time is not strictly
	// after cursor. !After handles the cursor=zero case (everything
	// passes) and avoids re-emitting boundary records on consecutive
	// fetches.
	if !cursor.IsZero() && !raw.Modified.After(cursor) {
		return SourceEvent{}, nil
	}

	if !raw.Withdrawn.IsZero() {
		return SourceEvent{ID: raw.ID, Withdrawn: true}, nil
	}
	return SourceEvent{ID: raw.ID, Vuln: normalize(&raw)}, nil
}
