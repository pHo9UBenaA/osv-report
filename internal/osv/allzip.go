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

// UnifiedAllZipSource downloads the OSV unified all.zip, optionally
// sending If-None-Match to avoid re-downloading unchanged data, and
// yields one SourceEvent per JSON entry. The download lands in a temp
// file (~1.2 GiB as of the 0-S spike) because random-access reading of
// the zip's central directory is the only practical way to iterate it.
//
// State persistence (ETag, cursor) is the caller's responsibility — see
// app.Fetch. This keeps the Source free of any database dependency.
type UnifiedAllZipSource struct {
	url        string
	httpClient *http.Client
}

// NewUnifiedAllZipSource constructs a source pointing at the canonical
// unified all.zip URL. Override the URL via UnifiedSourceOptions for
// tests.
func NewUnifiedAllZipSource(opts ...UnifiedSourceOption) *UnifiedAllZipSource {
	s := &UnifiedAllZipSource{
		url:        UnifiedAllZipURL,
		httpClient: &http.Client{Timeout: defaultAllZipHTTPTimeout},
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

// Fetch downloads (or skips, on 304) the unified all.zip and returns
// the result the caller commits at the end of the run.
//
// A zip-open failure is fatal and reported as a non-nil error here so
// the caller treats it as "no state advance" instead of consuming a
// per-event error from an iterator that has nothing to give. Per-entry
// decode errors come through the iterator the usual way.
//
// The returned iterator owns the temp file: it deletes the file when
// iteration completes or is abandoned via early return. Callers should
// consume the iterator even on a context cancel so the cleanup runs.
func (s *UnifiedAllZipSource) Fetch(ctx context.Context, cursor time.Time, prevETag string) (*FetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if prevETag != "" {
		// Source.Fetch contract: only attach If-None-Match when a previous
		// ETag is known. Sending an empty value makes the upstream answer
		// 200 every time, which is worse than not sending it at all.
		req.Header.Set("If-None-Match", prevETag)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusNotModified:
		resp.Body.Close() //nolint:errcheck
		// 304: ETag must be empty (contract pinned by tests) so callers
		// keep their previously persisted value.
		return &FetchResult{Events: emptySeq, ETag: "", NotModified: true}, nil
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

	// Open the zip eagerly so a truncated / corrupt download becomes a
	// Fetch-level error rather than a single per-entry error the caller
	// might swallow as "just one bad record".
	zr, err := zip.NewReader(tmp, size)
	if err != nil {
		tmp.Close()           //nolint:errcheck
		os.Remove(tmp.Name()) //nolint:errcheck
		return nil, fmt.Errorf("open zip: %w", err)
	}

	return &FetchResult{
		Events: zipSeqFromReader(ctx, zr, tmp, cursor),
		ETag:   resp.Header.Get("ETag"),
	}, nil
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

// zipSeqFromReader iterates an already-opened zip reader, decoding one
// rawVulnerability per entry, filtering by cursor, and yielding
// SourceEvents. The temp file is closed and deleted when iteration
// finishes (or when the iterator is closed early via break).
//
// ctx.Err is checked at the top of every entry so a long decode loop
// honours Ctrl-C even though the HTTP download is already complete.
func zipSeqFromReader(ctx context.Context, zr *zip.Reader, tmp *os.File, cursor time.Time) iter.Seq2[SourceEvent, error] {
	return func(yield func(SourceEvent, error) bool) {
		defer func() {
			tmp.Close()           //nolint:errcheck
			os.Remove(tmp.Name()) //nolint:errcheck
		}()

		for _, file := range zr.File {
			if err := ctx.Err(); err != nil {
				yield(SourceEvent{}, err)
				return
			}
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
// Both active and withdrawn events carry Modified so the cursor
// machinery can advance off either path.
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
		return SourceEvent{ID: raw.ID, Modified: raw.Modified, Withdrawn: true}, nil
	}
	return SourceEvent{ID: raw.ID, Modified: raw.Modified, Vuln: normalize(&raw)}, nil
}
