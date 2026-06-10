package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// memoryETagStorage implements ETagStorage entirely in memory; used by
// the unified-source tests so they don't depend on the SQLite store.
type memoryETagStorage struct {
	mu      sync.Mutex
	storage map[string]string
}

func newMemoryETagStorage() *memoryETagStorage {
	return &memoryETagStorage{storage: map[string]string{}}
}

func (m *memoryETagStorage) GetETag(_ context.Context, source string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.storage[source], nil
}

func (m *memoryETagStorage) SaveETag(_ context.Context, source, etag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storage[source] = etag
	return nil
}

// buildOSVZip writes a zip with one JSON entry per supplied raw record,
// suitable for serving from httptest.
func buildOSVZip(t *testing.T, records []rawVulnerability) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, r := range records {
		w, err := zw.Create(r.ID + ".json")
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if err := json.NewEncoder(w).Encode(r); err != nil {
			t.Fatalf("zip encode: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func TestUnifiedAllZipSource_200_YieldsEvents(t *testing.T) {
	t0 := time.Date(2025, 10, 1, 12, 0, 0, 0, time.UTC)
	records := []rawVulnerability{
		{ID: "GHSA-1", Modified: t0, Affected: []rawAffected{{Package: rawPackage{Ecosystem: "npm", Name: "a"}}}},
		{ID: "GHSA-2", Modified: t0.Add(time.Hour), Affected: []rawAffected{{Package: rawPackage{Ecosystem: "PyPI", Name: "b"}}}},
		{ID: "GHSA-3", Modified: t0.Add(2 * time.Hour), Withdrawn: t0.Add(3 * time.Hour)},
	}
	zipBytes := buildOSVZip(t, records)
	const wantETag = `"deadbeef"`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", wantETag)
		w.Header().Set("Content-Type", "application/zip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()

	store := newMemoryETagStorage()
	src := NewUnifiedAllZipSource(store, WithUnifiedURL(srv.URL))

	seq, err := src.Fetch(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	gotIDs := map[string]SourceEvent{}
	for ev, err := range seq {
		if err != nil {
			t.Fatalf("event err: %v", err)
		}
		gotIDs[ev.ID] = ev
	}

	if len(gotIDs) != 3 {
		t.Fatalf("got %d events, want 3", len(gotIDs))
	}
	if gotIDs["GHSA-3"].Withdrawn != true || gotIDs["GHSA-3"].Vuln != nil {
		t.Errorf("GHSA-3 should be withdrawn, got %+v", gotIDs["GHSA-3"])
	}
	if gotIDs["GHSA-1"].Vuln == nil || gotIDs["GHSA-1"].Vuln.Affected[0].Ecosystem != "npm" {
		t.Errorf("GHSA-1 affected mismatch: %+v", gotIDs["GHSA-1"])
	}

	if got, _ := store.GetETag(context.Background(), UnifiedSourceCursorKey); got != wantETag {
		t.Errorf("etag stored = %q, want %q", got, wantETag)
	}
}

func TestUnifiedAllZipSource_304_YieldsNothingAndKeepsETag(t *testing.T) {
	const etag = `"abc"`
	var seenIfNoneMatch string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenIfNoneMatch = r.Header.Get("If-None-Match")
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	store := newMemoryETagStorage()
	_ = store.SaveETag(context.Background(), UnifiedSourceCursorKey, etag)

	src := NewUnifiedAllZipSource(store, WithUnifiedURL(srv.URL))
	seq, err := src.Fetch(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	for ev, err := range seq {
		t.Fatalf("expected no events from 304, got %+v err=%v", ev, err)
	}
	if seenIfNoneMatch != etag {
		t.Errorf("server did not see If-None-Match: got %q want %q", seenIfNoneMatch, etag)
	}
	if got, _ := store.GetETag(context.Background(), UnifiedSourceCursorKey); got != etag {
		t.Errorf("etag mutated to %q, want %q", got, etag)
	}
}

func TestUnifiedAllZipSource_CursorFiltersBelowAndEqual(t *testing.T) {
	t0 := time.Date(2025, 10, 1, 12, 0, 0, 0, time.UTC)
	records := []rawVulnerability{
		{ID: "old", Modified: t0.Add(-time.Hour), Affected: []rawAffected{{Package: rawPackage{Ecosystem: "npm", Name: "a"}}}},
		{ID: "boundary", Modified: t0, Affected: []rawAffected{{Package: rawPackage{Ecosystem: "npm", Name: "b"}}}},
		{ID: "new", Modified: t0.Add(time.Hour), Affected: []rawAffected{{Package: rawPackage{Ecosystem: "npm", Name: "c"}}}},
	}
	zipBytes := buildOSVZip(t, records)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"x"`)
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()

	store := newMemoryETagStorage()
	src := NewUnifiedAllZipSource(store, WithUnifiedURL(srv.URL))

	seq, err := src.Fetch(context.Background(), t0)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	var ids []string
	for ev, err := range seq {
		if err != nil {
			t.Fatalf("event err: %v", err)
		}
		ids = append(ids, ev.ID)
	}
	if len(ids) != 1 || ids[0] != "new" {
		t.Errorf("cursor filter wrong: got %v want [new] (strict >)", ids)
	}
}

func TestUnifiedAllZipSource_NonOKNon304_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	src := NewUnifiedAllZipSource(newMemoryETagStorage(), WithUnifiedURL(srv.URL))
	if _, err := src.Fetch(context.Background(), time.Time{}); err == nil {
		t.Fatal("expected error for 500 response")
	}
}

// Sanity check the test helper itself so reading other tests isn't a
// matter of trusting buildOSVZip.
func TestBuildOSVZip_RoundTrips(t *testing.T) {
	rec := rawVulnerability{ID: "X", Modified: time.Now()}
	data := buildOSVZip(t, []rawVulnerability{rec})
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("read zip: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("entries = %d, want 1", len(zr.File))
	}
	f, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("open entry: %v", err)
	}
	defer f.Close() //nolint:errcheck
	body, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read entry: %v", err)
	}
	if !bytes.Contains(body, []byte(`"id":"X"`)) {
		t.Errorf("entry missing id: %s", body)
	}
	_ = fmt.Sprintf // keep imports stable
}
