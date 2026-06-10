package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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

// drainEvents collects every event from a FetchResult, failing the test
// on any iterator error so individual tests stay focused on their
// happy-path assertions.
func drainEvents(t *testing.T, result *FetchResult) []SourceEvent {
	t.Helper()
	var out []SourceEvent
	for ev, err := range result.Events {
		if err != nil {
			t.Fatalf("event err: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

func TestUnifiedAllZipSource_200_ReturnsETag(t *testing.T) {
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

	src := NewUnifiedAllZipSource(WithUnifiedURL(srv.URL))
	result, err := src.Fetch(context.Background(), time.Time{}, "")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result.NotModified {
		t.Errorf("200 should not set NotModified")
	}
	if result.ETag != wantETag {
		t.Errorf("ETag = %q, want %q", result.ETag, wantETag)
	}

	events := drainEvents(t, result)
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3", len(events))
	}

	byID := map[string]SourceEvent{}
	for _, ev := range events {
		byID[ev.ID] = ev
	}
	if byID["GHSA-3"].Withdrawn != true || byID["GHSA-3"].Vuln != nil {
		t.Errorf("GHSA-3 should be withdrawn, got %+v", byID["GHSA-3"])
	}
	if byID["GHSA-3"].Modified.IsZero() {
		t.Errorf("withdrawn event should still carry Modified, got zero")
	}
	if byID["GHSA-1"].Vuln == nil || byID["GHSA-1"].Vuln.Affected[0].Ecosystem != "npm" {
		t.Errorf("GHSA-1 affected mismatch: %+v", byID["GHSA-1"])
	}
}

func TestUnifiedAllZipSource_304_SetsNotModified(t *testing.T) {
	const prev = `"abc"`
	var seenIfNoneMatch string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenIfNoneMatch = r.Header.Get("If-None-Match")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	src := NewUnifiedAllZipSource(WithUnifiedURL(srv.URL))
	result, err := src.Fetch(context.Background(), time.Time{}, prev)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !result.NotModified {
		t.Errorf("304 should set NotModified")
	}
	if result.ETag != "" {
		t.Errorf("304 must leave ETag empty so callers do not overwrite their saved value, got %q", result.ETag)
	}
	if events := drainEvents(t, result); len(events) != 0 {
		t.Errorf("304 must yield no events, got %d", len(events))
	}
	if seenIfNoneMatch != prev {
		t.Errorf("If-None-Match = %q, want %q", seenIfNoneMatch, prev)
	}
}

func TestUnifiedAllZipSource_CorruptZip_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"corrupt"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("definitely not a zip file"))
	}))
	defer srv.Close()

	src := NewUnifiedAllZipSource(WithUnifiedURL(srv.URL))
	result, err := src.Fetch(context.Background(), time.Time{}, "")
	if err == nil {
		t.Fatalf("expected fatal error for corrupt zip, got result=%+v", result)
	}
	if result != nil {
		t.Errorf("result must be nil on fatal Fetch error, got %+v", result)
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

	src := NewUnifiedAllZipSource(WithUnifiedURL(srv.URL))
	result, err := src.Fetch(context.Background(), t0, "")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	events := drainEvents(t, result)
	var ids []string
	for _, ev := range events {
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

	src := NewUnifiedAllZipSource(WithUnifiedURL(srv.URL))
	if _, err := src.Fetch(context.Background(), time.Time{}, ""); err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestUnifiedAllZipSource_NoPrevETag_OmitsIfNoneMatch(t *testing.T) {
	var headerSent bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["If-None-Match"]; ok {
			headerSent = true
		}
		w.Header().Set("ETag", `"a"`)
		_, _ = w.Write(buildOSVZip(t, nil))
	}))
	defer srv.Close()

	src := NewUnifiedAllZipSource(WithUnifiedURL(srv.URL))
	if _, err := src.Fetch(context.Background(), time.Time{}, ""); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if headerSent {
		t.Errorf("If-None-Match should not be sent when prevETag is empty")
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
}
