package app

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-report/internal/model"
	"github.com/pHo9UBenaA/osv-report/internal/osv"
	"github.com/pHo9UBenaA/osv-report/internal/store"
)

type fakeClient struct {
	vulns map[string]*model.Vulnerability
}

func (f *fakeClient) GetVulnerability(_ context.Context, id string) (*model.Vulnerability, error) {
	if v, ok := f.vulns[id]; ok {
		return v, nil
	}
	return nil, osv.ErrNotFound
}

type fakeStore struct {
	mu            sync.Mutex
	savedVulns    []store.Vulnerability
	savedAffected []store.Affected
	tombstones    []string
}

func (f *fakeStore) GetCursor(_ context.Context, _ string) (time.Time, error) {
	return time.Time{}, nil
}
func (f *fakeStore) SaveCursor(_ context.Context, _ string, _ time.Time) error { return nil }
func (f *fakeStore) DeleteVulnerabilitiesOlderThan(_ context.Context, _ time.Time) error {
	return nil
}

func (f *fakeStore) SaveVulnerabilityWithAffected(_ context.Context, v store.Vulnerability, affected []store.Affected) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.savedVulns = append(f.savedVulns, v)
	f.savedAffected = append(f.savedAffected, affected...)
	return nil
}

func (f *fakeStore) SaveTombstone(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tombstones = append(f.tombstones, id)
	return nil
}

func TestProcessEntry_VulnFound_SavesVulnAndAffected(t *testing.T) {
	client := &fakeClient{vulns: map[string]*model.Vulnerability{
		"GHSA-test-1": {
			ID:        "GHSA-test-1",
			Modified:  time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
			Published: time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC),
			Summary:   "Test vulnerability",
			Affected: []model.AffectedPackage{
				{Ecosystem: "npm", Name: "express"},
			},
			Severity: []model.SeverityEntry{
				{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			},
		},
	}}
	st := &fakeStore{}
	entry := model.Entry{ID: "GHSA-test-1", Modified: time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)}

	err := processEntry(context.Background(), client, st, entry)
	if err != nil {
		t.Fatalf("processEntry() error = %v", err)
	}

	if len(st.savedVulns) != 1 {
		t.Fatalf("savedVulns count = %d, want 1", len(st.savedVulns))
	}
	v := st.savedVulns[0]
	if v.ID != "GHSA-test-1" {
		t.Errorf("ID = %q, want GHSA-test-1", v.ID)
	}
	wantModified := time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)
	if !v.Modified.Equal(wantModified) {
		t.Errorf("Modified = %v, want %v", v.Modified, wantModified)
	}
	wantPublished := time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC)
	if !v.Published.Equal(wantPublished) {
		t.Errorf("Published = %v, want %v", v.Published, wantPublished)
	}
	if v.Summary != "Test vulnerability" {
		t.Errorf("Summary = %q, want %q", v.Summary, "Test vulnerability")
	}
	if v.SeverityBaseScore == nil || *v.SeverityBaseScore != 9.8 {
		t.Errorf("SeverityBaseScore = %v, want 9.8", v.SeverityBaseScore)
	}
	if v.SeverityVector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("SeverityVector = %q, want CVSS vector", v.SeverityVector)
	}
	if len(st.savedAffected) != 1 {
		t.Fatalf("savedAffected count = %d, want 1", len(st.savedAffected))
	}
	a := st.savedAffected[0]
	if a.VulnID != "GHSA-test-1" {
		t.Errorf("savedAffected[0].VulnID = %q, want GHSA-test-1", a.VulnID)
	}
	if a.Ecosystem != "npm" || a.Package != "express" {
		t.Errorf("savedAffected[0] = {%q, %q}, want {npm, express}", a.Ecosystem, a.Package)
	}
}

func TestProcessEntry_NotFound_SavesTombstone(t *testing.T) {
	client := &fakeClient{vulns: map[string]*model.Vulnerability{}}
	st := &fakeStore{}
	entry := model.Entry{ID: "GHSA-gone-1", Modified: time.Now()}

	err := processEntry(context.Background(), client, st, entry)
	if err != nil {
		t.Fatalf("processEntry() error = %v", err)
	}

	if len(st.tombstones) != 1 || st.tombstones[0] != "GHSA-gone-1" {
		t.Errorf("tombstones = %v, want [GHSA-gone-1]", st.tombstones)
	}
	if len(st.savedVulns) != 0 {
		t.Errorf("savedVulns count = %d, want 0", len(st.savedVulns))
	}
}

func TestProcessEntry_ClientError_PropagatesError(t *testing.T) {
	client := &errorClient{err: fmt.Errorf("network failure")}
	st := &fakeStore{}
	entry := model.Entry{ID: "GHSA-err-1", Modified: time.Now()}

	err := processEntry(context.Background(), client, st, entry)
	if err == nil {
		t.Fatal("processEntry() expected error, got nil")
	}
}

type errorClient struct {
	err error
}

func (e *errorClient) GetVulnerability(_ context.Context, _ string) (*model.Vulnerability, error) {
	return nil, e.err
}

func TestProcessEntriesParallel_MultipleEntries_AllProcessed(t *testing.T) {
	vulns := map[string]*model.Vulnerability{
		"V-1": {ID: "V-1", Modified: time.Now(), Affected: []model.AffectedPackage{{Ecosystem: "npm", Name: "p1"}}},
		"V-2": {ID: "V-2", Modified: time.Now(), Affected: []model.AffectedPackage{{Ecosystem: "npm", Name: "p2"}}},
		"V-3": {ID: "V-3", Modified: time.Now(), Affected: []model.AffectedPackage{{Ecosystem: "npm", Name: "p3"}}},
	}
	client := &fakeClient{vulns: vulns}
	st := &fakeStore{}
	entries := []model.Entry{
		{ID: "V-1", Modified: time.Now()},
		{ID: "V-2", Modified: time.Now()},
		{ID: "V-3", Modified: time.Now()},
	}

	err := processEntriesParallel(context.Background(), client, st, entries, 2)
	if err != nil {
		t.Fatalf("processEntriesParallel() error = %v", err)
	}

	if len(st.savedVulns) != 3 {
		t.Fatalf("savedVulns count = %d, want 3", len(st.savedVulns))
	}

	vulnByID := make(map[string]store.Vulnerability)
	for _, v := range st.savedVulns {
		vulnByID[v.ID] = v
	}
	for _, id := range []string{"V-1", "V-2", "V-3"} {
		if _, ok := vulnByID[id]; !ok {
			t.Errorf("missing vuln ID %q in saved vulns", id)
		}
	}

	affectedByVuln := make(map[string]store.Affected)
	for _, a := range st.savedAffected {
		affectedByVuln[a.VulnID] = a
	}
	if len(st.savedAffected) != 3 {
		t.Fatalf("savedAffected count = %d, want 3", len(st.savedAffected))
	}
	if affectedByVuln["V-1"].Package != "p1" {
		t.Errorf("V-1 affected package = %q, want p1", affectedByVuln["V-1"].Package)
	}
}

func TestProcessEntriesParallel_ZeroConcurrency_FallsBackToSerial(t *testing.T) {
	vulns := map[string]*model.Vulnerability{
		"V-1": {ID: "V-1", Modified: time.Now()},
		"V-2": {ID: "V-2", Modified: time.Now()},
	}
	client := &fakeClient{vulns: vulns}
	st := &fakeStore{}
	entries := []model.Entry{
		{ID: "V-1", Modified: time.Now()},
		{ID: "V-2", Modified: time.Now()},
	}

	err := processEntriesParallel(context.Background(), client, st, entries, 0)
	if err != nil {
		t.Fatalf("processEntriesParallel() error = %v", err)
	}

	if len(st.savedVulns) != 2 {
		t.Errorf("savedVulns count = %d, want 2", len(st.savedVulns))
	}
}
