package osv

import (
	"testing"
	"time"
)

func TestNormalize_MapsAllFields(t *testing.T) {
	modified := time.Date(2025, 10, 1, 12, 0, 0, 0, time.UTC)
	published := time.Date(2025, 9, 30, 8, 0, 0, 0, time.UTC)
	raw := &rawVulnerability{
		ID:        "GHSA-1234",
		Modified:  modified,
		Published: published,
		Summary:   "summary text",
		Details:   "details text",
		Affected: []rawAffected{
			{Package: rawPackage{Ecosystem: "npm", Name: "lodash"}},
			{Package: rawPackage{Ecosystem: "Go", Name: "go.example/m"}},
		},
		Severity: []rawSeverity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
	}

	got := normalize(raw)
	if got.ID != raw.ID {
		t.Errorf("ID = %q, want %q", got.ID, raw.ID)
	}
	if !got.Modified.Equal(raw.Modified) {
		t.Errorf("Modified = %v, want %v", got.Modified, raw.Modified)
	}
	if !got.Published.Equal(raw.Published) {
		t.Errorf("Published = %v, want %v", got.Published, raw.Published)
	}
	if got.Summary != raw.Summary || got.Details != raw.Details {
		t.Errorf("Summary/Details mismatch: %+v", got)
	}
	if len(got.Affected) != 2 || got.Affected[0].Ecosystem != "npm" || got.Affected[1].Name != "go.example/m" {
		t.Errorf("Affected = %+v", got.Affected)
	}
	if len(got.Severity) != 1 || got.Severity[0].Type != "CVSS_V3" {
		t.Errorf("Severity = %+v", got.Severity)
	}
}

func TestNormalize_EmptyAffectedAndSeverity(t *testing.T) {
	raw := &rawVulnerability{ID: "GHSA-empty", Modified: time.Now()}
	got := normalize(raw)
	if len(got.Affected) != 0 {
		t.Errorf("expected empty Affected, got %+v", got.Affected)
	}
	if len(got.Severity) != 0 {
		t.Errorf("expected empty Severity, got %+v", got.Severity)
	}
}
