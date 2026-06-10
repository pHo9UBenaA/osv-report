package store_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-report/internal/store"
)

func ptrFloat64(v float64) *float64 { return &v }

// newTestStore creates a temp-dir SQLite store and registers Close as cleanup.
// Returned dbPath lets callers open a second handle for direct SQL inspection.
func newTestStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := store.NewStore(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dbPath
}

func TestNewStore_ForeignKeysEnabled(t *testing.T) {
	_, dbPath := newTestStore(t)
	ctx := context.Background()

	// PRAGMA foreign_keys is per-connection in SQLite. Verify the driver-level
	// DSN configuration applies the pragma to every pooled connection by
	// opening an independent handle and inspecting the value there.
	db, err := sql.Open(store.DriverName, store.OpenDSN(dbPath))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer db.Close() //nolint:errcheck

	var enabled int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&enabled); err != nil {
		t.Fatalf("query PRAGMA foreign_keys: %v", err)
	}
	if enabled != 1 {
		t.Errorf("PRAGMA foreign_keys = %d, want 1", enabled)
	}
}

func TestNewStore_ValidPath_CreatesDatabaseFile(t *testing.T) {
	_, dbPath := newTestStore(t)

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Errorf("database file was not created at %s", dbPath)
	}
}

func TestSaveThenGetCursor_ReturnsSavedTimestamp(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	source := "test-ecosystem"
	cursor := time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC)

	if err := s.SaveCursor(ctx, source, cursor); err != nil {
		t.Fatalf("SaveCursor() error = %v", err)
	}

	got, err := s.GetCursor(ctx, source)
	if err != nil {
		t.Fatalf("GetCursor() error = %v", err)
	}

	if !got.Equal(cursor) {
		t.Errorf("GetCursor() = %v, want %v", got, cursor)
	}
}

func TestGetCursor_ErrorConditions(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	t.Run("NonExistentSource_ReturnsNoRowsError", func(t *testing.T) {
		_, err := s.GetCursor(ctx, "non-existent-source")
		if err == nil {
			t.Fatal("GetCursor() with non-existent source should return error")
		}

		if err != sql.ErrNoRows {
			t.Errorf("GetCursor() should return sql.ErrNoRows directly for non-existent source, got: %v (type: %T)", err, err)
		}
	})

	t.Run("DBError_DistinguishedFromNoRows", func(t *testing.T) {
		originalStore := s
		s.Close() //nolint:errcheck

		_, err := originalStore.GetCursor(ctx, "any-source")
		if err == nil {
			t.Fatal("GetCursor() on closed DB should return error")
		}

		if err == sql.ErrNoRows {
			t.Errorf("GetCursor() DB error should NOT be sql.ErrNoRows, got: %v", err)
		}
	})
}

func TestSaveVulnerability_NewEntry_PersistsIdempotently(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	vuln := store.Vulnerability{
		ID:       "GHSA-xxxx-yyyy-zzzz",
		Modified: time.Date(2025, 10, 4, 12, 34, 56, 0, time.UTC),
	}

	if err := s.SaveVulnerability(ctx, vuln); err != nil {
		t.Fatalf("SaveVulnerability() error = %v", err)
	}

	if err := s.SaveVulnerability(ctx, vuln); err != nil {
		t.Fatalf("SaveVulnerability() second call error = %v", err)
	}
}

func TestSaveVulnerability_NullThenUpdate_SeverityFieldsPersist(t *testing.T) {
	s, dbPath := newTestStore(t)
	ctx := context.Background()

	vulnID := "GHSA-severity-check"
	modified := time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC)

	if err := s.SaveVulnerability(ctx, store.Vulnerability{ID: vulnID, Modified: modified}); err != nil {
		t.Fatalf("SaveVulnerability() error = %v", err)
	}

	db, err := sql.Open(store.DriverName, store.OpenDSN(dbPath))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer db.Close() //nolint:errcheck

	var base sql.NullFloat64
	var vector sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT severity_base_score, severity_vector FROM vulnerability WHERE id = ?", vulnID).Scan(&base, &vector); err != nil {
		t.Fatalf("query severity fields: %v", err)
	}

	if base.Valid {
		t.Error("severity_base_score should be NULL when not provided")
	}
	if vector.Valid {
		t.Error("severity_vector should be NULL when not provided")
	}

	update := store.Vulnerability{
		ID:                vulnID,
		Modified:          modified.Add(time.Minute),
		SeverityBaseScore: sql.NullFloat64{Float64: 7.5, Valid: true},
		SeverityVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L",
	}

	if err := s.SaveVulnerability(ctx, update); err != nil {
		t.Fatalf("SaveVulnerability(update) error = %v", err)
	}

	if err := db.QueryRowContext(ctx, "SELECT severity_base_score, severity_vector FROM vulnerability WHERE id = ?", vulnID).Scan(&base, &vector); err != nil {
		t.Fatalf("query severity fields after update: %v", err)
	}

	if !base.Valid || base.Float64 != 7.5 {
		t.Errorf("severity_base_score = %v (valid=%v), want 7.5 and true", base.Float64, base.Valid)
	}
	if !vector.Valid || vector.String != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L" {
		t.Errorf("severity_vector = %q (valid=%v), want expected vector", vector.String, vector.Valid)
	}
}

func TestSaveVulnerability_WithSummaryAndDetails_PersistsAllFields(t *testing.T) {
	s, dbPath := newTestStore(t)
	ctx := context.Background()

	vuln := store.Vulnerability{
		ID:       "GHSA-detail-test",
		Modified: time.Date(2025, 10, 4, 12, 34, 56, 0, time.UTC),
		Summary:  "Test vulnerability summary",
		Details:  "Detailed description of the vulnerability",
	}

	if err := s.SaveVulnerability(ctx, vuln); err != nil {
		t.Fatalf("SaveVulnerability() error = %v", err)
	}

	db, err := sql.Open(store.DriverName, store.OpenDSN(dbPath))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer db.Close() //nolint:errcheck

	var summary, details string
	err = db.QueryRowContext(ctx, "SELECT summary, details FROM vulnerability WHERE id = ?", vuln.ID).Scan(&summary, &details)
	if err != nil {
		t.Fatalf("query summary/details: %v", err)
	}

	if summary != "Test vulnerability summary" {
		t.Errorf("summary = %q, want %q", summary, "Test vulnerability summary")
	}
	if details != "Detailed description of the vulnerability" {
		t.Errorf("details = %q, want %q", details, "Detailed description of the vulnerability")
	}
}

func TestNewStore_SchemaIndexes_ExistAfterCreation(t *testing.T) {
	_, dbPath := newTestStore(t)
	ctx := context.Background()

	db, err := sql.Open(store.DriverName, store.OpenDSN(dbPath))
	if err != nil {
		t.Fatalf("Open database error = %v", err)
	}
	defer db.Close() //nolint:errcheck

	indexes := []string{"idx_affected_ecosystem", "idx_vulnerability_modified"}
	for _, idx := range indexes {
		var count int
		err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", idx).Scan(&count)
		if err != nil {
			t.Fatalf("Query index %s error = %v", idx, err)
		}
		if count != 1 {
			t.Errorf("index %s not found", idx)
		}
	}
}

func TestSaveAffected_NewRecord_Persists(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	vulnID := "GHSA-test-affected"
	if err := s.SaveVulnerability(ctx, store.Vulnerability{
		ID:       vulnID,
		Modified: time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("SaveVulnerability() error = %v", err)
	}

	affected := store.Affected{
		VulnID:    vulnID,
		Ecosystem: "Go",
		Package:   "github.com/test/pkg",
	}

	if err := s.SaveAffected(ctx, affected); err != nil {
		t.Fatalf("SaveAffected() error = %v", err)
	}
}

func TestSaveTombstone_NewAndDuplicate_PersistsIdempotently(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	id := "GHSA-deleted-vuln"

	if err := s.SaveTombstone(ctx, id); err != nil {
		t.Fatalf("SaveTombstone() error = %v", err)
	}

	if err := s.SaveTombstone(ctx, id); err != nil {
		t.Fatalf("SaveTombstone() second call error = %v", err)
	}
}

func TestDeleteVulnerabilitiesOlderThan_MixedAges_RemovesOnlyOld(t *testing.T) {
	s, dbPath := newTestStore(t)
	ctx := context.Background()

	oldTime := time.Now().AddDate(0, 0, -14)
	oldVuln := store.Vulnerability{
		ID:       "GHSA-old-vuln",
		Modified: oldTime,
	}
	if err := s.SaveVulnerability(ctx, oldVuln); err != nil {
		t.Fatalf("SaveVulnerability(old) error = %v", err)
	}

	oldAffected := store.Affected{
		VulnID:    "GHSA-old-vuln",
		Ecosystem: "npm",
		Package:   "old-package",
	}
	if err := s.SaveAffected(ctx, oldAffected); err != nil {
		t.Fatalf("SaveAffected(old) error = %v", err)
	}

	newTime := time.Now().AddDate(0, 0, -3)
	newVuln := store.Vulnerability{
		ID:       "GHSA-new-vuln",
		Modified: newTime,
	}
	if err := s.SaveVulnerability(ctx, newVuln); err != nil {
		t.Fatalf("SaveVulnerability(new) error = %v", err)
	}

	newAffected := store.Affected{
		VulnID:    "GHSA-new-vuln",
		Ecosystem: "npm",
		Package:   "new-package",
	}
	if err := s.SaveAffected(ctx, newAffected); err != nil {
		t.Fatalf("SaveAffected(new) error = %v", err)
	}

	cutoff := time.Now().AddDate(0, 0, -7)
	if err := s.DeleteVulnerabilitiesOlderThan(ctx, cutoff); err != nil {
		t.Fatalf("DeleteVulnerabilitiesOlderThan() error = %v", err)
	}

	db, err := sql.Open(store.DriverName, store.OpenDSN(dbPath))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer db.Close() //nolint:errcheck

	var oldCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM vulnerability WHERE id = ?", "GHSA-old-vuln").Scan(&oldCount)
	if err != nil {
		t.Fatalf("query old vulnerability error = %v", err)
	}
	if oldCount != 0 {
		t.Errorf("old vulnerability was not deleted, count = %d", oldCount)
	}

	var newCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM vulnerability WHERE id = ?", "GHSA-new-vuln").Scan(&newCount)
	if err != nil {
		t.Fatalf("query new vulnerability error = %v", err)
	}
	if newCount != 1 {
		t.Errorf("new vulnerability was deleted, count = %d", newCount)
	}

	var oldAffectedCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM affected WHERE vuln_id = ?", "GHSA-old-vuln").Scan(&oldAffectedCount)
	if err != nil {
		t.Fatalf("query old affected error = %v", err)
	}
	if oldAffectedCount != 0 {
		t.Errorf("old affected was not deleted, count = %d", oldAffectedCount)
	}

	var newAffectedCount int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM affected WHERE vuln_id = ?", "GHSA-new-vuln").Scan(&newAffectedCount)
	if err != nil {
		t.Fatalf("query new affected error = %v", err)
	}
	if newAffectedCount != 1 {
		t.Errorf("new affected was deleted, count = %d", newAffectedCount)
	}
}

func TestGetVulnerabilitiesForReport_MultipleEcosystems_FiltersCorrectly(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	vuln1 := store.Vulnerability{
		ID:                "GHSA-1234-5678-90ab",
		Modified:          time.Now(),
		Summary:           "Test vulnerability 1",
		Details:           "Details for test vulnerability 1",
		SeverityBaseScore: sql.NullFloat64{Float64: 9.8, Valid: true},
		SeverityVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}
	if err := s.SaveVulnerability(ctx, vuln1); err != nil {
		t.Fatalf("SaveVulnerability(1) error = %v", err)
	}

	affected1 := store.Affected{
		VulnID:    "GHSA-1234-5678-90ab",
		Ecosystem: "npm",
		Package:   "test-package-1",
	}
	if err := s.SaveAffected(ctx, affected1); err != nil {
		t.Fatalf("SaveAffected(1) error = %v", err)
	}

	vuln2 := store.Vulnerability{
		ID:             "GHSA-abcd-efgh-ijkl",
		Modified:       time.Now(),
		Summary:        "Test vulnerability 2",
		Details:        "Details for test vulnerability 2",
		SeverityVector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
	}
	if err := s.SaveVulnerability(ctx, vuln2); err != nil {
		t.Fatalf("SaveVulnerability(2) error = %v", err)
	}

	affected2 := store.Affected{
		VulnID:    "GHSA-abcd-efgh-ijkl",
		Ecosystem: "PyPI",
		Package:   "test-package-2",
	}
	if err := s.SaveAffected(ctx, affected2); err != nil {
		t.Fatalf("SaveAffected(2) error = %v", err)
	}

	entries, err := s.GetVulnerabilitiesForReport(ctx, "")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesForReport() error = %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("GetVulnerabilitiesForReport() returned %d entries, want 2", len(entries))
	}

	npmEntries, err := s.GetVulnerabilitiesForReport(ctx, "npm")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesForReport(npm) error = %v", err)
	}

	if len(npmEntries) != 1 {
		t.Errorf("GetVulnerabilitiesForReport(npm) returned %d entries, want 1", len(npmEntries))
	}

	if npmEntries[0].ID != "GHSA-1234-5678-90ab" {
		t.Errorf("npmEntries[0].ID = %q, want %q", npmEntries[0].ID, "GHSA-1234-5678-90ab")
	}

	if npmEntries[0].SeverityScore == nil {
		t.Fatal("expected SeverityScore to be non-nil")
	}

	if *npmEntries[0].SeverityScore != 9.8 {
		t.Errorf("SeverityScore = %v, want 9.8", *npmEntries[0].SeverityScore)
	}
}

func TestGetVulnerabilitiesForReport_DifferentDates_SortsByPublishedDescending(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	oldestPublished := time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)
	middlePublished := time.Date(2025, 10, 2, 0, 0, 0, 0, time.UTC)
	newestPublished := time.Date(2025, 10, 3, 0, 0, 0, 0, time.UTC)

	vuln1 := store.Vulnerability{ID: "GHSA-oldest", Modified: time.Now(), Published: oldestPublished}
	if err := s.SaveVulnerability(ctx, vuln1); err != nil {
		t.Fatalf("SaveVulnerability(oldest) error = %v", err)
	}
	if err := s.SaveAffected(ctx, store.Affected{VulnID: "GHSA-oldest", Ecosystem: "npm", Package: "pkg1"}); err != nil {
		t.Fatalf("SaveAffected(oldest) error = %v", err)
	}

	vuln2 := store.Vulnerability{ID: "GHSA-newest", Modified: time.Now(), Published: newestPublished}
	if err := s.SaveVulnerability(ctx, vuln2); err != nil {
		t.Fatalf("SaveVulnerability(newest) error = %v", err)
	}
	if err := s.SaveAffected(ctx, store.Affected{VulnID: "GHSA-newest", Ecosystem: "npm", Package: "pkg2"}); err != nil {
		t.Fatalf("SaveAffected(newest) error = %v", err)
	}

	vuln3 := store.Vulnerability{ID: "GHSA-middle", Modified: time.Now(), Published: middlePublished}
	if err := s.SaveVulnerability(ctx, vuln3); err != nil {
		t.Fatalf("SaveVulnerability(middle) error = %v", err)
	}
	if err := s.SaveAffected(ctx, store.Affected{VulnID: "GHSA-middle", Ecosystem: "npm", Package: "pkg3"}); err != nil {
		t.Fatalf("SaveAffected(middle) error = %v", err)
	}

	entries, err := s.GetVulnerabilitiesForReport(ctx, "")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesForReport() error = %v", err)
	}

	if len(entries) != 3 {
		t.Fatalf("GetVulnerabilitiesForReport() returned %d entries, want 3", len(entries))
	}

	if entries[0].ID != "GHSA-newest" {
		t.Errorf("entries[0].ID = %q, want GHSA-newest", entries[0].ID)
	}
	if entries[1].ID != "GHSA-middle" {
		t.Errorf("entries[1].ID = %q, want GHSA-middle", entries[1].ID)
	}
	if entries[2].ID != "GHSA-oldest" {
		t.Errorf("entries[2].ID = %q, want GHSA-oldest", entries[2].ID)
	}
}

func TestSaveReportSnapshot_ReplaceExisting_ContainsOnlyNewEntries(t *testing.T) {
	s, dbPath := newTestStore(t)
	ctx := context.Background()

	entries := []store.ReportRow{
		{
			ID:             "GHSA-test-1",
			Ecosystem:      "npm",
			Package:        "pkg1",
			Published:      "2025-10-01T00:00:00Z",
			Modified:       "2025-10-02T00:00:00Z",
			SeverityScore:  ptrFloat64(9.8),
			SeverityVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		},
		{
			ID:             "GHSA-test-2",
			Ecosystem:      "PyPI",
			Package:        "pkg2",
			Published:      "2025-10-03T00:00:00Z",
			Modified:       "2025-10-03T00:00:00Z",
			SeverityVector: "",
		},
	}

	if err := s.SaveReportSnapshot(ctx, entries); err != nil {
		t.Fatalf("SaveReportSnapshot() error = %v", err)
	}

	db, err := sql.Open(store.DriverName, store.OpenDSN(dbPath))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer db.Close() //nolint:errcheck

	var count int
	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM reported_snapshot").Scan(&count)
	if err != nil {
		t.Fatalf("query count error = %v", err)
	}

	if count != 2 {
		t.Errorf("reported_snapshot count = %d, want 2", count)
	}

	newEntries := []store.ReportRow{
		{
			ID:             "GHSA-test-3",
			Ecosystem:      "Go",
			Package:        "pkg3",
			Published:      "2025-10-04T00:00:00Z",
			Modified:       "2025-10-04T00:00:00Z",
			SeverityVector: "",
		},
	}

	if err := s.SaveReportSnapshot(ctx, newEntries); err != nil {
		t.Fatalf("SaveReportSnapshot(2) error = %v", err)
	}

	err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM reported_snapshot").Scan(&count)
	if err != nil {
		t.Fatalf("query count after replace error = %v", err)
	}

	if count != 1 {
		t.Errorf("reported_snapshot count after replace = %d, want 1", count)
	}
}

func TestGetUnreportedVulnerabilities_MixedState_ReturnsModifiedAndNew(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	vuln1 := store.Vulnerability{
		ID:                "GHSA-unchanged",
		Modified:          time.Now(),
		Published:         time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
		SeverityBaseScore: sql.NullFloat64{Float64: 9.8, Valid: true},
		SeverityVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}
	if err := s.SaveVulnerability(ctx, vuln1); err != nil {
		t.Fatalf("SaveVulnerability(unchanged) error = %v", err)
	}
	if err := s.SaveAffected(ctx, store.Affected{VulnID: "GHSA-unchanged", Ecosystem: "npm", Package: "pkg-unchanged"}); err != nil {
		t.Fatalf("SaveAffected(unchanged) error = %v", err)
	}

	vuln2 := store.Vulnerability{
		ID:                "GHSA-modified",
		Modified:          time.Date(2025, 10, 3, 0, 0, 0, 0, time.UTC),
		Published:         time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
		SeverityBaseScore: sql.NullFloat64{Float64: 6.4, Valid: true},
		SeverityVector:    "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
	}
	if err := s.SaveVulnerability(ctx, vuln2); err != nil {
		t.Fatalf("SaveVulnerability(modified) error = %v", err)
	}
	if err := s.SaveAffected(ctx, store.Affected{VulnID: "GHSA-modified", Ecosystem: "npm", Package: "pkg-modified"}); err != nil {
		t.Fatalf("SaveAffected(modified) error = %v", err)
	}

	vuln3 := store.Vulnerability{
		ID:        "GHSA-new",
		Modified:  time.Now(),
		Published: time.Date(2025, 10, 2, 0, 0, 0, 0, time.UTC),
	}
	if err := s.SaveVulnerability(ctx, vuln3); err != nil {
		t.Fatalf("SaveVulnerability(new) error = %v", err)
	}
	if err := s.SaveAffected(ctx, store.Affected{VulnID: "GHSA-new", Ecosystem: "PyPI", Package: "pkg-new"}); err != nil {
		t.Fatalf("SaveAffected(new) error = %v", err)
	}

	snapshot := []store.ReportRow{
		{
			ID:             "GHSA-unchanged",
			Ecosystem:      "npm",
			Package:        "pkg-unchanged",
			Published:      "2025-10-01T00:00:00Z",
			Modified:       time.Now().Format(time.RFC3339),
			SeverityScore:  ptrFloat64(9.8),
			SeverityVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		},
		{
			ID:             "GHSA-modified",
			Ecosystem:      "npm",
			Package:        "pkg-modified",
			Published:      "2025-10-01T00:00:00Z",
			Modified:       "2025-10-02T00:00:00Z",
			SeverityScore:  ptrFloat64(6.4),
			SeverityVector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
		},
	}
	if err := s.SaveReportSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("SaveReportSnapshot() error = %v", err)
	}

	unreported, err := s.GetUnreportedVulnerabilities(ctx, "")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities() error = %v", err)
	}

	if len(unreported) != 2 {
		t.Fatalf("GetUnreportedVulnerabilities() returned %d entries, want 2", len(unreported))
	}

	unreportedIDs := map[string]bool{unreported[0].ID: true, unreported[1].ID: true}
	if !unreportedIDs["GHSA-modified"] {
		t.Errorf("GetUnreportedVulnerabilities() did not return GHSA-modified, got %v", unreportedIDs)
	}
	if !unreportedIDs["GHSA-new"] {
		t.Errorf("GetUnreportedVulnerabilities() did not return GHSA-new, got %v", unreportedIDs)
	}
	if unreportedIDs["GHSA-unchanged"] {
		t.Errorf("GetUnreportedVulnerabilities() should not return GHSA-unchanged")
	}

	npmUnreported, err := s.GetUnreportedVulnerabilities(ctx, "npm")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities(npm) error = %v", err)
	}

	if len(npmUnreported) != 1 {
		t.Fatalf("GetUnreportedVulnerabilities(npm) returned %d entries, want 1", len(npmUnreported))
	}

	if npmUnreported[0].ID != "GHSA-modified" {
		t.Errorf("GetUnreportedVulnerabilities(npm)[0].ID = %q, want GHSA-modified", npmUnreported[0].ID)
	}
}
