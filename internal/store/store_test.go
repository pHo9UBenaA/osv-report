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

// tickingClock yields a deterministic time sequence: each call to Now()
// returns the next tick. Used to make fetched_at predictable in tests.
type tickingClock struct {
	next time.Time
	step time.Duration
}

func newTickingClock(start time.Time, step time.Duration) *tickingClock {
	return &tickingClock{next: start, step: step}
}

func (c *tickingClock) Now() time.Time {
	t := c.next
	c.next = c.next.Add(c.step)
	return t
}

// seedLegacyDatabase materializes a SQLite file at the v3 schema (post-
// affected-CASCADE, post-published-NULL, but pre-fetched_at and pre-
// watermark) with one vulnerability + one affected + a matching snapshot
// row, then closes the connection. Calling NewStore against the resulting
// path triggers migrations v4 and v5 against real legacy data.
func seedLegacyDatabase(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open(store.DriverName, store.OpenDSN(dbPath))
	if err != nil {
		t.Fatalf("open legacy db: %v", err)
	}
	defer db.Close() //nolint:errcheck

	stmts := []string{
		`CREATE TABLE source_cursor (source TEXT PRIMARY KEY, cursor TEXT NOT NULL)`,
		`CREATE TABLE vulnerability (
			id TEXT PRIMARY KEY,
			modified TEXT NOT NULL,
			published TEXT,
			summary TEXT,
			details TEXT,
			severity_base_score REAL,
			severity_vector TEXT
		)`,
		`CREATE TABLE tombstone (
			id TEXT PRIMARY KEY,
			deleted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE affected (
			vuln_id TEXT NOT NULL,
			ecosystem TEXT NOT NULL,
			package TEXT NOT NULL,
			PRIMARY KEY (vuln_id, ecosystem, package),
			FOREIGN KEY (vuln_id) REFERENCES vulnerability(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE reported_snapshot (
			id TEXT NOT NULL,
			ecosystem TEXT NOT NULL,
			package TEXT NOT NULL,
			published TEXT,
			modified TEXT,
			severity_base_score REAL,
			severity_vector TEXT,
			PRIMARY KEY (id, ecosystem, package)
		)`,
		`CREATE INDEX idx_affected_ecosystem ON affected(ecosystem)`,
		`CREATE INDEX idx_vulnerability_modified ON vulnerability(modified)`,
		`CREATE TABLE schema_version (version INTEGER NOT NULL)`,
		`INSERT INTO schema_version (version) VALUES (1), (2), (3)`,
		`INSERT INTO vulnerability (id, modified) VALUES ('GHSA-legacy', '2025-10-01T00:00:00Z')`,
		`INSERT INTO affected (vuln_id, ecosystem, package) VALUES ('GHSA-legacy', 'npm', 'legacy-pkg')`,
		`INSERT INTO reported_snapshot (id, ecosystem, package, published, modified) VALUES ('GHSA-legacy', 'npm', 'legacy-pkg', NULL, '2025-10-01T00:00:00Z')`,
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("seed legacy db exec %q: %v", q, err)
		}
	}
}

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

// TestSourceState_RoundTrip pins that Save then Get returns the same
// state, including the zero-value case. time.Time{} serialises to
// "0001-01-01T00:00:00Z" which round-trips through strict RFC3339
// parsing and reports IsZero() = true; that's the structural reason
// the rev4 cursor='' poison row cannot recur under the new API.
func TestSourceState_RoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	t.Run("PopulatedState", func(t *testing.T) {
		want := store.SourceState{
			Cursor:     time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC),
			ETag:       `"v1-etag"`,
			Ecosystems: "npm\nPyPI",
		}
		if err := s.SaveSourceState(ctx, "populated", want); err != nil {
			t.Fatalf("SaveSourceState: %v", err)
		}
		got, err := s.GetSourceState(ctx, "populated")
		if err != nil {
			t.Fatalf("GetSourceState: %v", err)
		}
		if !got.Cursor.Equal(want.Cursor) || got.ETag != want.ETag || got.Ecosystems != want.Ecosystems {
			t.Fatalf("round-trip mismatch: got %+v, want %+v", got, want)
		}
	})

	t.Run("ZeroValue", func(t *testing.T) {
		if err := s.SaveSourceState(ctx, "zero", store.SourceState{}); err != nil {
			t.Fatalf("SaveSourceState zero: %v", err)
		}
		got, err := s.GetSourceState(ctx, "zero")
		if err != nil {
			t.Fatalf("GetSourceState zero: %v", err)
		}
		if !got.Cursor.IsZero() {
			t.Errorf("zero cursor round trip failed: got %v", got.Cursor)
		}
		if got.ETag != "" || got.Ecosystems != "" {
			t.Errorf("non-empty fields on zero round trip: %+v", got)
		}
	})
}

// TestSourceState_AbsentRow_ReturnsZeroValue pins that the store does
// not leak sql.ErrNoRows; callers treat zero-value as "no state yet".
func TestSourceState_AbsentRow_ReturnsZeroValue(t *testing.T) {
	s, _ := newTestStore(t)
	got, err := s.GetSourceState(context.Background(), "never-saved")
	if err != nil {
		t.Fatalf("GetSourceState: %v", err)
	}
	if got != (store.SourceState{}) {
		t.Errorf("absent row should return zero value, got %+v", got)
	}
}

// TestSourceState_OverwritesBothFieldsAtomically pins that the second
// Save replaces every column. If the API ever drifts back to a partial
// update (the rev4 SaveETag pattern), this fails because the original
// fields linger.
func TestSourceState_OverwritesBothFieldsAtomically(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	first := store.SourceState{
		Cursor:     time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC),
		ETag:       `"first"`,
		Ecosystems: "npm",
	}
	if err := s.SaveSourceState(ctx, "k", first); err != nil {
		t.Fatalf("first save: %v", err)
	}

	second := store.SourceState{
		Cursor:     time.Date(2025, 10, 5, 0, 0, 0, 0, time.UTC),
		ETag:       `"second"`,
		Ecosystems: "PyPI",
	}
	if err := s.SaveSourceState(ctx, "k", second); err != nil {
		t.Fatalf("second save: %v", err)
	}

	got, err := s.GetSourceState(ctx, "k")
	if err != nil {
		t.Fatalf("GetSourceState: %v", err)
	}
	if !got.Cursor.Equal(second.Cursor) || got.ETag != second.ETag || got.Ecosystems != second.Ecosystems {
		t.Fatalf("partial overwrite: got %+v, want %+v", got, second)
	}
}

// TestSourceState_StrictParse_RejectsCorruptCursor pins that
// GetSourceState surfaces unparseable cursors as errors rather than
// silently treating them as zero. External tampering is the only way
// to produce such a row under the new API, and the runbook tells the
// operator to DELETE it.
func TestSourceState_StrictParse_RejectsCorruptCursor(t *testing.T) {
	_, dbPath := newTestStore(t)
	ctx := context.Background()

	db, err := sql.Open(store.DriverName, store.OpenDSN(dbPath))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close() //nolint:errcheck
	if _, err := db.ExecContext(ctx, "INSERT INTO source_cursor (source, cursor) VALUES (?, ?)", "tampered", "garbage"); err != nil {
		t.Fatalf("inject row: %v", err)
	}

	s2, err := store.NewStore(ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	if _, err := s2.GetSourceState(ctx, "tampered"); err == nil {
		t.Fatal("GetSourceState should reject corrupt cursor, got nil error")
	}
}

// TestSaveVulnerabilityWithAffected_FetchedAtNotRestampedOnSameModified
// pins the D4 fetched_at semantics: an unchanged record on re-ingest
// keeps its original fetched_at, so a retry after a partial-failure run
// does not flood the diff report. A subsequent save with a new modified
// stamps a fresh fetched_at.
func TestSaveVulnerabilityWithAffected_FetchedAtNotRestampedOnSameModified(t *testing.T) {
	s, dbPath := newTestStore(t)
	ctx := context.Background()

	clock := newTickingClock(time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC), time.Hour)
	store.SetStoreClockForTesting(s, clock.Now)

	v := store.Vulnerability{ID: "V-stable", Modified: time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC)}
	if err := s.SaveVulnerabilityWithAffected(ctx, v, nil); err != nil {
		t.Fatalf("first save: %v", err)
	}

	db, err := sql.Open(store.DriverName, store.OpenDSN(dbPath))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close() //nolint:errcheck

	var firstFetched int64
	if err := db.QueryRowContext(ctx, "SELECT fetched_at FROM vulnerability WHERE id = ?", v.ID).Scan(&firstFetched); err != nil {
		t.Fatalf("read first fetched_at: %v", err)
	}

	// Same modified, the clock has already ticked: fetched_at must stay put.
	if err := s.SaveVulnerabilityWithAffected(ctx, v, nil); err != nil {
		t.Fatalf("second save: %v", err)
	}
	var secondFetched int64
	if err := db.QueryRowContext(ctx, "SELECT fetched_at FROM vulnerability WHERE id = ?", v.ID).Scan(&secondFetched); err != nil {
		t.Fatalf("read second fetched_at: %v", err)
	}
	if secondFetched != firstFetched {
		t.Errorf("fetched_at restamped on unchanged modified: first=%d, second=%d", firstFetched, secondFetched)
	}

	// Bump modified: fetched_at must advance.
	v.Modified = v.Modified.Add(24 * time.Hour)
	if err := s.SaveVulnerabilityWithAffected(ctx, v, nil); err != nil {
		t.Fatalf("third save: %v", err)
	}
	var thirdFetched int64
	if err := db.QueryRowContext(ctx, "SELECT fetched_at FROM vulnerability WHERE id = ?", v.ID).Scan(&thirdFetched); err != nil {
		t.Fatalf("read third fetched_at: %v", err)
	}
	if thirdFetched == firstFetched {
		t.Errorf("fetched_at did not advance after modified change: %d", thirdFetched)
	}
}

// seedV8Database materialises a v8-shape SQLite file (last migration
// before this rev's v9) and pre-populates source_cursor with three
// rows representing each pre-rev5 state we want v9 to delete or keep.
// The schema_version table is filled up to 8 so NewStore only re-runs
// v9 and v10.
func seedV8Database(t *testing.T, dbPath string) {
	t.Helper()
	db, err := sql.Open(store.DriverName, store.OpenDSN(dbPath))
	if err != nil {
		t.Fatalf("open v8 db: %v", err)
	}
	defer db.Close() //nolint:errcheck

	stmts := []string{
		// v8 source_cursor shape: cursor TEXT NOT NULL + etag TEXT.
		`CREATE TABLE source_cursor (source TEXT PRIMARY KEY, cursor TEXT NOT NULL, etag TEXT)`,
		`CREATE TABLE vulnerability (
			id TEXT PRIMARY KEY,
			modified TEXT NOT NULL,
			published TEXT,
			summary TEXT,
			details TEXT,
			severity_base_score REAL,
			severity_vector TEXT,
			severity_type TEXT,
			fetched_at INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE affected (
			vuln_id TEXT NOT NULL,
			ecosystem TEXT NOT NULL,
			package TEXT NOT NULL,
			PRIMARY KEY (vuln_id, ecosystem, package),
			FOREIGN KEY (vuln_id) REFERENCES vulnerability(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE report_watermark (
			ecosystem TEXT PRIMARY KEY,
			reported_until INTEGER NOT NULL
		)`,
		`CREATE INDEX idx_affected_ecosystem ON affected(ecosystem)`,
		`CREATE INDEX idx_vulnerability_modified ON vulnerability(modified)`,
		`CREATE TABLE schema_version (version INTEGER NOT NULL)`,
		`INSERT INTO schema_version (version) VALUES (1), (2), (3), (4), (5), (6), (7), (8)`,
		// Healthy-looking unified row.
		`INSERT INTO source_cursor (source, cursor, etag) VALUES ('__unified__', '2025-10-01T00:00:00Z', '"healthy"')`,
		// rev4 cursor='' poison row.
		`INSERT INTO source_cursor (source, cursor, etag) VALUES ('__unified__-poison', '', '"orphan-etag"')`,
		// pre-F per-ecosystem row.
		`INSERT INTO source_cursor (source, cursor, etag) VALUES ('npm', '2025-09-01T00:00:00Z', NULL)`,
	}
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("seed v8 exec %q: %v", q, err)
		}
	}
}

// TestMigrationV9_TruncatesSourceCursor pins that opening a v8-shape
// database under the new code deletes every source_cursor row — even
// rows that look healthy — and leaves the ecosystems column ready for
// SaveSourceState.
func TestMigrationV9_TruncatesSourceCursor(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "v8.db")
	seedV8Database(t, dbPath)

	s, err := store.NewStore(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("NewStore on v8 DB: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	db, err := sql.Open(store.DriverName, store.OpenDSN(dbPath))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close() //nolint:errcheck

	var count int
	if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM source_cursor").Scan(&count); err != nil {
		t.Fatalf("count source_cursor: %v", err)
	}
	if count != 0 {
		t.Errorf("v9 should have truncated source_cursor, got %d rows", count)
	}

	got, err := s.GetSourceState(context.Background(), "__unified__")
	if err != nil {
		t.Fatalf("GetSourceState after v9: %v", err)
	}
	if got != (store.SourceState{}) {
		t.Errorf("post-v9 state should be zero, got %+v", got)
	}

	// v10 must have added the ecosystems column so SaveSourceState works.
	if err := s.SaveSourceState(context.Background(), "__unified__", store.SourceState{
		Cursor:     time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC),
		ETag:       `"new"`,
		Ecosystems: "npm",
	}); err != nil {
		t.Fatalf("SaveSourceState after v9/v10: %v", err)
	}
}

func TestSaveVulnerabilityWithAffected_NewEntry_PersistsIdempotently(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	vuln := store.Vulnerability{
		ID:       "GHSA-xxxx-yyyy-zzzz",
		Modified: time.Date(2025, 10, 4, 12, 34, 56, 0, time.UTC),
	}

	if err := s.SaveVulnerabilityWithAffected(ctx, vuln, nil); err != nil {
		t.Fatalf("first SaveVulnerabilityWithAffected: %v", err)
	}

	if err := s.SaveVulnerabilityWithAffected(ctx, vuln, nil); err != nil {
		t.Fatalf("second SaveVulnerabilityWithAffected: %v", err)
	}
}

func TestSaveVulnerabilityWithAffected_NullThenUpdate_SeverityFieldsPersist(t *testing.T) {
	s, dbPath := newTestStore(t)
	ctx := context.Background()

	vulnID := "GHSA-severity-check"
	modified := time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC)

	if err := s.SaveVulnerabilityWithAffected(ctx, store.Vulnerability{ID: vulnID, Modified: modified}, nil); err != nil {
		t.Fatalf("SaveVulnerabilityWithAffected: %v", err)
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
		SeverityBaseScore: ptrFloat64(7.5),
		SeverityVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L",
	}

	if err := s.SaveVulnerabilityWithAffected(ctx, update, nil); err != nil {
		t.Fatalf("SaveVulnerabilityWithAffected(update): %v", err)
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

func TestSaveVulnerabilityWithAffected_WithSummaryAndDetails_PersistsAllFields(t *testing.T) {
	s, dbPath := newTestStore(t)
	ctx := context.Background()

	vuln := store.Vulnerability{
		ID:       "GHSA-detail-test",
		Modified: time.Date(2025, 10, 4, 12, 34, 56, 0, time.UTC),
		Summary:  "Test vulnerability summary",
		Details:  "Detailed description of the vulnerability",
	}

	if err := s.SaveVulnerabilityWithAffected(ctx, vuln, nil); err != nil {
		t.Fatalf("SaveVulnerabilityWithAffected: %v", err)
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

func TestSaveVulnerabilityWithAffected_SingleAffected_Persists(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	vulnID := "GHSA-test-affected"
	v := store.Vulnerability{
		ID:       vulnID,
		Modified: time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC),
	}
	affected := []store.Affected{
		{VulnID: vulnID, Ecosystem: "Go", Package: "github.com/test/pkg"},
	}

	if err := s.SaveVulnerabilityWithAffected(ctx, v, affected); err != nil {
		t.Fatalf("SaveVulnerabilityWithAffected: %v", err)
	}
}

func TestDeleteVulnerability_PresentAndAbsent_BothSucceed(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	v := store.Vulnerability{ID: "GHSA-deleted-vuln", Modified: time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)}
	if err := s.SaveVulnerabilityWithAffected(ctx, v, []store.Affected{{VulnID: v.ID, Ecosystem: "npm", Package: "p"}}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := s.DeleteVulnerability(ctx, v.ID); err != nil {
		t.Fatalf("delete present: %v", err)
	}

	// CASCADE should have removed the affected row too.
	rows, err := s.GetVulnerabilitiesForReport(ctx, "")
	if err != nil {
		t.Fatalf("query after delete: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 rows after delete + CASCADE, got %d", len(rows))
	}

	// Deleting an absent id is a no-op, not an error.
	if err := s.DeleteVulnerability(ctx, "GHSA-never-existed"); err != nil {
		t.Errorf("delete absent should not error, got %v", err)
	}
}

func TestDeleteVulnerabilitiesOlderThan_MixedAges_RemovesOnlyOld(t *testing.T) {
	s, dbPath := newTestStore(t)
	ctx := context.Background()

	oldTime := time.Now().AddDate(0, 0, -14)
	if err := s.SaveVulnerabilityWithAffected(ctx,
		store.Vulnerability{ID: "GHSA-old-vuln", Modified: oldTime},
		[]store.Affected{{VulnID: "GHSA-old-vuln", Ecosystem: "npm", Package: "old-package"}},
	); err != nil {
		t.Fatalf("save old: %v", err)
	}

	newTime := time.Now().AddDate(0, 0, -3)
	if err := s.SaveVulnerabilityWithAffected(ctx,
		store.Vulnerability{ID: "GHSA-new-vuln", Modified: newTime},
		[]store.Affected{{VulnID: "GHSA-new-vuln", Ecosystem: "npm", Package: "new-package"}},
	); err != nil {
		t.Fatalf("save new: %v", err)
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
		SeverityBaseScore: ptrFloat64(9.8),
		SeverityVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		SeverityType:      "CVSS_V3.1",
	}
	if err := s.SaveVulnerabilityWithAffected(ctx, vuln1,
		[]store.Affected{{VulnID: vuln1.ID, Ecosystem: "npm", Package: "test-package-1"}},
	); err != nil {
		t.Fatalf("save vuln1: %v", err)
	}

	vuln2 := store.Vulnerability{
		ID:             "GHSA-abcd-efgh-ijkl",
		Modified:       time.Now(),
		Summary:        "Test vulnerability 2",
		Details:        "Details for test vulnerability 2",
		SeverityVector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
	}
	if err := s.SaveVulnerabilityWithAffected(ctx, vuln2,
		[]store.Affected{{VulnID: vuln2.ID, Ecosystem: "PyPI", Package: "test-package-2"}},
	); err != nil {
		t.Fatalf("save vuln2: %v", err)
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

	if npmEntries[0].SeverityType != "CVSS_V3.1" {
		t.Errorf("SeverityType = %q, want CVSS_V3.1", npmEntries[0].SeverityType)
	}
}

func TestGetVulnerabilitiesForReport_DifferentDates_SortsByPublishedDescending(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	oldestPublished := time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)
	middlePublished := time.Date(2025, 10, 2, 0, 0, 0, 0, time.UTC)
	newestPublished := time.Date(2025, 10, 3, 0, 0, 0, 0, time.UTC)

	if err := s.SaveVulnerabilityWithAffected(ctx,
		store.Vulnerability{ID: "GHSA-oldest", Modified: time.Now(), Published: oldestPublished},
		[]store.Affected{{VulnID: "GHSA-oldest", Ecosystem: "npm", Package: "pkg1"}},
	); err != nil {
		t.Fatalf("save oldest: %v", err)
	}
	if err := s.SaveVulnerabilityWithAffected(ctx,
		store.Vulnerability{ID: "GHSA-newest", Modified: time.Now(), Published: newestPublished},
		[]store.Affected{{VulnID: "GHSA-newest", Ecosystem: "npm", Package: "pkg2"}},
	); err != nil {
		t.Fatalf("save newest: %v", err)
	}
	if err := s.SaveVulnerabilityWithAffected(ctx,
		store.Vulnerability{ID: "GHSA-middle", Modified: time.Now(), Published: middlePublished},
		[]store.Affected{{VulnID: "GHSA-middle", Ecosystem: "npm", Package: "pkg3"}},
	); err != nil {
		t.Fatalf("save middle: %v", err)
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

func TestAdvanceWatermarks_MonotonicGuard(t *testing.T) {
	s, dbPath := newTestStore(t)
	ctx := context.Background()

	// Two rows for npm with fetched_at 100 and 200; running AdvanceWatermarks
	// in both orders must leave the watermark at 200 (the higher value).
	rowsLow := []store.ReportRow{{ID: "A", Ecosystem: "npm", Package: "p", FetchedAt: 100}}
	rowsHigh := []store.ReportRow{{ID: "B", Ecosystem: "npm", Package: "p", FetchedAt: 200}}

	if err := s.AdvanceWatermarks(ctx, rowsHigh); err != nil {
		t.Fatalf("advance high: %v", err)
	}
	if err := s.AdvanceWatermarks(ctx, rowsLow); err != nil {
		t.Fatalf("advance low: %v", err)
	}

	db, err := sql.Open(store.DriverName, store.OpenDSN(dbPath))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close() //nolint:errcheck

	var got int64
	if err := db.QueryRowContext(ctx, "SELECT reported_until FROM report_watermark WHERE ecosystem = ?", "npm").Scan(&got); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if got != 200 {
		t.Errorf("monotonic guard regressed: watermark = %d, want 200", got)
	}
}

func TestSaveVulnerabilityWithAffected_ShrinksAffectedRows(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	vulnID := "GHSA-shrink-test"
	modified := time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC)
	v := store.Vulnerability{ID: vulnID, Modified: modified}

	first := []store.Affected{
		{VulnID: vulnID, Ecosystem: "npm", Package: "a"},
		{VulnID: vulnID, Ecosystem: "npm", Package: "b"},
	}
	if err := s.SaveVulnerabilityWithAffected(ctx, v, first); err != nil {
		t.Fatalf("first SaveVulnerabilityWithAffected: %v", err)
	}

	second := []store.Affected{
		{VulnID: vulnID, Ecosystem: "npm", Package: "a"},
	}
	if err := s.SaveVulnerabilityWithAffected(ctx, v, second); err != nil {
		t.Fatalf("second SaveVulnerabilityWithAffected: %v", err)
	}

	rows, err := s.GetVulnerabilitiesForReport(ctx, "npm")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesForReport: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("after shrinking affected: got %d rows, want 1 (b should be gone)", len(rows))
	}
	if rows[0].Package != "a" {
		t.Errorf("surviving row Package = %q, want %q", rows[0].Package, "a")
	}
}

func TestSaveVulnerabilityWithAffected_PublishedNullSortsBeforeOnlyModified(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Vulnerability A: published unset (zero time), modified at time T2.
	// Vulnerability B: published at T1 (earlier than T2), modified at T1.
	// Expected order (DESC by COALESCE(published, modified)): A first (T2), then B (T1).
	// If A's missing published was stored as empty string, A would sort last under
	// SQLite's text comparison instead of falling back to modified.
	t1 := time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2025, 10, 5, 0, 0, 0, 0, time.UTC)

	a := store.Vulnerability{ID: "GHSA-a", Modified: t2}
	if err := s.SaveVulnerabilityWithAffected(ctx, a, []store.Affected{{VulnID: "GHSA-a", Ecosystem: "npm", Package: "pkg-a"}}); err != nil {
		t.Fatalf("save A: %v", err)
	}

	b := store.Vulnerability{ID: "GHSA-b", Modified: t1, Published: t1}
	if err := s.SaveVulnerabilityWithAffected(ctx, b, []store.Affected{{VulnID: "GHSA-b", Ecosystem: "npm", Package: "pkg-b"}}); err != nil {
		t.Fatalf("save B: %v", err)
	}

	rows, err := s.GetVulnerabilitiesForReport(ctx, "npm")
	if err != nil {
		t.Fatalf("GetVulnerabilitiesForReport: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].ID != "GHSA-a" {
		t.Errorf("expected GHSA-a (modified T2) to sort first, got order: %s, %s", rows[0].ID, rows[1].ID)
	}
}

func TestDiff_EcosystemFilter_DoesNotResetOtherEcosystem(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	clock := newTickingClock(time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC), time.Second)
	store.SetStoreClockForTesting(s, clock.Now)

	saveOne := func(id, eco string) {
		v := store.Vulnerability{ID: id, Modified: clock.Now()}
		if err := s.SaveVulnerabilityWithAffected(ctx, v, []store.Affected{{VulnID: id, Ecosystem: eco, Package: id + "-pkg"}}); err != nil {
			t.Fatalf("save %s/%s: %v", id, eco, err)
		}
	}
	saveOne("V-npm", "npm")
	saveOne("V-pypi", "PyPI")

	npmRows, err := s.GetUnreportedVulnerabilities(ctx, "npm")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities(npm): %v", err)
	}
	if err := s.AdvanceWatermarks(ctx, npmRows); err != nil {
		t.Fatalf("AdvanceWatermarks(npm): %v", err)
	}

	pypiRows, err := s.GetUnreportedVulnerabilities(ctx, "PyPI")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities(PyPI): %v", err)
	}
	if len(pypiRows) != 1 {
		t.Fatalf("PyPI watermark wiped by npm diff: got %d unreported, want 1", len(pypiRows))
	}
}

func TestDiff_NoChange_EmitsZero(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	clock := newTickingClock(time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC), time.Second)
	store.SetStoreClockForTesting(s, clock.Now)

	v := store.Vulnerability{ID: "V-1", Modified: clock.Now()}
	if err := s.SaveVulnerabilityWithAffected(ctx, v, []store.Affected{{VulnID: "V-1", Ecosystem: "npm", Package: "p1"}}); err != nil {
		t.Fatalf("save: %v", err)
	}

	first, err := s.GetUnreportedVulnerabilities(ctx, "npm")
	if err != nil {
		t.Fatalf("first GetUnreported: %v", err)
	}
	if err := s.AdvanceWatermarks(ctx, first); err != nil {
		t.Fatalf("AdvanceWatermarks: %v", err)
	}

	second, err := s.GetUnreportedVulnerabilities(ctx, "npm")
	if err != nil {
		t.Fatalf("second GetUnreported: %v", err)
	}
	if len(second) != 0 {
		t.Errorf("second diff returned %d rows, want 0", len(second))
	}
}

// TestWatermark_UnchangedRecordStaysQuietOnReingest pins the D4
// fetched_at-CASE semantics at the diff layer: re-ingesting the same
// record on retry does not resurface it. fetched_at is the "new content
// arrived" axis, not "we touched the row" — see the D4 acceptance note
// in the rev5 plan for the full causal analysis.
func TestWatermark_UnchangedRecordStaysQuietOnReingest(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	t0 := time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)
	clock := newTickingClock(t0, time.Hour)
	store.SetStoreClockForTesting(s, clock.Now)

	v := store.Vulnerability{ID: "V-stable", Modified: time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC)}
	if err := s.SaveVulnerabilityWithAffected(ctx, v, []store.Affected{{VulnID: "V-stable", Ecosystem: "npm", Package: "p"}}); err != nil {
		t.Fatalf("first save: %v", err)
	}
	first, err := s.GetUnreportedVulnerabilities(ctx, "npm")
	if err != nil || len(first) != 1 {
		t.Fatalf("first diff: rows=%d err=%v", len(first), err)
	}
	if err := s.AdvanceWatermarks(ctx, first); err != nil {
		t.Fatalf("advance: %v", err)
	}

	// Same modified, clock has ticked: D4's CASE keeps fetched_at fixed.
	if err := s.SaveVulnerabilityWithAffected(ctx, v, []store.Affected{{VulnID: "V-stable", Ecosystem: "npm", Package: "p"}}); err != nil {
		t.Fatalf("second save: %v", err)
	}
	second, err := s.GetUnreportedVulnerabilities(ctx, "npm")
	if err != nil {
		t.Fatalf("second diff err: %v", err)
	}
	if len(second) != 0 {
		t.Errorf("unchanged record resurfaced in diff: got %d rows, want 0", len(second))
	}
}

// TestWatermark_DelayedInitialIngestSurfaces pins that a record whose
// FIRST ingest happens after another record has already advanced the
// watermark still surfaces in the diff. INSERT stamps fetched_at = now
// unconditionally (the CASE only fires on UPDATE), so the
// "initial-delay" guarantee still holds even though re-ingest is now
// quiet.
func TestWatermark_DelayedInitialIngestSurfaces(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	t0 := time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC)
	clock := newTickingClock(t0, time.Hour)
	store.SetStoreClockForTesting(s, clock.Now)

	// First record advances the watermark at fetched_at=t0.
	early := store.Vulnerability{ID: "V-first", Modified: time.Date(2025, 9, 15, 0, 0, 0, 0, time.UTC)}
	if err := s.SaveVulnerabilityWithAffected(ctx, early, []store.Affected{{VulnID: "V-first", Ecosystem: "npm", Package: "p"}}); err != nil {
		t.Fatalf("save early: %v", err)
	}
	rows, err := s.GetUnreportedVulnerabilities(ctx, "npm")
	if err != nil {
		t.Fatalf("first diff: %v", err)
	}
	if err := s.AdvanceWatermarks(ctx, rows); err != nil {
		t.Fatalf("advance: %v", err)
	}

	// Second record has an OLDER modified but arrives now (fetched_at>watermark).
	// It is the first ingest of this ID so the INSERT path runs and stamps
	// fetched_at unconditionally — the diff must surface it.
	late := store.Vulnerability{ID: "V-late", Modified: time.Date(2025, 8, 1, 0, 0, 0, 0, time.UTC)}
	if err := s.SaveVulnerabilityWithAffected(ctx, late, []store.Affected{{VulnID: "V-late", Ecosystem: "npm", Package: "q"}}); err != nil {
		t.Fatalf("save late: %v", err)
	}
	second, err := s.GetUnreportedVulnerabilities(ctx, "npm")
	if err != nil {
		t.Fatalf("second diff: %v", err)
	}
	if len(second) != 1 || second[0].ID != "V-late" {
		t.Errorf("delayed initial ingest did not surface: got %+v, want only V-late", second)
	}
}

func TestWatermarkMigration_DerivesFromExistingSnapshot(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// Pre-seed a database in the v2-shape (no fetched_at, with reported_snapshot)
	// to simulate an upgrade. After migration the watermark must be populated
	// from the snapshot so the first post-migration diff doesn't re-report
	// everything.
	seedLegacyDatabase(t, dbPath)

	s, err := store.NewStore(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("NewStore on legacy DB: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	rows, err := s.GetUnreportedVulnerabilities(context.Background(), "npm")
	if err != nil {
		t.Fatalf("GetUnreportedVulnerabilities: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("first diff on migrated DB returned %d rows, expected 0 (watermark should be derived)", len(rows))
	}
}

func TestGetUnreportedVulnerabilities_AfterAdvance_OnlyNewSurfaces(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	clock := newTickingClock(time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC), time.Second)
	store.SetStoreClockForTesting(s, clock.Now)

	// Save two rows under different ecosystems.
	v1 := store.Vulnerability{ID: "V-a", Modified: time.Date(2025, 10, 2, 0, 0, 0, 0, time.UTC)}
	v2 := store.Vulnerability{ID: "V-b", Modified: time.Date(2025, 10, 3, 0, 0, 0, 0, time.UTC)}
	if err := s.SaveVulnerabilityWithAffected(ctx, v1, []store.Affected{{VulnID: v1.ID, Ecosystem: "npm", Package: "pkg-a"}}); err != nil {
		t.Fatalf("save v1: %v", err)
	}
	if err := s.SaveVulnerabilityWithAffected(ctx, v2, []store.Affected{{VulnID: v2.ID, Ecosystem: "PyPI", Package: "pkg-b"}}); err != nil {
		t.Fatalf("save v2: %v", err)
	}

	// First diff covers both, then advance.
	all, err := s.GetUnreportedVulnerabilities(ctx, "")
	if err != nil {
		t.Fatalf("first diff: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("first diff returned %d, want 2", len(all))
	}
	if err := s.AdvanceWatermarks(ctx, all); err != nil {
		t.Fatalf("advance: %v", err)
	}

	// A third row arrives; only it should surface in the next diff.
	v3 := store.Vulnerability{ID: "V-c", Modified: time.Date(2025, 10, 4, 0, 0, 0, 0, time.UTC)}
	if err := s.SaveVulnerabilityWithAffected(ctx, v3, []store.Affected{{VulnID: v3.ID, Ecosystem: "npm", Package: "pkg-c"}}); err != nil {
		t.Fatalf("save v3: %v", err)
	}

	second, err := s.GetUnreportedVulnerabilities(ctx, "")
	if err != nil {
		t.Fatalf("second diff: %v", err)
	}
	if len(second) != 1 || second[0].ID != "V-c" {
		t.Errorf("second diff = %+v, want only V-c", second)
	}
}
