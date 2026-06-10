package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DriverName is the database/sql driver name registered by the SQLite driver
// used by this package. Exported so tests can open the database with the same
// driver as production code.
const DriverName = "sqlite"

// OpenDSN returns the DSN that NewStore uses, including per-connection PRAGMA
// configuration that applies to every connection in the pool. Exported so
// tests can replicate production connection behavior when opening the
// database directly.
//
// PRAGMA foreign_keys and busy_timeout are per-connection in SQLite. Setting
// them via DSN guarantees every pooled connection has them on, which is the
// only safe way given database/sql may transparently open new connections.
// journal_mode=WAL is file-persistent so the DSN entry is for first-time
// database creation only.
func OpenDSN(dbPath string) string {
	return fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", dbPath)
}

const timeFormat = time.RFC3339

// Vulnerability represents a vulnerability record in the database.
type Vulnerability struct {
	ID                string
	Modified          time.Time
	Published         time.Time
	Summary           string
	Details           string
	SeverityBaseScore *float64
	SeverityVector    string
	SeverityType      string
}

// Affected represents an affected package in the database.
type Affected struct {
	VulnID    string
	Ecosystem string
	Package   string
}

// ReportRow represents a vulnerability with metadata for reporting.
// Uses *float64 instead of sql.NullFloat64 to keep DB details internal.
//
// FetchedAt is the ingest timestamp in Unix nanoseconds (the column type
// SQLite sees is INTEGER). The watermark machinery operates on this value;
// using int64 instead of a formatted string keeps comparison numeric and
// avoids the trailing-zero footgun in time.RFC3339Nano.
type ReportRow struct {
	ID             string
	Ecosystem      string
	Package        string
	Published      string
	Modified       string
	FetchedAt      int64
	SeverityScore  *float64
	SeverityVector string
	SeverityType   string
}

// Store manages database operations for the OSV scraper.
type Store struct {
	db    *sql.DB
	clock func() time.Time
}

func toNullableFloat(value *float64) any {
	if value == nil {
		return nil
	}
	return *value
}

func toNullString(value string) any {
	if value != "" {
		return value
	}
	return nil
}

// withTx runs fn inside a single database transaction. The transaction is
// committed if fn returns nil and rolled back otherwise. Wrapping each
// schema migration this way makes the "execute migration + record version"
// pair atomic, so a crash between the two cannot leave a half-applied
// migration that would re-run destructively on next startup.
func withTx(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// NewStore creates a new store instance and initializes the database.
func NewStore(ctx context.Context, dbPath string) (*Store, error) {
	db, err := sql.Open(DriverName, OpenDSN(dbPath))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Configure connection pool for concurrent access
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.PingContext(ctx); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("ping database: %w", err)
	}

	s := &Store{db: db, clock: time.Now}

	if err := s.initSchema(ctx); err != nil {
		db.Close() //nolint:errcheck
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return s, nil
}

func (s *Store) initSchema(ctx context.Context) error {
	// PRAGMA configuration is applied via the DSN (see OpenDSN) so it takes
	// effect on every pooled connection, not just the one that runs
	// initSchema. Per-connection Exec is unreliable because database/sql can
	// open additional connections at any time.

	// Create schema
	schema := `
		CREATE TABLE IF NOT EXISTS source_cursor (
			source TEXT PRIMARY KEY,
			cursor TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS vulnerability (
			id TEXT PRIMARY KEY,
			modified TEXT NOT NULL,
			published TEXT,
			summary TEXT,
			details TEXT,
			severity_base_score REAL,
			severity_vector TEXT
		);

		CREATE TABLE IF NOT EXISTS affected (
			vuln_id TEXT NOT NULL,
			ecosystem TEXT NOT NULL,
			package TEXT NOT NULL,
			FOREIGN KEY (vuln_id) REFERENCES vulnerability(id),
			PRIMARY KEY (vuln_id, ecosystem, package)
		);

		CREATE TABLE IF NOT EXISTS reported_snapshot (
			id TEXT NOT NULL,
			ecosystem TEXT NOT NULL,
			package TEXT NOT NULL,
			published TEXT,
			modified TEXT,
			severity_base_score REAL,
			severity_vector TEXT,
			PRIMARY KEY (id, ecosystem, package)
		);

		CREATE INDEX IF NOT EXISTS idx_affected_ecosystem ON affected(ecosystem);
		CREATE INDEX IF NOT EXISTS idx_vulnerability_modified ON vulnerability(modified);
	`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}

	// Version-based migrations
	if err := s.runMigrations(ctx); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	return nil
}

func (s *Store) runMigrations(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("create schema_version table: %w", err)
	}

	var version int
	if err := s.db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&version); err != nil {
		return fmt.Errorf("get schema version: %w", err)
	}

	// All migrations in order. Each migration runs exactly once.
	//
	// disablesFKDuringRebuild applies to migrations that recreate a table with
	// foreign keys (the SQLite documented "12-step ALTER" workaround). The
	// rebuild must run with foreign_keys=OFF so the intermediate state with
	// duplicated rows doesn't trigger constraint failures. PRAGMA foreign_keys
	// is a no-op inside a transaction, so the toggle has to wrap the tx.
	type migration struct {
		version                 int
		sql                     string
		disablesFKDuringRebuild bool
	}
	migrations := []migration{
		{version: 1, sql: "DROP TABLE IF EXISTS package_metrics"},
		{
			version: 2,
			sql: `
				CREATE TABLE affected_new (
					vuln_id TEXT NOT NULL,
					ecosystem TEXT NOT NULL,
					package TEXT NOT NULL,
					PRIMARY KEY (vuln_id, ecosystem, package),
					FOREIGN KEY (vuln_id) REFERENCES vulnerability(id) ON DELETE CASCADE
				);
				INSERT INTO affected_new (vuln_id, ecosystem, package)
					SELECT vuln_id, ecosystem, package FROM affected;
				DROP TABLE affected;
				ALTER TABLE affected_new RENAME TO affected;
				CREATE INDEX IF NOT EXISTS idx_affected_ecosystem ON affected(ecosystem);
			`,
			disablesFKDuringRebuild: true,
		},
		{version: 3, sql: "UPDATE vulnerability SET published = NULL WHERE published = ''"},
		{
			version: 4,
			sql: `
				ALTER TABLE vulnerability ADD COLUMN fetched_at INTEGER NOT NULL DEFAULT 0;
				UPDATE vulnerability
					SET fetched_at = CAST(strftime('%s', modified) AS INTEGER) * 1000000000
					WHERE fetched_at = 0;
			`,
		},
		{
			version: 5,
			sql: `
				CREATE TABLE report_watermark (
					ecosystem TEXT PRIMARY KEY,
					reported_until INTEGER NOT NULL
				);
				INSERT INTO report_watermark (ecosystem, reported_until)
					SELECT ecosystem,
					       MAX(CAST(strftime('%s', modified) AS INTEGER) * 1000000000)
					FROM reported_snapshot
					GROUP BY ecosystem;
				DROP TABLE reported_snapshot;
			`,
		},
		{version: 6, sql: "ALTER TABLE vulnerability ADD COLUMN severity_type TEXT"},
		{version: 7, sql: "DROP TABLE IF EXISTS tombstone"},
		{version: 8, sql: "ALTER TABLE source_cursor ADD COLUMN etag TEXT"},
	}

	for _, m := range migrations {
		if m.version <= version {
			continue
		}
		if m.disablesFKDuringRebuild {
			if _, err := s.db.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
				return fmt.Errorf("disable foreign_keys for v%d: %w", m.version, err)
			}
		}
		err := withTx(ctx, s.db, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, m.sql); err != nil {
				return fmt.Errorf("migration v%d: %w", m.version, err)
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO schema_version (version) VALUES (?)", m.version); err != nil {
				return fmt.Errorf("update schema version to %d: %w", m.version, err)
			}
			return nil
		})
		if m.disablesFKDuringRebuild {
			// Restore FK regardless of migration outcome so subsequent connection
			// reuse can't see foreign_keys=OFF (a leaked PRAGMA outlives the tx).
			if _, e := s.db.ExecContext(ctx, "PRAGMA foreign_keys=ON"); e != nil {
				return fmt.Errorf("re-enable foreign_keys after v%d: %w", m.version, e)
			}
		}
		if err != nil {
			return err
		}
		if m.disablesFKDuringRebuild {
			// Confirm no orphan rows were left behind by the rebuild. Scan a single
			// row: sql.ErrNoRows means the check is clean; any other outcome is a
			// violation that should fail the migration loudly.
			var table, parent sql.NullString
			var rowid, fkid sql.NullInt64
			scanErr := s.db.QueryRowContext(ctx, "PRAGMA foreign_key_check").Scan(&table, &rowid, &parent, &fkid)
			if scanErr == nil {
				return fmt.Errorf("foreign_key_check after v%d: orphan in %s", m.version, table.String)
			}
			if !errors.Is(scanErr, sql.ErrNoRows) {
				return fmt.Errorf("foreign_key_check after v%d: %w", m.version, scanErr)
			}
		}
	}

	return nil
}

// SaveCursor saves the cursor for a given source.
func (s *Store) SaveCursor(ctx context.Context, source string, cursor time.Time) error {
	query := `
		INSERT INTO source_cursor (source, cursor)
		VALUES (?, ?)
		ON CONFLICT(source) DO UPDATE SET cursor = excluded.cursor
	`
	_, err := s.db.ExecContext(ctx, query, source, cursor.UTC().Format(timeFormat))
	if err != nil {
		return fmt.Errorf("save cursor: %w", err)
	}
	return nil
}

// GetETag retrieves the ETag stored alongside a source cursor, or empty
// string if no row or no ETag exists yet.
func (s *Store) GetETag(ctx context.Context, source string) (string, error) {
	var etag sql.NullString
	err := s.db.QueryRowContext(ctx, "SELECT etag FROM source_cursor WHERE source = ?", source).Scan(&etag)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("get etag: %w", err)
	}
	if !etag.Valid {
		return "", nil
	}
	return etag.String, nil
}

// SaveETag records the ETag returned by the upstream HTTP server. The
// cursor row is created on first call (with an empty cursor string) so
// the unified source can store ETag-only state without a meaningful
// timestamp.
func (s *Store) SaveETag(ctx context.Context, source, etag string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO source_cursor (source, cursor, etag)
		VALUES (?, '', ?)
		ON CONFLICT(source) DO UPDATE SET etag = excluded.etag
	`, source, etag)
	if err != nil {
		return fmt.Errorf("save etag: %w", err)
	}
	return nil
}

// GetCursor retrieves the cursor for a given source.
// Returns sql.ErrNoRows directly if no cursor exists for the source,
// allowing callers to distinguish "no cursor yet" from database errors.
func (s *Store) GetCursor(ctx context.Context, source string) (time.Time, error) {
	query := `SELECT cursor FROM source_cursor WHERE source = ?`
	var cursorStr string
	err := s.db.QueryRowContext(ctx, query, source).Scan(&cursorStr)
	if err != nil {
		// Return sql.ErrNoRows directly to allow caller to distinguish
		// "no cursor found" from actual database errors
		if errors.Is(err, sql.ErrNoRows) {
			return time.Time{}, sql.ErrNoRows
		}
		return time.Time{}, fmt.Errorf("get cursor: %w", err)
	}

	cursor, err := time.Parse(timeFormat, cursorStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse cursor: %w", err)
	}

	return cursor, nil
}

// SaveVulnerabilityWithAffected upserts a vulnerability and replaces its
// affected-package set atomically.
//
// Why one combined API rather than two separate calls: OSV publishes the
// complete affected set with each vulnerability record, so an additive
// "append affected rows" API leaks stale entries when an upstream record
// shrinks its affected list. The DELETE inside the tx makes the persisted
// set match the input set exactly.
//
// fetched_at is stamped here from s.clock, not from the caller, so the
// watermark axis is decoupled from the OSV-supplied modified timestamp.
// That decoupling prevents records whose modified is older than the
// previous watermark from being silently skipped on re-fetch.
func (s *Store) SaveVulnerabilityWithAffected(ctx context.Context, v Vulnerability, affected []Affected) error {
	publishedParam := any(nil)
	if !v.Published.IsZero() {
		publishedParam = v.Published.UTC().Format(timeFormat)
	}
	fetchedAt := s.clock().UTC().UnixNano()

	return withTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO vulnerability (id, modified, published, summary, details, severity_base_score, severity_vector, severity_type, fetched_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				modified = excluded.modified,
				published = excluded.published,
				summary = excluded.summary,
				details = excluded.details,
				severity_base_score = excluded.severity_base_score,
				severity_vector = excluded.severity_vector,
				severity_type = excluded.severity_type,
				fetched_at = excluded.fetched_at
		`,
			v.ID,
			v.Modified.UTC().Format(timeFormat),
			publishedParam,
			v.Summary,
			v.Details,
			toNullableFloat(v.SeverityBaseScore),
			toNullString(v.SeverityVector),
			toNullString(v.SeverityType),
			fetchedAt,
		); err != nil {
			return fmt.Errorf("upsert vulnerability: %w", err)
		}

		if _, err := tx.ExecContext(ctx, "DELETE FROM affected WHERE vuln_id = ?", v.ID); err != nil {
			return fmt.Errorf("delete old affected: %w", err)
		}

		if len(affected) == 0 {
			return nil
		}

		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO affected (vuln_id, ecosystem, package)
			VALUES (?, ?, ?)
			ON CONFLICT(vuln_id, ecosystem, package) DO NOTHING
		`)
		if err != nil {
			return fmt.Errorf("prepare insert affected: %w", err)
		}
		defer stmt.Close() //nolint:errcheck
		for _, a := range affected {
			if _, err := stmt.ExecContext(ctx, a.VulnID, a.Ecosystem, a.Package); err != nil {
				return fmt.Errorf("insert affected: %w", err)
			}
		}
		return nil
	})
}

// DeleteVulnerability removes a vulnerability and (via ON DELETE CASCADE
// on the affected table) its package rows. Used when the upstream marks
// a record as withdrawn or returns 404.
func (s *Store) DeleteVulnerability(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM vulnerability WHERE id = ?", id); err != nil {
		return fmt.Errorf("delete vulnerability: %w", err)
	}
	return nil
}

// scanReportRows scans report rows from sql.Rows. Column order must match
// the SELECT lists in reportSelectColumns.
func scanReportRows(rows *sql.Rows) ([]ReportRow, error) {
	var entries []ReportRow
	for rows.Next() {
		var r ReportRow
		var score sql.NullFloat64
		if err := rows.Scan(
			&r.ID, &r.Ecosystem, &r.Package,
			&r.Published, &r.Modified, &r.FetchedAt,
			&score, &r.SeverityVector, &r.SeverityType,
		); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		if score.Valid {
			r.SeverityScore = &score.Float64
		}
		entries = append(entries, r)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return entries, nil
}

// reportSelectColumns is the SELECT projection shared by every query that
// produces a ReportRow. Defined once so the SELECT-order vs Scan-order
// contract has a single source of truth.
const reportSelectColumns = `
	v.id, a.ecosystem, a.package,
	COALESCE(v.published, '') as published,
	v.modified, v.fetched_at,
	v.severity_base_score,
	COALESCE(v.severity_vector, '') as severity_vector,
	COALESCE(v.severity_type, '') as severity_type`

// ecosystemClause returns the WHERE fragment and argument list used to
// restrict a vulnerability/affected join to a single ecosystem. Empty
// ecosystem produces no restriction.
func ecosystemClause(ecosystem, prefix string) (string, []any) {
	if ecosystem == "" {
		return "", nil
	}
	return prefix + " a.ecosystem = ?", []any{ecosystem}
}

// GetVulnerabilitiesForReport retrieves vulnerabilities for reporting.
func (s *Store) GetVulnerabilitiesForReport(ctx context.Context, ecosystem string) ([]ReportRow, error) {
	clause, args := ecosystemClause(ecosystem, " WHERE")
	query := `
		SELECT ` + reportSelectColumns + `
		FROM vulnerability v
		INNER JOIN affected a ON v.id = a.vuln_id` + clause + `
		ORDER BY COALESCE(v.published, v.modified) DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	return scanReportRows(rows)
}

// DeleteVulnerabilitiesOlderThan deletes vulnerabilities and related data older than the cutoff time.
func (s *Store) DeleteVulnerabilitiesOlderThan(ctx context.Context, cutoff time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	cutoffStr := cutoff.UTC().Format(timeFormat)

	// Delete affected records for old vulnerabilities
	_, err = tx.ExecContext(ctx, `
		DELETE FROM affected WHERE vuln_id IN (
			SELECT id FROM vulnerability WHERE modified < ?
		)
	`, cutoffStr)
	if err != nil {
		return fmt.Errorf("delete old affected records: %w", err)
	}

	// Delete old vulnerabilities
	_, err = tx.ExecContext(ctx, `DELETE FROM vulnerability WHERE modified < ?`, cutoffStr)
	if err != nil {
		return fmt.Errorf("delete old vulnerabilities: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

// GetUnreportedVulnerabilities returns the affected-package rows whose
// fetched_at is past the report_watermark entry for their ecosystem.
// Rows with no watermark entry (a freshly-tracked ecosystem) are all
// returned. The watermark is per-ecosystem so an ecosystem-filtered diff
// run never disturbs the watermark of any other ecosystem.
func (s *Store) GetUnreportedVulnerabilities(ctx context.Context, ecosystem string) ([]ReportRow, error) {
	clause, args := ecosystemClause(ecosystem, " AND")
	query := `
		SELECT ` + reportSelectColumns + `
		FROM vulnerability v
		INNER JOIN affected a ON v.id = a.vuln_id
		LEFT JOIN report_watermark w ON w.ecosystem = a.ecosystem
		WHERE v.fetched_at > COALESCE(w.reported_until, 0)` + clause + `
		ORDER BY COALESCE(v.published, v.modified) DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query unreported vulnerabilities: %w", err)
	}
	defer rows.Close() //nolint:errcheck

	return scanReportRows(rows)
}

// AdvanceWatermarks records that the given rows have been reported.
// For each ecosystem touched it stores max(fetched_at) and refuses to
// move backwards, so a stale or filtered re-run cannot regress the
// watermark and re-flag rows that are already reported.
func (s *Store) AdvanceWatermarks(ctx context.Context, rows []ReportRow) error {
	if len(rows) == 0 {
		return nil
	}
	maxByEcosystem := make(map[string]int64)
	for _, r := range rows {
		if r.FetchedAt > maxByEcosystem[r.Ecosystem] {
			maxByEcosystem[r.Ecosystem] = r.FetchedAt
		}
	}

	return withTx(ctx, s.db, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO report_watermark (ecosystem, reported_until)
			VALUES (?, ?)
			ON CONFLICT(ecosystem) DO UPDATE
				SET reported_until = excluded.reported_until
				WHERE excluded.reported_until > report_watermark.reported_until
		`)
		if err != nil {
			return fmt.Errorf("prepare upsert watermark: %w", err)
		}
		defer stmt.Close() //nolint:errcheck

		for eco, fa := range maxByEcosystem {
			if _, err := stmt.ExecContext(ctx, eco, fa); err != nil {
				return fmt.Errorf("upsert watermark for %s: %w", eco, err)
			}
		}
		return nil
	})
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
