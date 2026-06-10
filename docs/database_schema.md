## Database Schema

### vulnerability
Stores vulnerability information.

```sql
CREATE TABLE vulnerability (
    id TEXT PRIMARY KEY, -- Vulnerability ID (e.g., "GHSA-xxxx-xxxx-xxxx")
    modified TEXT NOT NULL, -- Last updated time, RFC3339 UTC
    published TEXT, -- Publication time, RFC3339 UTC; NULL if upstream omitted it
    summary TEXT,
    details TEXT,
    severity_base_score REAL, -- CVSS base score (NULL if no usable CVSS entry)
    severity_vector TEXT, -- The chosen CVSS vector string
    severity_type TEXT, -- One of CVSS_V2 / CVSS_V3.0 / CVSS_V3.1 / CVSS_V4.0
    fetched_at INTEGER NOT NULL -- Ingest timestamp, Unix nanoseconds (drives the diff watermark)
);
```

### affected
Stores affected packages for each vulnerability. The foreign key cascades
deletions so removing a vulnerability cleans up its package rows in one step.

```sql
CREATE TABLE affected (
    vuln_id TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    package TEXT NOT NULL,
    PRIMARY KEY (vuln_id, ecosystem, package),
    FOREIGN KEY (vuln_id) REFERENCES vulnerability(id) ON DELETE CASCADE
);
```

### source_cursor
Tracks per-source ingest state. The unified all.zip source uses a single row
keyed `__unified__`: `cursor` is the last record-level modified time seen,
`etag` is the HTTP ETag used for `If-None-Match`.

```sql
CREATE TABLE source_cursor (
    source TEXT PRIMARY KEY,
    cursor TEXT NOT NULL, -- Last processed modified time, RFC3339 UTC
    etag TEXT -- ETag for If-None-Match; only meaningful for the unified source
);
```

### report_watermark
One row per ecosystem that has been included in any `--diff` report. Stores
the maximum `fetched_at` (Unix nanoseconds) that has already been reported;
new vulnerabilities surface only when their `fetched_at` strictly exceeds
this. Per-ecosystem keying means an ecosystem-filtered diff run never
disturbs the watermark of any other ecosystem.

```sql
CREATE TABLE report_watermark (
    ecosystem TEXT PRIMARY KEY,
    reported_until INTEGER NOT NULL
);
```

### schema_version
Records the highest applied migration. Each migration body and its
`INSERT INTO schema_version` are wrapped in a single transaction so a crash
between the two cannot leave a half-applied state.

```sql
CREATE TABLE schema_version (
    version INTEGER NOT NULL
);
```

## Indexes

### Automatic indexes (from PRIMARY KEY constraints)

- `vulnerability(id)`
- `affected(vuln_id, ecosystem, package)`
- `source_cursor(source)`
- `report_watermark(ecosystem)`

### Performance indexes

- `idx_affected_ecosystem` on `affected(ecosystem)` — for ecosystem-filtered report queries.
- `idx_vulnerability_modified` on `vulnerability(modified)` — for retention-based deletion.

## Data Retention

- Vulnerability data older than `OSV_DATA_RETENTION_DAYS` (default: 7 days) is deleted during fetch via `DELETE FROM vulnerability WHERE modified < cutoff`. The `affected` rows cascade.
- `source_cursor` keeps cross-run state for the unified source (cursor + ETag).
- `report_watermark` advances per-ecosystem after each `--diff` report.
