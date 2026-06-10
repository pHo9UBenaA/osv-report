## Database Schema

### vulnerability
Stores vulnerability information

```sql
CREATE TABLE vulnerability (
    id TEXT PRIMARY KEY, -- Vulnerability ID (e.g., "GHSA-xxxx-xxxx-xxxx")
    modified TEXT NOT NULL, -- Last updated time (RFC3339 format)
    published TEXT, -- Publication time (RFC3339 format)
    summary TEXT, -- Vulnerability summary
    details TEXT, -- Detailed description
    severity_base_score REAL, -- CVSS base score rounded to one decimal
    severity_vector TEXT -- CVSS vector string
);
```

### affected
Stores affected packages for each vulnerability

```sql
CREATE TABLE affected (
    vuln_id TEXT NOT NULL, -- Foreign key to vulnerability.id
    ecosystem TEXT NOT NULL, -- Ecosystem name (e.g., "npm", "PyPI", "Go")
    package TEXT NOT NULL, -- Package name
    PRIMARY KEY (vuln_id, ecosystem, package),
    FOREIGN KEY (vuln_id) REFERENCES vulnerability(id)
);
```

### source_cursor
Manages processing cursor (last processed time) for each ecosystem

```sql
CREATE TABLE source_cursor (
    source TEXT PRIMARY KEY, -- Ecosystem name (e.g., "npm", "PyPI", "Go")
    cursor TEXT NOT NULL -- Last processed time (RFC3339 format)
);
```

### tombstone
Records deleted vulnerabilities (tombstones)

```sql
CREATE TABLE tombstone (
    id TEXT PRIMARY KEY, -- Deleted vulnerability ID
    deleted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### reported_snapshot
Tracks vulnerabilities included in differential reports

```sql
CREATE TABLE reported_snapshot (
    id TEXT NOT NULL, -- Vulnerability ID
    ecosystem TEXT NOT NULL, -- Ecosystem name
    package TEXT NOT NULL, -- Package name
    published TEXT, -- Publication time
    modified TEXT, -- Last modified time
    severity_base_score REAL, -- CVSS base score (nullable)
    severity_vector TEXT, -- CVSS vector string
    PRIMARY KEY (id, ecosystem, package)
);
```

## Indexes

### Automatic Indexes (from PRIMARY KEY constraints)

- `vulnerability(id)` - Primary key index
- `affected(vuln_id, ecosystem, package)` - Composite primary key index
- `source_cursor(source)` - Primary key index
- `tombstone(id)` - Primary key index
- `reported_snapshot(id, ecosystem, package)` - Composite primary key index

### Performance Optimization Indexes

- `idx_affected_ecosystem` - Index on `affected(ecosystem)` for efficient ecosystem filtering
- `idx_vulnerability_modified` - Index on `vulnerability(modified)` for efficient date-based queries and deletion

## Data Retention

- Vulnerability data older than `OSV_DATA_RETENTION_DAYS` (default: 7 days) is automatically deleted during fetch operations
- The `source_cursor` table maintains the synchronization state for incremental updates
- The `reported_snapshot` table is cleared and rebuilt when generating differential reports
