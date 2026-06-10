# Performance Notes

This document describes the cost profile of the fetch and report paths
after the migration to the OSV unified `all.zip` download.

## Fetch path

Fetch is dominated by one HTTP transaction:

1. `GET https://osv-vulnerabilities.storage.googleapis.com/all.zip` with
   `If-None-Match: <prev ETag>`.
2. If the server replies `304 Not Modified`, the fetch path skips
   ingestion entirely. The cursor and ETag are kept as-is; the
   retention DELETE still runs so freshness applies regardless of
   whether new data arrived.
3. Otherwise the body (~1.2 GiB as of 2026-06) streams into a temp
   file. The zip is then iterated record-by-record; each entry whose
   ecosystem intersects `OSV_ECOSYSTEMS` is upserted via the combined
   `SaveVulnerabilityWithAffected` transaction.

There is no rate limiter, no retry transport, no per-vulnerability HTTP
call, no per-ecosystem zip download, no goroutine fan-out, and no
batching. The previous code base that needed those knobs has been
replaced; `internal/config/config.go` no longer exposes
`RateLimit`/`MaxConcurrency`/`BatchSize`/`HTTPTimeout` because nothing
in the call graph reads them anymore.

### Cursor and ETag

Two pieces of state persist between runs in the `source_cursor` row
with key `__unified__`:

- `cursor` — the highest `modified` timestamp the previous run
  consumed. The Source uses strict `modified > cursor` to skip
  records that were already processed even when the same zip is
  downloaded again.
- `etag` — the HTTP ETag returned by the server. Sending it as
  `If-None-Match` lets the server respond 304 when the bundle hasn't
  changed, avoiding the 1.2 GiB transfer entirely.

### Withdrawal handling

Records carry a top-level `withdrawn` RFC3339 timestamp when the
upstream has withdrawn them. They remain in the bundle (the 0-S spike
confirmed this across multiple ecosystems), so `withdrawn != null` is
the authoritative delete signal — no ID-set diff against the local
store is required.

### Retention

`OSV_DATA_RETENTION_DAYS` (default 7) is applied at the end of each
fetch via `DELETE FROM vulnerability WHERE modified < cutoff`. The
`affected` rows cascade via `ON DELETE CASCADE`.

## Report path

`osv-report report` does one SQL query and one file write.

- Snapshot mode: `GetVulnerabilitiesForReport` joins `vulnerability ×
  affected`, optionally filters by `--ecosystem`, orders by
  `COALESCE(published, modified) DESC`, and streams rows into the
  chosen formatter.
- Diff mode: `GetUnreportedVulnerabilities` adds a LEFT JOIN against
  `report_watermark` and filters `v.fetched_at > COALESCE(reported_until, 0)`.
  After the file is written, `AdvanceWatermarks` records the maximum
  `fetched_at` per ecosystem seen in the report. The advance is
  monotonic at the SQL level, so a re-run with a stricter filter cannot
  regress the watermark.

Both paths are I/O-light: the report-time cost on a 7-day window is in
the tens of milliseconds.

## Reproducing numbers

```bash
# End-to-end timing for a single ecosystem
time OSV_ECOSYSTEMS=Go ./osv-report fetch

# Second run hits the ETag and should return in well under a second
time OSV_ECOSYSTEMS=Go ./osv-report fetch

# Report
time ./osv-report report --format markdown --output-dir ./reports

# Store-only microbenchmark
go test -bench=BenchmarkSaveVulnerabilityWithAffected ./internal/store/
```

The `BenchmarkSaveVulnerabilityWithAffected` baseline on an Apple M4
with the pure-Go `modernc.org/sqlite` driver is roughly 80 µs/op
including the affected-row washout inside the transaction. End-to-end
fetch wall-clock numbers vary by available bandwidth (the zip is
~1.2 GiB).
