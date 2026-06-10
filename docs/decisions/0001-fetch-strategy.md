# 0001: OSV Fetch Strategy

## Status

Decided — adopt **Candidate 1 (unified `all.zip`)**. Project takes **Phase F (unified subpath)**; Phase E is skipped.

## Context

The pre-rev5 fetch layer (sitemap + per-id API) carried the bulk of the
review findings (§1-2, §1-4, §1-5, §1-9 and the entire osv package polish).
Phase 0-S is a half-day investigation spike to decide whether to repair that
layer (Phase E) or replace it with a single zip download (Phase F).

The driving questions: does the unified `all.zip` actually exist, does GCS
honour conditional requests (so the second daily fetch is essentially free),
and does the zip preserve `withdrawn` records in-place (so we don't need an
ID-set diff to detect revocations)?

## Findings

Empirical probes against `https://osv-vulnerabilities.storage.googleapis.com/`
on 2026-06-10. Headers via `curl -sD`, body via `curl -s [-r 0-N]`, JSON
inspected with a streaming `PK\x03\x04` walker because GCS-produced zips set
flag bit 3 (data descriptor) and a Range-truncated file has no central
directory.

| Property | Unified `all.zip` | `npm/all.zip` | `Go/all.zip` |
|---|---|---|---|
| Exists (HTTP 200) | yes | yes | yes |
| Content-Type | `application/zip` | `application/zip` | `application/zip` |
| Content-Length | 1 252 385 668 (~1.17 GiB) | 206 524 841 (~197 MiB) | 8 918 662 (~8.5 MiB) |
| `Accept-Ranges: bytes` | yes | yes | yes |
| ETag | `"f1ba5f8be90dab59942450e1d40abf44"` | `"44866e0e8b2b8c272990d77b2ca9f5f9"` | `"0521780543d70f0ff052d9860c27d97a"` |
| Last-Modified | Wed, 10 Jun 2026 09:37:53 GMT | Wed, 10 Jun 2026 08:06:20 GMT | Tue, 09 Jun 2026 22:21:23 GMT |
| `Cache-Control` | `public, max-age=3600` | same | same |
| `If-None-Match` → 304 | yes (verified) | yes (verified) | yes (verified) |
| `If-Modified-Since` → 304 | yes (verified) | n/a (subsumed by ETag) | n/a |
| Record has top-level `modified` (RFC3339) | yes, 100% (sampled 67 162) | yes, 100% (sampled 8 892) | yes, 100% (7 155 / 7 155) |
| `modified` precision varies | yes — string lengths {20, 24, 27, 30}; not fixed `RFC3339Nano` | same | same |
| Record has optional top-level `withdrawn` | yes (22 112 / 67 162 sampled ≈ 32 %) | yes (276 / 8 892 ≈ 3.1 %) | yes (105 / 7 155 ≈ 1.5 %) |
| Withdrawn records remain in zip | **yes** — `withdrawn != null` is the per-record signal; no expungement observed | **yes** | **yes** (e.g. `GO-2020-0031`) |
| Record count | ≈ 1.6 M (extrapolated: 67 163 local headers in first 50 MB × full size) | ≈ 183 k (extrapolated) | 7 155 (exact) |
| ID-set diff needed? | no (withdrawn is in-band) | no, but app-side dedup needed across ecosystems | no for self, but combined per-eco set-diff required across all 46 ecosystems |
| ID-set memory if we did keep one | ~34 MiB raw / ~150 MiB as `map[string]struct{}` for 1.6 M IDs at 22 B avg | small | small |

Unified zip serves all 46 ecosystems listed in
`https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt`
(`AlmaLinux`, …, `npm`, `Go`, etc.). The high withdrawn share in the unified
sample comes from `ALBA-*` / `ALEA-*` (AlmaLinux errata) — confirming that
even distros that aggressively revoke entries keep the records in the zip
with `withdrawn` set.

## Decision

**Adopt the unified `all.zip`** and route the project to **Phase F (unified
subpath)**. The unified zip exists, ships ETag + Last-Modified with working
304 responses, contains every ecosystem in a single de-duplicated stream,
and preserves withdrawn records with a top-level RFC3339 `withdrawn` field —
which collapses the "did this ID disappear?" question into a single
per-record check. The 1.17 GiB transfer cost is paid once per change and
zero on no-op days thanks to 304; in exchange we delete the entire sitemap +
per-id-API + rate-limiter + retry path.

## Consequences

Code that goes away (per plan §Phase F-3):
- `internal/osv/sitemap.go` (and `_test.go`)
- The rate limiter, retry wrapper, `RoundTrip`, and most `ClientOption`
  surface in `internal/osv/client.go`
- `processEntry` / `processEntriesParallel` in `internal/app/fetch_batch.go`
  and the per-id API loop in `internal/app/fetch.go`
- `model.SitemapURL` and `model.ModifiedCSVURL` (the latter migrates per
  plan §F-4 — under the unified subpath the URL is not per-ecosystem, so it
  is deleted from `model` and a single `unifiedAllZipURL` constant lives in
  the `osv` package)

Code that gets written:
- `internal/osv/normalize.go` — pure `jsonVulnerability → model.Vulnerability`
- `internal/osv/allzip.go` — unified `Source` + `FetchResult` per plan §F-1
- Migration **v8**: add `etag TEXT` column alongside `source_cursor` for
  conditional GET state. Cursor key is the constant `"__unified__"` per
  plan §F-2
- App-side ecosystem filter (plan §F-2): only events whose `vuln.Affected[*]`
  intersect the configured `cfg.Ecosystems` set are passed to the store. The
  unified zip includes Linux distros we do not want to ingest

Phase routing:
- **Phase E is skipped in full.** Phase 0 → A → B → C → D → F (unified)
- Migration sequence becomes v2 (A-0) / v3 (A-3) / v4 (B-0) / v5 (B-1/B-2)
  / v6 (C-2b) / v7 (tombstone DROP) / v8 (etag) — no collision with E

ID-set delete logic: not required for the unified path. Per plan §F-1's
"ObservedIDs returns error → skip set-diff delete" guard, the unified
`Source` may simply never advertise `ObservedIDs` (or return an error from
it) so the app always relies on the per-record `Withdrawn` signal. If a
defensive set-diff is wanted later, the ~150 MiB peak `map[string]struct{}`
for 1.6 M IDs is tolerable but not free.

## Followups

- Confirm during implementation that the unified zip's withdrawn semantics
  hold for **all** ecosystems we filter to (sampled here: GHSA, GO, MAL,
  ALBA, ALEA). If any ecosystem expunges instead of marking withdrawn, the
  set-diff fallback per plan §F-2 must be turned on for that subset
- The `modified` string is not zero-padded — observed lengths {20, 24, 27,
  30}. Phase B already stores `fetched_at` as Unix nanoseconds (INTEGER) so
  this is a non-issue for watermarks, but the `osv/normalize.go` parser
  must accept all four shapes (use `time.Parse(time.RFC3339, …)` after
  trimming, not `RFC3339Nano`)
- Confirm `cache-control: public, max-age=3600` does not cause stale 200s
  via intermediate proxies in CI — the ETag round-trip itself is
  origin-served, but if a corporate proxy serves a cached body we lose the
  304 fast-path. Run a back-to-back fetch in CI to verify

## Operational notes (rev5)

- `defaultAllZipHTTPTimeout` is 30 minutes. A 1.17 GiB body over a low-end
  pipe (≈ 1 MB/s) just clears that window; raise the timeout via
  `WithUnifiedHTTPClient` if a deployment routinely sees timeouts.
- The download lands in `os.TempDir()`. On Linux distributions where
  `/tmp` is a `tmpfs`, that means ~1.2 GiB of RAM until the iterator
  closes. Set `TMPDIR` to the same directory as the SQLite database (or
  any disk-backed mount) to keep RAM use bounded.
- Past the rev5 state rewrite there is no `__unified__` literal in the
  migrations. Migration v9 truncates `source_cursor` because the rev4
  rows could be carrying silently-skipped state (bug #4) or an orphan
  ETag (bug #1); the cost is one extra ~1.2 GiB download after upgrade.
- `OSV_ECOSYSTEMS` changes are picked up automatically: the persisted
  ecosystems fingerprint is compared with the configured set on every
  run, and a mismatch forces a full refetch (cursor and ETag cleared)
  so newly-subscribed ecosystems pick up historical records. Removing an
  ecosystem also triggers a full refetch — the existing rows are not
  deleted on the spot, so for the retention window the report still
  shows the dropped ecosystem. This is an accepted trade-off; the
  alternative is bespoke "diff the configured set" logic.

### Tail-risk: a permanently undecodable record

Strict-fail (`decodeFailures > 0 ⇒ state held, exit 1`) is the only
safe response to a record we cannot decode — the failing record's
modified is unknown so we cannot advance the cursor past it. The blast
radius is the **whole OSV corpus** (~1.6 M records), not just the
configured ecosystems, because `decodeZipEntry` runs before the
ecosystem filter: an AlmaLinux record's schema drift halts an
npm-only deployment. The upstream schema is strict enough that the
realised rate is low (0-S sampled every record in npm / Go / unified
and parsed cleanly), so we accept the tail rather than build an escape
hatch in this rev.

retention runs on every exit path after the state has loaded, so
multi-day decode-failure outages drain the database to empty within
the retention window. That follows from the freshness contract: data
older than `OSV_DATA_RETENTION_DAYS` is out of scope by design, and
preserving the last good snapshot past that window would defeat the
contract. Treat a continuous decode failure as a P1.

### Runbooks

- **Repeated `N source events failed to decode` exit 1**: inspect the
  `decode <file>.json` warning to identify the failing entry in the
  zip. `DELETE FROM source_cursor` does NOT help here — the same zip
  re-served from upstream will fail on the same entry. Either wait for
  the OSV.dev fix (file an issue with the entry ID) or patch
  `rawVulnerability` / `normalize` for the schema drift. Watch the
  retention window: the DB empties at the cutoff.
- **`get source state: parse cursor: ...` at startup**: external
  tampering put a non-RFC3339 cursor value in `source_cursor`. Run
  `DELETE FROM source_cursor WHERE source = '__unified__'` to clear it;
  the next run does a full refetch.
