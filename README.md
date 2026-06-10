# OSV Report

> **PILOT VERSION** — not yet reviewed by contributors. Use with caution.

Fetches vulnerability data directly from the [OSV](https://osv.dev/) ecosystem, stores it locally in SQLite, and generates snapshot or differential reports for ecosystems such as npm, PyPI, Go, and Maven.

## What this tool does

* Fetches vulnerability data from the OSV ecosystem
* Stores fetched data in a local SQLite database
* Generates reports in Markdown, CSV, or JSONL format
* Supports full snapshots and differential (diff) reports

## Quick Start

The steps below show the minimum workflow to fetch vulnerabilities and generate a report.

```bash
# 1. Prepare configuration
cp .env.example .env
```

Edit `.env` and set `OSV_ECOSYSTEMS` to the ecosystems you want to fetch.

```bash
# 2. Fetch vulnerability data
task fetch
```

```bash
# 3. Generate a Markdown report
task report-markdown
```

The Taskfile wrappers write reports under `./reports/` (via `--output-dir=./reports/`). When invoking the CLI directly, the default `--output-dir` is the current directory (`.`).

## How it works

The tool follows a simple lifecycle:

1. Fetch vulnerability data from OSV for configured ecosystems
2. Persist the data locally in SQLite, keeping historical state
3. Generate reports from the stored data, either as full snapshots or diffs

<details>

### Fetch phase

* Loads configuration from `.env` / environment variables (`OSV_ECOSYSTEMS`, `OSV_DB_PATH`, `OSV_DATA_RETENTION_DAYS`).
* For each ecosystem, reads the last processed cursor from `source_cursor` and fetches the ecosystem sitemap.
* Extracts `(vulnerability ID, lastmod)` from the sitemap and keeps only entries newer than the cursor.
* Fetches vulnerability details from `GET /v1/vulns/{id}` with rate limiting (10 req/s), retry-on-429, batches of 100, and bounded parallelism (5 concurrent).
* If the OSV API returns 404 for an ID, records it as a tombstone.
* After the fetch completes, rows older than `OSV_DATA_RETENTION_DAYS` are deleted to keep the database bounded.

### Store phase

* Persists data in SQLite (`OSV_DB_PATH`) using upserts for `vulnerability` and idempotent inserts for `affected`.
* Tracks progress per ecosystem in `source_cursor` so subsequent runs only fetch newly modified entries.
* Deletes vulnerabilities (and related `affected` rows) older than the retention cutoff during fetch to keep the DB size bounded.
* Keeps `tombstone` and `reported_snapshot` tables for deleted IDs and diff reporting.

### Report phase

* Reads from SQLite by joining `vulnerability` and `affected`, ordered by published/modified time, optionally filtered by ecosystem.
* Writes Markdown / CSV / JSONL reports to the output directory as `prefix_YYYYMMDDThhmmssZ.ext` (UTC timestamp).
* Snapshot reports emit the current rows in the DB.
* Diff reports advance a per-ecosystem watermark, so consecutive diff runs only emit rows changed since the last report.

</details>

## Reports: Snapshot and Diff

Snapshot and diff reports are generated from the same stored data, but differ in how they compare the current state to past runs.

* **Snapshot reports** include all vulnerabilities currently stored in the database
* **Diff reports** include only vulnerabilities that are new or updated since the last diff run
* Diff reports use `reported_snapshot` as the baseline and rebuild it on each run

## Using the CLI directly

If you prefer to bypass the Taskfile wrappers, run `./osv-report` yourself: it exposes a simple command set that mirrors the documented workflow.

<details>

### Commands overview

* `fetch` – pulls fresh vulnerabilities for every configured ecosystem, respects stored cursors and retention window, and saves the results locally.
* `report` – reads the stored data and writes Markdown/CSV/JSONL exports, optionally filtered by ecosystem and/or limited to new edits since the previous diff report.
* `help` (`-h`/`--help`) – prints usage text and exits without touching the database.

### Report flags

```bash
./osv-report report --diff --format csv --ecosystem npm --output-dir ./reports --file-prefix npm-vuln
```

Options:

* `--format` (`markdown`, `csv`, or `jsonl`)
* `--output-dir` (destination directory)
* `--file-prefix` (prepended to the timestamped filename)
* `--ecosystem` (empty string selects every ecosystem)
* `--diff` (emit only rows that are new or changed since the last diff report)

Both commands share the same configuration and SQLite backend, so reports always reflect the data left behind by the most recent fetch run.

</details>

## Configuration

Configuration is provided via `.env` or environment variables.

At minimum, `OSV_ECOSYSTEMS` must be set before running the fetch command.

| Name                      | Description                           | Default                   |
| ------------------------- | ------------------------------------- | ------------------------- |
| `OSV_ECOSYSTEMS`          | Comma-separated ecosystems to monitor ([full list](https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt)) | *(empty – no collection)* |
| `OSV_DB_PATH`             | SQLite database file                  | `./osv.db`                |
| `OSV_DATA_RETENTION_DAYS` | Days of vulnerability data to keep    | `7`                       |

Other operational parameters (API base URL, rate limit, concurrency, batch size, HTTP timeout) are compiled-in constants. See [docs/performance.md](docs/performance.md) for details.

## License

[MIT](./LICENSE)
