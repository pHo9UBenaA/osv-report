package main

import "fmt"

// showHelp displays usage information.
func showHelp() {
	fmt.Print(`
Work with the OSV vulnerability database from the command line.

USAGE
  osv-report <command> [flags]

CORE COMMANDS
  fetch:        Fetch the latest vulnerability data from the OSV API
  report:       Generate a report from the local vulnerability database
  help:         Show this help message

REPORT FLAGS
  --format:                Report format: markdown, csv, jsonl (default: markdown)
  --output-dir:            Report output directory (default: .)
  --file-prefix:           Report filename prefix (default: report)
  --ecosystem:             Filter report by ecosystem (empty = all)
  --diff:                  Generate differential report (only new/changed vulnerabilities)

ENVIRONMENT VARIABLES
  OSV_ECOSYSTEMS           Comma-separated ecosystems (e.g. npm,PyPI,Go)
                           Full list: https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt
  OSV_DB_PATH              Path to the local database (default: ./osv.db)
  OSV_DATA_RETENTION_DAYS  Data retention period in days (default: 7)

EXAMPLES
  $ OSV_ECOSYSTEMS=npm,PyPI osv-report fetch
  $ osv-report report --format markdown --output-dir . --file-prefix report
  $ osv-report report --diff --format csv --ecosystem npm --output-dir ./reports --file-prefix npm-vuln

LEARN MORE
  Read the manual at https://github.com/pHo9UBenaA/osv-report/
`)
}
