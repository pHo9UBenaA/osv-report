## Development

### Prerequisites

- Go 1.25+

The project uses the pure-Go [`modernc.org/sqlite`](https://pkg.go.dev/modernc.org/sqlite) driver, so no C compiler is required.

### Architecture

<details>

```
osv-report/
├── cmd/osv-report/     # CLI entry point
├── internal/            # Internal packages (Go standard)
│   ├── app/             # Application orchestration (fetch, report)
│   ├── config/          # Configuration management (env vars)
│   ├── model/           # Domain models (Vulnerability, Ecosystem, CVSS)
│   ├── osv/             # Unified all.zip Source (download + decode)
│   ├── report/          # Report output (CSV, JSONL, Markdown)
│   └── store/           # SQLite storage (database/sql + modernc.org/sqlite)
├── docs/                # Documentation
└── go.mod
```

**Design Principles:**
- Simple, direct code over unnecessary abstractions (YAGNI)
- Go standard patterns (`internal/` for package privacy)
- Single responsibility: each package has a clear purpose
- Testability through straightforward code, not complex interfaces

</details>

### Testing

```bash
# Run all tests
task test

# With coverage
task test-cover
```

### Code Quality Check

```bash
# Check code formatting
task fmt

# Fix code formatting
task fmt-fix

# Run static analysis
task vet

# Run all checks (test, format, vet)
task check
```
