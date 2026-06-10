// Package report renders vulnerability entries into human- and
// machine-readable output formats (Markdown / CSV / JSONL).
//
// The Formatter abstraction decouples "how to serialise a slice of entries"
// from "where to put the bytes" — callers own the io.Writer (file, buffer,
// network) and the formatter only knows the wire shape. This keeps the
// package free of filesystem or os.File concerns and makes each format
// independently testable.
package report

import (
	"fmt"
	"io"
)

// Formatter renders a slice of vulnerability entries to an io.Writer.
//
// Implementations must write directly to w (no intermediate string build)
// so large reports don't double-buffer the whole payload in memory.
type Formatter interface {
	// Extension returns the conventional file extension (e.g. ".md")
	// for files containing this format. Includes the leading dot.
	Extension() string

	// Format writes all entries to w in this format's encoding. Returns
	// the first write/encode error encountered.
	Format(w io.Writer, entries []VulnerabilityEntry) error
}

// FormatterByName resolves a format name (case-sensitive) to its
// Formatter implementation. Returns ok=false for unknown names so the
// caller can produce a domain-appropriate error message listing the
// supported formats.
func FormatterByName(name string) (Formatter, bool) {
	switch name {
	case "markdown":
		return &MarkdownFormatter{}, true
	case "csv":
		return &CSVFormatter{}, true
	case "jsonl":
		return &JSONLFormatter{}, true
	default:
		return nil, false
	}
}

// formatString returns "NA" if val is empty, otherwise returns val.
// Used by Markdown and CSV which both render "NA" placeholders for
// missing data; JSONL uses native JSON null instead.
func formatString(val string) string {
	if val == "" {
		return "NA"
	}
	return val
}

// formatBaseScore returns "NA" if val is nil, otherwise returns the
// score formatted to one decimal place. Markdown/CSV only — JSONL
// emits the *float64 directly so consumers get a real number or null.
func formatBaseScore(val *float64) string {
	if val == nil {
		return "NA"
	}
	return fmt.Sprintf("%.1f", *val)
}
