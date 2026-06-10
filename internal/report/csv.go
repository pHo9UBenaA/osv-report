package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// CSVFormatter renders entries as RFC 4180 CSV with a header row.
// Values whose first rune could be interpreted as a spreadsheet
// formula (=, +, -, @) — or a leading control character that strips to
// such a rune — are prefixed with a single quote to neutralise them.
type CSVFormatter struct{}

// Extension returns ".csv".
func (f *CSVFormatter) Extension() string { return ".csv" }

// Format writes the CSV report to w. Errors from the underlying
// csv.Writer (including its deferred Flush) are returned wrapped.
func (f *CSVFormatter) Format(w io.Writer, entries []VulnerabilityEntry) error {
	cw := csv.NewWriter(w)

	header := []string{"ecosystem", "package", "id", "published", "modified", "severity_base_score", "severity_type", "severity_vector"}
	if err := cw.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	for _, e := range entries {
		record := []string{
			escapeCSVInjection(e.Ecosystem),
			escapeCSVInjection(e.Package),
			escapeCSVInjection(e.ID),
			escapeCSVInjection(formatString(e.Published)),
			escapeCSVInjection(formatString(e.Modified)),
			escapeCSVInjection(formatBaseScore(e.SeverityBaseScore)),
			escapeCSVInjection(formatString(e.SeverityType)),
			escapeCSVInjection(formatString(e.SeverityVector)),
		}
		if err := cw.Write(record); err != nil {
			return fmt.Errorf("write record: %w", err)
		}
	}

	cw.Flush()
	if err := cw.Error(); err != nil {
		return fmt.Errorf("flush csv: %w", err)
	}
	return nil
}

// escapeCSVInjection prevents CSV formula injection by prefixing
// dangerous characters with a single quote.
//
// Two-stage check is necessary because strings.TrimLeftFunc(unicode.
// IsSpace) eats '\t', '\r', and '\n' — so by the time we look at the
// "trimmed" first rune those control characters have already been
// consumed and would slip past the formula-injection guard. Stage 1
// inspects the raw first rune for those control codes; stage 2 strips
// leading whitespace (so " =cmd" is still caught) and checks the usual
// =+-@ prefixes.
func escapeCSVInjection(s string) string {
	if s == "" {
		return s
	}

	// Stage 1: raw first-rune check for control characters that
	// TrimLeftFunc would otherwise discard before we could inspect them.
	if r, _ := utf8.DecodeRuneInString(s); r == '\t' || r == '\r' || r == '\n' {
		return "'" + s
	}

	// Stage 2: usual formula-injection guard, after stripping leading
	// space so " =cmd" still gets caught.
	trimmed := strings.TrimLeftFunc(s, unicode.IsSpace)
	if trimmed == "" {
		return s
	}
	switch r, _ := utf8.DecodeRuneInString(trimmed); r {
	case '=', '+', '-', '@':
		return "'" + s
	}
	return s
}
