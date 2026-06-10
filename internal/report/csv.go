package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// FormatCSV generates CSV output from vulnerability entries.
func FormatCSV(entries []VulnerabilityEntry) (string, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// Write header
	header := []string{"ecosystem", "package", "id", "published", "modified", "severity_base_score", "severity_type", "severity_vector"}
	if err := w.Write(header); err != nil {
		return "", fmt.Errorf("write header: %w", err)
	}

	// Write entries
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
		if err := w.Write(record); err != nil {
			return "", fmt.Errorf("write record: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return "", fmt.Errorf("flush csv: %w", err)
	}

	return buf.String(), nil
}

// escapeCSVInjection prevents CSV formula injection by prefixing dangerous characters with a single quote.
func escapeCSVInjection(s string) string {
	if s == "" {
		return s
	}

	trimmed := strings.TrimLeftFunc(s, unicode.IsSpace)
	if trimmed == "" {
		return s
	}

	first, _ := utf8.DecodeRuneInString(trimmed)
	dangerous := []rune{'=', '+', '-', '@'}
	for _, d := range dangerous {
		if first == d {
			return "'" + s
		}
	}

	return s
}
