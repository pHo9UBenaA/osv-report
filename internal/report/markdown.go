package report

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// VulnerabilityEntry represents a vulnerability with metrics for reporting.
type VulnerabilityEntry struct {
	ID                string
	Ecosystem         string
	Package           string
	Published         string
	Modified          string
	SeverityBaseScore *float64
	SeverityVector    string
	SeverityType      string
}

// markdownReplacer escapes characters that would otherwise break
// Markdown table cells or render as Markdown syntax.
//
// Order matters: strings.NewReplacer applies rules in argument order on
// non-overlapping input. CRLF must precede LF/CR so it isn't split into
// two <br>; the lone CR rule then catches any standalone "\r".
// Backslash sits last because it would otherwise double-escape the
// backslashes we just added.
var markdownReplacer = strings.NewReplacer(
	"\r\n", "<br>", // CRLF before LF/CR so we emit one <br>, not two
	"\n", "<br>",
	"\r", "<br>",
	"|", "\\|", // Pipe breaks table structure
	"*", "\\*", // Asterisk for emphasis/bold
	"_", "\\_", // Underscore for emphasis/bold
	"[", "\\[", // Opening bracket for links
	"]", "\\]", // Closing bracket for links
	"<", "\\<", // Opening angle bracket for HTML tags
	">", "\\>", // Closing angle bracket for HTML tags
	"`", "\\`", // Backtick for code
	"#", "\\#", // Hash for headers
	"\\", "\\\\", // Backslash itself
)

// MarkdownFormatter renders entries as a Markdown report. The output
// includes a small metadata header (generated-at timestamp, entry
// count, ecosystem filter, diff flag) above the table so reviewers can
// tell at a glance which run produced the file.
//
// Zero value is usable: Ecosystem defaults to "all", Diff to false, and
// Now to time.Now (UTC). The Now field exists purely to make the
// generated timestamp deterministic in tests.
type MarkdownFormatter struct {
	// Ecosystem is the ecosystem filter recorded in the header. Empty
	// string renders as "all" so the header is unambiguous.
	Ecosystem string
	// Diff records whether this run was a differential report.
	Diff bool
	// Now overrides time.Now for the header timestamp. Tests can pin
	// this; production leaves it nil.
	Now func() time.Time
}

// Extension returns ".md".
func (f *MarkdownFormatter) Extension() string { return ".md" }

// Format writes the Markdown report (header + table) to w.
func (f *MarkdownFormatter) Format(w io.Writer, entries []VulnerabilityEntry) error {
	now := f.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	ecosystem := f.Ecosystem
	if ecosystem == "" {
		ecosystem = "all"
	}

	if _, err := fmt.Fprintf(w,
		"# Vulnerability Report\n\n"+
			"- Generated: %s\n"+
			"- Count: %d\n"+
			"- Ecosystem filter: %s\n"+
			"- Diff: %t\n\n",
		now().UTC().Format(time.RFC3339),
		len(entries),
		ecosystem,
		f.Diff,
	); err != nil {
		return fmt.Errorf("write markdown header: %w", err)
	}

	if _, err := io.WriteString(w,
		"| Ecosystem | Package | ID | Published | Modified | Severity: Base Score | Severity: Type | Severity: Vector String |\n"+
			"| --- | --- | --- | --- | --- | --- | --- | --- |\n",
	); err != nil {
		return fmt.Errorf("write markdown table header: %w", err)
	}

	for _, e := range entries {
		if _, err := fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			escapeMarkdown(e.Ecosystem),
			escapeMarkdown(e.Package),
			escapeMarkdown(e.ID),
			escapeMarkdown(formatString(e.Published)),
			escapeMarkdown(formatString(e.Modified)),
			formatBaseScore(e.SeverityBaseScore),
			escapeMarkdown(formatString(e.SeverityType)),
			escapeMarkdown(formatString(e.SeverityVector)),
		); err != nil {
			return fmt.Errorf("write markdown row: %w", err)
		}
	}

	return nil
}

// escapeMarkdown escapes special characters that could break Markdown table
// formatting or be interpreted as Markdown syntax.
func escapeMarkdown(s string) string {
	return markdownReplacer.Replace(s)
}
