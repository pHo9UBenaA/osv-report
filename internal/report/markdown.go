package report

import (
	"fmt"
	"strings"
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

// markdownReplacer is used to escape special Markdown characters.
var markdownReplacer = strings.NewReplacer(
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

// FormatMarkdown generates a Markdown table from vulnerability entries.
func FormatMarkdown(entries []VulnerabilityEntry) string {
	var sb strings.Builder

	// Write header
	sb.WriteString("| Ecosystem | Package | ID | Published | Modified | Severity: Base Score | Severity: Type | Severity: Vector String |\n")
	sb.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")

	// Write entries
	for _, e := range entries {
		ecosystem := escapeMarkdown(e.Ecosystem)
		pkg := escapeMarkdown(e.Package)
		id := escapeMarkdown(e.ID)
		published := escapeMarkdown(formatString(e.Published))
		modified := escapeMarkdown(formatString(e.Modified))
		severityBase := formatBaseScore(e.SeverityBaseScore)
		severityType := escapeMarkdown(formatString(e.SeverityType))
		severityVector := escapeMarkdown(formatString(e.SeverityVector))

		fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			ecosystem, pkg, id, published, modified, severityBase, severityType, severityVector)
	}

	return sb.String()
}

// escapeMarkdown escapes special characters that could break Markdown table formatting
// or be interpreted as Markdown syntax.
func escapeMarkdown(s string) string {
	return markdownReplacer.Replace(s)
}
