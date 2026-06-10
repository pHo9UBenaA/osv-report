package report_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-report/internal/report"
)

func formatMarkdown(t *testing.T, f *report.MarkdownFormatter, entries []report.VulnerabilityEntry) string {
	t.Helper()
	var buf bytes.Buffer
	if err := f.Format(&buf, entries); err != nil {
		t.Fatalf("MarkdownFormatter.Format() error = %v", err)
	}
	return buf.String()
}

func TestMarkdownFormatter_NewlineInCell_RendersAsBR(t *testing.T) {
	// Newlines inside a Markdown table cell break the row layout — the
	// formatter must escape them to <br>. The Replacer is ordered so
	// CRLF maps to a single <br>, not two.
	entries := []report.VulnerabilityEntry{
		{ID: "id\nwith\nLF", Ecosystem: "eco\r\nwith\r\nCRLF", Package: "pkg\rwith\rCR"},
	}
	out := formatMarkdown(t, &report.MarkdownFormatter{}, entries)

	if strings.Contains(out, "id\nwith") || strings.Contains(out, "with\rCR") {
		t.Errorf("raw newlines leaked into output:\n%s", out)
	}
	if !strings.Contains(out, "id<br>with<br>LF") {
		t.Errorf("LF not replaced with <br>: %s", out)
	}
	if !strings.Contains(out, "eco<br>with<br>CRLF") {
		// CRLF should fold to one <br>, not two.
		t.Errorf("CRLF should fold to single <br>: %s", out)
	}
	if !strings.Contains(out, "pkg<br>with<br>CR") {
		t.Errorf("CR not replaced with <br>: %s", out)
	}
}

func TestMarkdownFormatter_MixedEntries_ProducesTableWithNADefaults(t *testing.T) {
	entries := []report.VulnerabilityEntry{
		{
			ID:        "GHSA-xxxx-yyyy-zzzz",
			Ecosystem: "npm",
			Package:   "express",
			Published: "2025-10-01T00:00:00Z",
			Modified:  "2025-10-02T00:00:00Z",
			SeverityBaseScore: func() *float64 {
				val := 9.8
				return &val
			}(),
			SeverityType:   "CVSS_V3.1",
			SeverityVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		},
		{
			ID:        "GHSA-aaaa-bbbb-cccc",
			Ecosystem: "PyPI",
			Package:   "requests",
			Published: "",
			Modified:  "",
		},
	}

	f := &report.MarkdownFormatter{Now: func() time.Time { return time.Date(2026, 6, 10, 18, 32, 0, 0, time.UTC) }}
	result := formatMarkdown(t, f, entries)

	if !strings.Contains(result, "# Vulnerability Report") {
		t.Errorf("missing report header in result")
	}
	if !strings.Contains(result, "- Generated: 2026-06-10T18:32:00Z") {
		t.Errorf("missing or wrong Generated timestamp in result")
	}
	if !strings.Contains(result, "- Count: 2") {
		t.Errorf("missing or wrong Count in result")
	}
	if !strings.Contains(result, "- Ecosystem filter: all") {
		t.Errorf("missing Ecosystem filter line (should default to 'all')")
	}
	if !strings.Contains(result, "- Diff: false") {
		t.Errorf("missing Diff line")
	}

	if !strings.Contains(result, "| Ecosystem | Package | ID | Published | Modified | Severity: Base Score | Severity: Type | Severity: Vector String |") {
		t.Errorf("missing header in result")
	}

	if !strings.Contains(result, "| --- | --- | --- | --- | --- | --- | --- | --- |") {
		t.Errorf("missing separator in result")
	}

	if !strings.Contains(result, "| npm | express | GHSA-xxxx-yyyy-zzzz | 2025-10-01T00:00:00Z | 2025-10-02T00:00:00Z | 9.8 | CVSS\\_V3.1 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |") {
		t.Errorf("missing first entry in result: %s", result)
	}

	if !strings.Contains(result, "| PyPI | requests | GHSA-aaaa-bbbb-cccc | NA | NA | NA | NA | NA |") {
		t.Errorf("missing second entry with NA values in result")
	}
}

func TestMarkdownFormatter_Header_RecordsEcosystemAndDiff(t *testing.T) {
	f := &report.MarkdownFormatter{
		Ecosystem: "npm",
		Diff:      true,
		Now:       func() time.Time { return time.Date(2026, 6, 10, 18, 32, 0, 0, time.UTC) },
	}
	result := formatMarkdown(t, f, []report.VulnerabilityEntry{{ID: "x", Ecosystem: "npm", Package: "p"}})

	if !strings.Contains(result, "- Ecosystem filter: npm") {
		t.Errorf("expected ecosystem filter 'npm' in header, got: %s", result)
	}
	if !strings.Contains(result, "- Diff: true") {
		t.Errorf("expected Diff: true in header, got: %s", result)
	}
	if !strings.Contains(result, "- Count: 1") {
		t.Errorf("expected Count: 1 in header, got: %s", result)
	}
}

func TestMarkdownFormatter_Extension_ReturnsDotMd(t *testing.T) {
	f := &report.MarkdownFormatter{}
	if got := f.Extension(); got != ".md" {
		t.Errorf("Extension() = %q, want %q", got, ".md")
	}
}

func TestMarkdownFormatter_SpecialChars_EscapesPipeAndHTML(t *testing.T) {
	entries := []report.VulnerabilityEntry{
		{
			ID:             "GHSA-test-0001",
			Ecosystem:      "npm",
			Package:        "pkg-with-|pipe|chars",
			Published:      "2025-10-01",
			Modified:       "2025-10-02",
			SeverityVector: "HIGH|CRITICAL",
			SeverityBaseScore: func() *float64 {
				val := 7.2
				return &val
			}(),
		},
		{
			ID:             "<script>alert('xss')</script>",
			Ecosystem:      "PyPI",
			Package:        "[dangerous](http://evil.com)",
			Published:      "2025-10-03",
			Modified:       "2025-10-04",
			SeverityVector: "*emphasis*",
		},
	}

	result := formatMarkdown(t, &report.MarkdownFormatter{}, entries)

	if strings.Contains(result, "pkg-with-|pipe|chars") {
		t.Errorf("pipe characters in package name should be escaped, got: %s", result)
	}
	if !strings.Contains(result, "pkg-with-\\|pipe\\|chars") {
		t.Errorf("expected escaped pipe characters in package name")
	}

	if strings.Contains(result, "<script>") {
		t.Errorf("HTML tags should be escaped, got: %s", result)
	}

	if strings.Contains(result, "[dangerous](http://evil.com)") {
		t.Errorf("markdown links should be escaped, got: %s", result)
	}

	if strings.Contains(result, "*emphasis*") && !strings.Contains(result, "\\*emphasis\\*") {
		t.Errorf("markdown emphasis characters should be escaped, got: %s", result)
	}
}

func TestMarkdownFormatter_NewlineHandling_CRLFCollapsesToSingleBr(t *testing.T) {
	// CRLF must produce one <br>, not two. If "\n" → "<br>" ran first,
	// "\r\n" would emit "<br>\r" then "<br>", giving "<br><br>" (or
	// worse, leaving a stray \r). Tests the replacer ordering.
	entries := []report.VulnerabilityEntry{
		{
			ID:        "crlf",
			Ecosystem: "npm",
			Package:   "line1\r\nline2",
			Published: "lone\rcr",
			Modified:  "lone\nlf",
		},
	}

	result := formatMarkdown(t, &report.MarkdownFormatter{}, entries)

	if strings.Contains(result, "<br><br>") {
		t.Errorf("CRLF should collapse to a single <br>, got double <br><br> in: %s", result)
	}
	if strings.Contains(result, "\r") || strings.Contains(result, "\n| ") {
		// Note: real row terminators still use \n; we only object to
		// raw \r anywhere, and to \n appearing *inside* a cell (which
		// would manifest as "\n| " mid-row).
		if strings.Contains(result, "\r") {
			t.Errorf("raw \\r should be replaced, got: %q", result)
		}
	}
	if !strings.Contains(result, "line1<br>line2") {
		t.Errorf("expected 'line1<br>line2' in result, got: %s", result)
	}
	if !strings.Contains(result, "lone<br>cr") {
		t.Errorf("expected lone CR replaced with <br>, got: %s", result)
	}
	if !strings.Contains(result, "lone<br>lf") {
		t.Errorf("expected lone LF replaced with <br>, got: %s", result)
	}
}
