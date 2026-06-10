package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pHo9UBenaA/osv-report/internal/report"
)

func formatJSONL(t *testing.T, entries []report.VulnerabilityEntry) string {
	t.Helper()
	var buf bytes.Buffer
	if err := (&report.JSONLFormatter{}).Format(&buf, entries); err != nil {
		t.Fatalf("JSONLFormatter.Format() error = %v", err)
	}
	return buf.String()
}

func TestJSONLFormatter_Extension_ReturnsDotJSONL(t *testing.T) {
	if got := (&report.JSONLFormatter{}).Extension(); got != ".jsonl" {
		t.Errorf("Extension() = %q, want %q", got, ".jsonl")
	}
}

func TestJSONLFormatter_MixedEntries_ProducesOneLinePerEntry(t *testing.T) {
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

	result := formatJSONL(t, entries)

	lines := strings.Split(strings.TrimSpace(result), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("failed to parse first line: %v", err)
	}
	if first["id"] != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("first.id = %v, want GHSA-xxxx-yyyy-zzzz", first["id"])
	}
	// Native JSON number, not the legacy "9.8" string.
	if got, ok := first["severity_base_score"].(float64); !ok || got != 9.8 {
		t.Errorf("first.severity_base_score = %v (%T), want 9.8 (float64)", first["severity_base_score"], first["severity_base_score"])
	}

	var second map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("failed to parse second line: %v", err)
	}
	// Empty timestamps remain empty strings (no more "NA").
	if second["published"] != "" {
		t.Errorf("second.published = %v, want empty string", second["published"])
	}
	// Missing score is null, not "NA".
	if second["severity_base_score"] != nil {
		t.Errorf("second.severity_base_score = %v, want nil/null", second["severity_base_score"])
	}
	// Verify the literal JSON token is `null`, not a string.
	if !strings.Contains(lines[1], `"severity_base_score":null`) {
		t.Errorf("expected literal JSON null for severity_base_score, got line: %s", lines[1])
	}
}

func TestJSONLFormatter_DangerousCharsAndControlCodes_SafelyJSONEncoded(t *testing.T) {
	entries := []report.VulnerabilityEntry{
		{
			ID:             "=cmd|'/c calc'!A1",
			Ecosystem:      "+EXEC",
			Package:        "-dangerous",
			Published:      "@FORMULA",
			Modified:       "2025-10-02T00:00:00Z",
			SeverityVector: "=1+1",
		},
		{
			ID:             "GHSA-ctrl-char",
			Ecosystem:      "npm",
			Package:        "test\npkg",
			Published:      "value\twith\ttabs",
			Modified:       "",
			SeverityVector: "value\rwith\rcarriage",
		},
	}

	result := formatJSONL(t, entries)
	lines := strings.Split(strings.TrimSpace(result), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}

	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("failed to parse first line: %v", err)
	}
	if first["id"] != "=cmd|'/c calc'!A1" {
		t.Errorf("first.id = %v, want =cmd|'/c calc'!A1", first["id"])
	}

	var second map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("failed to parse second line: %v", err)
	}
	if second["package"] != "test\npkg" {
		t.Errorf("second.package = %v, want test\\npkg", second["package"])
	}

	if !strings.Contains(result, `"package":"test\npkg"`) {
		t.Error("expected newline to be escaped as \\n in JSON output")
	}
}
