package report_test

import (
	"testing"

	"github.com/pHo9UBenaA/osv-report/internal/report"
)

func TestFormatterByName_KnownNames_ReturnsMatchingFormatter(t *testing.T) {
	tests := []struct {
		name    string
		wantExt string
	}{
		{"markdown", ".md"},
		{"csv", ".csv"},
		{"jsonl", ".jsonl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, ok := report.FormatterByName(tt.name)
			if !ok {
				t.Fatalf("FormatterByName(%q) ok = false, want true", tt.name)
			}
			if got := f.Extension(); got != tt.wantExt {
				t.Errorf("Extension() = %q, want %q", got, tt.wantExt)
			}
		})
	}
}

func TestFormatterByName_UnknownName_ReturnsFalse(t *testing.T) {
	if _, ok := report.FormatterByName("xml"); ok {
		t.Error("FormatterByName(\"xml\") ok = true, want false")
	}
	if _, ok := report.FormatterByName(""); ok {
		t.Error("FormatterByName(\"\") ok = true, want false")
	}
}
