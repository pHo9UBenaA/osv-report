package app_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pHo9UBenaA/osv-report/internal/app"
	"github.com/pHo9UBenaA/osv-report/internal/store"
)

type fakeReportStore struct {
	rows               []store.ReportRow
	unreportedRows     []store.ReportRow
	watermarksAdvanced []store.ReportRow
}

func (f *fakeReportStore) GetVulnerabilitiesForReport(_ context.Context, _ string) ([]store.ReportRow, error) {
	return f.rows, nil
}

func (f *fakeReportStore) GetUnreportedVulnerabilities(_ context.Context, _ string) ([]store.ReportRow, error) {
	return f.unreportedRows, nil
}

func (f *fakeReportStore) AdvanceWatermarks(_ context.Context, rows []store.ReportRow) error {
	f.watermarksAdvanced = rows
	return nil
}

func ptrFloat64(v float64) *float64 { return &v }

func TestGenerateReport_FullMode_WritesReportFile(t *testing.T) {
	st := &fakeReportStore{
		rows: []store.ReportRow{
			{
				ID:             "GHSA-test-1",
				Ecosystem:      "npm",
				Package:        "express",
				Published:      "2025-10-01T00:00:00Z",
				Modified:       "2025-10-02T00:00:00Z",
				SeverityScore:  ptrFloat64(9.8),
				SeverityVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			},
		},
	}

	tmpDir := t.TempDir()
	opts := app.ReportOptions{
		Format:     "csv",
		OutputDir:  tmpDir,
		FilePrefix: "report",
		Diff:       false,
	}

	err := app.GenerateReport(context.Background(), st, opts)
	if err != nil {
		t.Fatalf("GenerateReport() error = %v", err)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}

	var csvFile string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".csv" {
			csvFile = e.Name()
			break
		}
	}
	if csvFile == "" {
		t.Fatal("expected .csv file in output directory")
	}

	data, err := os.ReadFile(filepath.Join(tmpDir, csvFile))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "GHSA-test-1") {
		t.Error("output missing vulnerability ID")
	}
	if !strings.Contains(content, "npm") {
		t.Error("output missing ecosystem")
	}
	if !strings.Contains(content, "express") {
		t.Error("output missing package name")
	}
	if !strings.Contains(content, "9.8") {
		t.Error("output missing severity score")
	}
}

func TestGenerateReport_NoRows_ReturnsNilWithoutFile(t *testing.T) {
	st := &fakeReportStore{rows: []store.ReportRow{}}

	tmpDir := t.TempDir()
	opts := app.ReportOptions{
		Format:     "csv",
		OutputDir:  tmpDir,
		FilePrefix: "report",
		Diff:       false,
	}

	err := app.GenerateReport(context.Background(), st, opts)
	if err != nil {
		t.Fatalf("GenerateReport() error = %v, want nil", err)
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no files in output directory, got %d", len(entries))
	}
}

func TestGenerateReport_UnknownFormat_ReturnsError(t *testing.T) {
	st := &fakeReportStore{
		rows: []store.ReportRow{
			{ID: "GHSA-test-1", Ecosystem: "npm", Package: "express"},
		},
	}

	opts := app.ReportOptions{
		Format:     "xml",
		OutputDir:  t.TempDir(),
		FilePrefix: "report",
		Diff:       false,
	}

	err := app.GenerateReport(context.Background(), st, opts)
	if err == nil {
		t.Fatal("GenerateReport() expected error for unknown format")
	}
	if !strings.Contains(err.Error(), "unknown report format") {
		t.Errorf("error = %q, want containing 'unknown report format'", err.Error())
	}
}
