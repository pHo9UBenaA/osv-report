package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/pHo9UBenaA/osv-report/internal/report"
	"github.com/pHo9UBenaA/osv-report/internal/store"
)

// ReportStore defines the store operations needed by the report workflow.
type ReportStore interface {
	GetVulnerabilitiesForReport(ctx context.Context, ecosystem string) ([]store.ReportRow, error)
	GetUnreportedVulnerabilities(ctx context.Context, ecosystem string) ([]store.ReportRow, error)
	AdvanceWatermarks(ctx context.Context, rows []store.ReportRow) error
}

// ReportOptions holds options for report generation.
type ReportOptions struct {
	Format     string
	OutputDir  string
	FilePrefix string
	Ecosystem  string
	Diff       bool
}

// GenerateReport creates a vulnerability report from the database.
func GenerateReport(ctx context.Context, st ReportStore, opts ReportOptions) error {
	formatter, ok := report.FormatterByName(opts.Format)
	if !ok {
		return fmt.Errorf("unknown report format: %s (supported: markdown, csv, jsonl)", opts.Format)
	}
	// Markdown carries metadata (count, ecosystem filter, diff flag) in
	// its header, so wire those through. Other formatters are stateless.
	if md, ok := formatter.(*report.MarkdownFormatter); ok {
		md.Ecosystem = opts.Ecosystem
		md.Diff = opts.Diff
	}

	outputPath := resolveOutputPath(opts.OutputDir, opts.FilePrefix, formatter.Extension(), time.Now().UTC())
	slog.Info("generating report", "format", opts.Format, "output", outputPath, "ecosystem", opts.Ecosystem, "diff", opts.Diff)

	var rows []store.ReportRow
	var err error

	if opts.Diff {
		rows, err = st.GetUnreportedVulnerabilities(ctx, opts.Ecosystem)
		if err != nil {
			return fmt.Errorf("get unreported vulnerabilities: %w", err)
		}
	} else {
		rows, err = st.GetVulnerabilitiesForReport(ctx, opts.Ecosystem)
		if err != nil {
			return fmt.Errorf("get vulnerabilities: %w", err)
		}
	}

	slog.Info("fetched vulnerabilities", "count", len(rows))

	if len(rows) == 0 {
		slog.Warn("no vulnerabilities found in database")
		return nil
	}

	reportEntries := convertToReportEntries(rows)

	f, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create report file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			slog.Error("close report file", "error", cerr)
		}
	}()

	if err := formatter.Format(f, reportEntries); err != nil {
		return fmt.Errorf("format report: %w", err)
	}

	slog.Info("report generated successfully", "output", outputPath)

	if opts.Diff {
		if err := st.AdvanceWatermarks(ctx, rows); err != nil {
			return fmt.Errorf("advance watermarks: %w", err)
		}
		slog.Info("advanced watermarks", "rows", len(rows))
	}

	return nil
}

// resolveOutputPath composes "<dir>/<prefix>_<UTC timestamp><ext>" so
// every run produces a unique, sortable filename.
func resolveOutputPath(dir, prefix, ext string, now time.Time) string {
	filename := fmt.Sprintf("%s_%s%s", prefix, now.Format("20060102T150405Z"), ext)
	return filepath.Join(dir, filename)
}

func convertToReportEntries(rows []store.ReportRow) []report.VulnerabilityEntry {
	result := make([]report.VulnerabilityEntry, len(rows))
	for i, r := range rows {
		result[i] = report.VulnerabilityEntry{
			ID:                r.ID,
			Ecosystem:         r.Ecosystem,
			Package:           r.Package,
			Published:         r.Published,
			Modified:          r.Modified,
			SeverityBaseScore: r.SeverityScore,
			SeverityVector:    r.SeverityVector,
			SeverityType:      r.SeverityType,
		}
	}
	return result
}
