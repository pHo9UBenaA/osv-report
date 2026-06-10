package app

import (
	"context"
	"fmt"
	"log/slog"
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
	outputPath := resolveOutputPath(opts.OutputDir, opts.FilePrefix, opts.Format, time.Now().UTC())
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

	switch opts.Format {
	case "markdown":
		err = report.WriteMarkdown(outputPath, reportEntries)
	case "csv":
		err = report.WriteCSV(outputPath, reportEntries)
	case "jsonl":
		err = report.WriteJSONL(outputPath, reportEntries)
	default:
		return fmt.Errorf("unknown report format: %s (supported: markdown, csv, jsonl)", opts.Format)
	}

	if err != nil {
		return fmt.Errorf("write report: %w", err)
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

func resolveOutputPath(dir, prefix, format string, now time.Time) string {
	ext := formatToExtension(format)
	filename := fmt.Sprintf("%s_%s%s", prefix, now.Format("20060102T150405Z"), ext)
	return filepath.Join(dir, filename)
}

func formatToExtension(format string) string {
	switch format {
	case "markdown":
		return ".md"
	case "csv":
		return ".csv"
	case "jsonl":
		return ".jsonl"
	default:
		return ".txt"
	}
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
		}
	}
	return result
}
