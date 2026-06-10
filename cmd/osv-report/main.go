package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/pHo9UBenaA/osv-report/internal/app"
	"github.com/pHo9UBenaA/osv-report/internal/config"
	"github.com/pHo9UBenaA/osv-report/internal/osv"
	"github.com/pHo9UBenaA/osv-report/internal/store"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		showHelp()
		os.Exit(0)
	}

	cmd := os.Args[1]

	switch cmd {
	case "fetch":
		if err := runFetch(); err != nil {
			slog.Error("command failed", "error", err)
			os.Exit(1)
		}
	case "report":
		if err := runReport(); err != nil {
			slog.Error("command failed", "error", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		showHelp()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		showHelp()
		os.Exit(1)
	}
}

func runFetch() error {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	st, err := store.NewStore(ctx, cfg.DBPath)
	if err != nil {
		return fmt.Errorf("new store: %w", err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			slog.Error("close store", "error", err)
		}
	}()

	client := osv.NewClientWithOptions(config.APIBaseURL, config.RateLimit, config.HTTPTimeout)
	lister := osv.NewEcosystemsFetcher(config.EcosystemsListURL, nil)
	return app.Fetch(ctx, cfg, client, st, lister)
}

func runReport() error {
	reportCmd := flag.NewFlagSet("report", flag.ExitOnError)
	format := reportCmd.String("format", "markdown", "Report format: markdown, csv, jsonl")
	outputDir := reportCmd.String("output-dir", ".", "Report output directory")
	filePrefix := reportCmd.String("file-prefix", "report", "Report filename prefix (timestamp and extension appended automatically)")
	ecosystem := reportCmd.String("ecosystem", "", "Filter report by ecosystem (empty = all)")
	diff := reportCmd.Bool("diff", false, "Generate differential report (only new/changed vulnerabilities)")

	// reportCmd uses flag.ExitOnError, so Parse never returns an error;
	// it exits the process on parse failure.
	reportCmd.Parse(os.Args[2:]) //nolint:errcheck

	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	st, err := store.NewStore(ctx, cfg.DBPath)
	if err != nil {
		return fmt.Errorf("new store: %w", err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			slog.Error("close store", "error", err)
		}
	}()

	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	return app.GenerateReport(ctx, st, app.ReportOptions{
		Format:     *format,
		OutputDir:  *outputDir,
		FilePrefix: *filePrefix,
		Ecosystem:  *ecosystem,
		Diff:       *diff,
	})
}
