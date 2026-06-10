package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"

	"github.com/pHo9UBenaA/osv-report/internal/model"
	"github.com/pHo9UBenaA/osv-report/internal/osv"
	"github.com/pHo9UBenaA/osv-report/internal/store"
)

// processEntries fetches vulnerabilities for each entry and stores them.
func processEntries(ctx context.Context, client Client, st FetchStore, entries []model.Entry) error {
	for _, entry := range entries {
		if err := processEntry(ctx, client, st, entry); err != nil {
			return fmt.Errorf("process entry %s: %w", entry.ID, err)
		}
	}
	return nil
}

// processEntriesParallel fetches vulnerabilities in parallel with controlled concurrency.
func processEntriesParallel(ctx context.Context, client Client, st FetchStore, entries []model.Entry, maxConcurrency int) error {
	if maxConcurrency <= 0 {
		return processEntries(ctx, client, st, entries)
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrency)

	for _, entry := range entries {
		g.Go(func() error {
			return processEntry(ctx, client, st, entry)
		})
	}

	return g.Wait()
}

func processEntry(ctx context.Context, client Client, st FetchStore, entry model.Entry) error {
	vuln, err := client.GetVulnerability(ctx, entry.ID)
	if err != nil {
		if errors.Is(err, osv.ErrNotFound) {
			return st.SaveTombstone(ctx, entry.ID)
		}
		return fmt.Errorf("get vulnerability: %w", err)
	}

	baseScore, vector, err := model.ExtractFromOSV(vuln.Severity)
	if err != nil {
		slog.Debug("parse severity", "id", vuln.ID, "vector", vector, "err", err)
	}

	var base sql.NullFloat64
	if baseScore != nil {
		base = sql.NullFloat64{Float64: *baseScore, Valid: true}
	}

	if err := st.SaveVulnerability(ctx, store.Vulnerability{
		ID:                vuln.ID,
		Modified:          vuln.Modified,
		Published:         vuln.Published,
		Summary:           vuln.Summary,
		Details:           vuln.Details,
		SeverityBaseScore: base,
		SeverityVector:    vector,
	}); err != nil {
		return fmt.Errorf("save vulnerability: %w", err)
	}

	for _, affected := range vuln.Affected {
		if err := st.SaveAffected(ctx, store.Affected{
			VulnID:    vuln.ID,
			Ecosystem: affected.Ecosystem,
			Package:   affected.Name,
		}); err != nil {
			return fmt.Errorf("save affected: %w", err)
		}
	}

	return nil
}
