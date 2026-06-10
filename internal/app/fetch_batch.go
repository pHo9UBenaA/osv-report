package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"

	"golang.org/x/sync/errgroup"

	"github.com/pHo9UBenaA/osv-report/internal/model"
	"github.com/pHo9UBenaA/osv-report/internal/osv"
	"github.com/pHo9UBenaA/osv-report/internal/store"
)

// processEntries fetches vulnerabilities for each entry and stores them.
func processEntries(ctx context.Context, client Client, st FetchStore, entries []model.Entry, parseFailures *atomic.Int64) error {
	for _, entry := range entries {
		if err := processEntry(ctx, client, st, entry, parseFailures); err != nil {
			return fmt.Errorf("process entry %s: %w", entry.ID, err)
		}
	}
	return nil
}

// processEntriesParallel fetches vulnerabilities in parallel with controlled concurrency.
func processEntriesParallel(ctx context.Context, client Client, st FetchStore, entries []model.Entry, maxConcurrency int, parseFailures *atomic.Int64) error {
	if maxConcurrency <= 0 {
		return processEntries(ctx, client, st, entries, parseFailures)
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(maxConcurrency)

	for _, entry := range entries {
		g.Go(func() error {
			return processEntry(ctx, client, st, entry, parseFailures)
		})
	}

	return g.Wait()
}

func processEntry(ctx context.Context, client Client, st FetchStore, entry model.Entry, parseFailures *atomic.Int64) error {
	vuln, err := client.GetVulnerability(ctx, entry.ID)
	if err != nil {
		if errors.Is(err, osv.ErrNotFound) {
			return st.SaveTombstone(ctx, entry.ID)
		}
		return fmt.Errorf("get vulnerability: %w", err)
	}

	baseScore, vector, kind, err := model.ExtractFromOSV(vuln.Severity)
	if err != nil {
		if parseFailures != nil {
			parseFailures.Add(1)
		}
		slog.Warn("parse severity", "id", vuln.ID, "vector", vector, "err", err)
	}

	affected := make([]store.Affected, len(vuln.Affected))
	for i, a := range vuln.Affected {
		affected[i] = store.Affected{
			VulnID:    vuln.ID,
			Ecosystem: a.Ecosystem,
			Package:   a.Name,
		}
	}

	if err := st.SaveVulnerabilityWithAffected(ctx, store.Vulnerability{
		ID:                vuln.ID,
		Modified:          vuln.Modified,
		Published:         vuln.Published,
		Summary:           vuln.Summary,
		Details:           vuln.Details,
		SeverityBaseScore: baseScore,
		SeverityVector:    vector,
		SeverityType:      kind,
	}, affected); err != nil {
		return fmt.Errorf("save vulnerability: %w", err)
	}

	return nil
}
