package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/pHo9UBenaA/osv-report/internal/config"
	"github.com/pHo9UBenaA/osv-report/internal/model"
	"github.com/pHo9UBenaA/osv-report/internal/osv"
	"github.com/pHo9UBenaA/osv-report/internal/store"
)

// Client defines the interface for fetching vulnerability data.
type Client interface {
	GetVulnerability(ctx context.Context, id string) (*model.Vulnerability, error)
}

// EcosystemLister fetches the canonical list of OSV ecosystems.
type EcosystemLister interface {
	FetchEcosystems(ctx context.Context) ([]string, error)
}

// FetchStore defines the store operations needed by the fetch workflow.
type FetchStore interface {
	GetCursor(ctx context.Context, source string) (time.Time, error)
	SaveCursor(ctx context.Context, source string, cursor time.Time) error
	SaveVulnerabilityWithAffected(ctx context.Context, v store.Vulnerability, affected []store.Affected) error
	SaveTombstone(ctx context.Context, id string) error
	DeleteVulnerabilitiesOlderThan(ctx context.Context, cutoff time.Time) error
}

// Fetch retrieves vulnerability data from OSV API for configured ecosystems.
func Fetch(ctx context.Context, cfg *config.Config, client Client, st FetchStore, lister EcosystemLister) error {
	if len(cfg.Ecosystems) == 0 {
		slog.Warn("no ecosystems configured, set OSV_ECOSYSTEMS environment variable")
		return nil
	}

	allowList, err := lister.FetchEcosystems(ctx)
	if err != nil {
		return fmt.Errorf("fetch canonical ecosystem list: %w", err)
	}

	if err := model.ValidateEcosystems(cfg.Ecosystems, allowList); err != nil {
		return fmt.Errorf("validate ecosystems: %w", err)
	}

	slog.Info("starting vulnerability fetch", "ecosystems", cfg.Ecosystems)

	retentionCutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)

	var errs []error
	for _, eco := range cfg.Ecosystems {
		if err := processEcosystem(ctx, eco, st, client); err != nil {
			slog.Error("failed to process ecosystem", "ecosystem", eco, "error", err)
			errs = append(errs, err)
			continue
		}
	}

	if err := st.DeleteVulnerabilitiesOlderThan(ctx, retentionCutoff); err != nil {
		return fmt.Errorf("delete old vulnerabilities: %w", err)
	}
	slog.Info("deleted old data", "cutoff", retentionCutoff)

	if len(errs) > 0 {
		return fmt.Errorf("some ecosystems failed to process: %w", errors.Join(errs...))
	}

	slog.Info("completed vulnerability fetch")
	return nil
}

func processEcosystem(ctx context.Context, eco model.Ecosystem, st FetchStore, client Client) error {
	source := eco.String()
	slog.Info("processing ecosystem", "ecosystem", source)

	lastCursor, err := st.GetCursor(ctx, source)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			lastCursor = time.Time{}
			slog.Info("no cursor found, starting from beginning", "ecosystem", source)
		} else {
			return fmt.Errorf("get cursor for %s: %w", source, err)
		}
	} else {
		slog.Info("resuming from cursor", "ecosystem", source, "cursor", lastCursor)
	}

	sitemapFetcher := osv.NewSitemapFetcher(eco.SitemapURL(), osv.WithSitemapCursor(lastCursor))
	entries, err := sitemapFetcher.Fetch(ctx)
	if err != nil {
		return fmt.Errorf("fetch sitemap: %w", err)
	}

	slog.Info("fetched entries from sitemap", "ecosystem", source, "count", len(entries))

	if len(entries) == 0 {
		slog.Info("no new entries to process", "ecosystem", source)
		return nil
	}

	var parseFailures atomic.Int64
	for i := 0; i < len(entries); i += config.BatchSize {
		end := i + config.BatchSize
		if end > len(entries) {
			end = len(entries)
		}

		batch := entries[i:end]
		slog.Info("processing batch", "ecosystem", source, "batchStart", i, "batchEnd", end, "total", len(entries))

		if err := processEntriesParallel(ctx, client, st, batch, config.MaxConcurrency, &parseFailures); err != nil {
			return fmt.Errorf("process batch: %w", err)
		}
	}

	if n := parseFailures.Load(); n > 0 {
		slog.Info("severity parse failures", "ecosystem", source, "count", n)
	}

	latestModified := model.MaxModified(entries)
	if err := st.SaveCursor(ctx, source, latestModified); err != nil {
		return fmt.Errorf("save cursor: %w", err)
	}

	slog.Info("completed ecosystem", "ecosystem", source, "processed", len(entries), "cursor", latestModified)
	return nil
}
