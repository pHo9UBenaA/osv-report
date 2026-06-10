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

// EcosystemLister fetches the canonical list of OSV ecosystems. Used
// for early validation of the configured allowlist; passing nil skips
// validation, which is convenient for tests.
type EcosystemLister interface {
	FetchEcosystems(ctx context.Context) ([]string, error)
}

// FetchStore defines the store operations needed by the fetch workflow.
type FetchStore interface {
	GetCursor(ctx context.Context, source string) (time.Time, error)
	SaveCursor(ctx context.Context, source string, cursor time.Time) error
	SaveVulnerabilityWithAffected(ctx context.Context, v store.Vulnerability, affected []store.Affected) error
	DeleteVulnerability(ctx context.Context, id string) error
	DeleteVulnerabilitiesOlderThan(ctx context.Context, cutoff time.Time) error
}

// Fetch downloads the OSV unified all.zip, projects every record onto
// the configured ecosystem allowlist, and persists the result.
//
// The per-record `withdrawn` field is the authoritative delete signal:
// the Phase 0-S spike confirmed that withdrawn records remain present
// in the zip with a non-empty withdrawn timestamp, so the caller does
// NOT need an ID-set diff to detect deletions — surfacing
// SourceEvent{Withdrawn: true} for each one is sufficient.
func Fetch(ctx context.Context, cfg *config.Config, source osv.Source, st FetchStore, lister EcosystemLister) error {
	if len(cfg.Ecosystems) == 0 {
		slog.Warn("no ecosystems configured, set OSV_ECOSYSTEMS environment variable")
		return nil
	}

	if lister != nil {
		allowList, err := lister.FetchEcosystems(ctx)
		if err != nil {
			return fmt.Errorf("fetch canonical ecosystem list: %w", err)
		}
		if err := model.ValidateEcosystems(cfg.Ecosystems, allowList); err != nil {
			return fmt.Errorf("validate ecosystems: %w", err)
		}
	}

	slog.Info("starting vulnerability fetch", "ecosystems", cfg.Ecosystems)

	configured := makeEcosystemSet(cfg.Ecosystems)
	retentionCutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)

	cursor, err := st.GetCursor(ctx, osv.UnifiedSourceCursorKey)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("get cursor: %w", err)
		}
		cursor = time.Time{}
	}

	events, err := source.Fetch(ctx, cursor)
	if err != nil {
		return fmt.Errorf("source fetch: %w", err)
	}

	var (
		parseFailures atomic.Int64
		maxModified   time.Time
		saved         int
		deleted       int
		skipped       int
	)
	for ev, evErr := range events {
		if evErr != nil {
			slog.Warn("source event error", "err", evErr)
			continue
		}
		if ev.Withdrawn {
			if err := st.DeleteVulnerability(ctx, ev.ID); err != nil {
				return fmt.Errorf("delete withdrawn %s: %w", ev.ID, err)
			}
			deleted++
			continue
		}

		vuln := ev.Vuln
		affected := filterAffected(vuln.Affected, configured, vuln.ID)
		if len(affected) == 0 {
			skipped++
			continue
		}

		baseScore, vector, kind, parseErr := model.ExtractFromOSV(vuln.Severity)
		if parseErr != nil {
			parseFailures.Add(1)
			slog.Warn("parse severity", "id", vuln.ID, "vector", vector, "err", parseErr)
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
			return fmt.Errorf("save %s: %w", vuln.ID, err)
		}
		saved++
		if vuln.Modified.After(maxModified) {
			maxModified = vuln.Modified
		}
	}

	if !maxModified.IsZero() {
		if err := st.SaveCursor(ctx, osv.UnifiedSourceCursorKey, maxModified); err != nil {
			return fmt.Errorf("save cursor: %w", err)
		}
	}

	if err := st.DeleteVulnerabilitiesOlderThan(ctx, retentionCutoff); err != nil {
		return fmt.Errorf("delete old vulnerabilities: %w", err)
	}

	slog.Info("completed vulnerability fetch",
		"saved", saved,
		"deleted_withdrawn", deleted,
		"skipped_other_ecosystems", skipped,
		"severity_parse_failures", parseFailures.Load(),
		"cursor", maxModified,
	)
	return nil
}

// makeEcosystemSet turns the configured Ecosystem slice into a set for
// O(1) lookup during the per-record filter.
func makeEcosystemSet(ecos []model.Ecosystem) map[string]struct{} {
	set := make(map[string]struct{}, len(ecos))
	for _, e := range ecos {
		set[string(e)] = struct{}{}
	}
	return set
}

// filterAffected keeps only those affected entries whose ecosystem is
// in the configured set. Returns nil when no affected entry matches —
// the caller drops the whole record in that case.
func filterAffected(affected []model.AffectedPackage, configured map[string]struct{}, vulnID string) []store.Affected {
	var out []store.Affected
	for _, a := range affected {
		if _, ok := configured[a.Ecosystem]; !ok {
			continue
		}
		out = append(out, store.Affected{
			VulnID:    vulnID,
			Ecosystem: a.Ecosystem,
			Package:   a.Name,
		})
	}
	return out
}
