package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
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

// FetchStore is the persistence surface the fetch workflow needs.
type FetchStore interface {
	GetSourceState(ctx context.Context, source string) (store.SourceState, error)
	SaveSourceState(ctx context.Context, source string, st store.SourceState) error
	SaveVulnerabilityWithAffected(ctx context.Context, v store.Vulnerability, affected []store.Affected) error
	DeleteVulnerability(ctx context.Context, id string) error
	DeleteVulnerabilitiesOlderThan(ctx context.Context, cutoff time.Time) error
}

// Fetch downloads the OSV unified all.zip, projects every record onto
// the configured ecosystem allowlist, and persists the result.
//
// State commit discipline (rev5):
//   - cursor + ETag + ecosystem fingerprint are written in one
//     SaveSourceState call only when the iterator completes without
//     decode failures (the rev4 bugs #1/#2/#4 are blocked structurally).
//   - retention DELETE is invoked on every return path after the state
//     has been read, via defer + named return + errors.Join — the
//     freshness contract from D4b applies even when Source.Fetch
//     errors out or a per-event error aborts the run.
//   - A change to cfg.Ecosystems is detected against the persisted
//     fingerprint and triggers a full refetch (cursor + ETag cleared)
//     so newly-subscribed ecosystems pick up historical records.
func Fetch(ctx context.Context, cfg *config.Config, source osv.Source, st FetchStore, lister EcosystemLister) (err error) {
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
	configuredKey := canonicalEcosystemKey(cfg.Ecosystems)
	retentionCutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)

	state, err := st.GetSourceState(ctx, osv.UnifiedSourceCursorKey)
	if err != nil {
		// Strict parse: corrupt rows are not laundered into "fresh start".
		return fmt.Errorf("get source state: %w", err)
	}

	if state.Ecosystems != configuredKey {
		slog.Info("ecosystems config changed; forcing full refetch",
			"previous", state.Ecosystems, "current", configuredKey)
		state.Cursor = time.Time{}
		state.ETag = ""
	}

	// Defer retention so it runs on every exit path after state has been
	// loaded. ctx-done short-circuits the DB call so a cancelled run
	// doesn't fight a closing connection. Errors flow through errors.Join
	// into the named return.
	defer func() {
		if ctx.Err() != nil {
			return
		}
		if rerr := st.DeleteVulnerabilitiesOlderThan(context.WithoutCancel(ctx), retentionCutoff); rerr != nil {
			err = errors.Join(err, fmt.Errorf("delete old: %w", rerr))
		}
	}()

	result, err := source.Fetch(ctx, state.Cursor, state.ETag)
	if err != nil {
		return fmt.Errorf("source fetch: %w", err)
	}

	if result.NotModified {
		slog.Info("fetch complete: source not modified")
		return nil
	}

	var (
		decodeFailures int
		parseFailures  int
		maxModified    time.Time
		saved          int
		deleted        int
		skipped        int
		skippedStale   int
	)

	for ev, evErr := range result.Events {
		if evErr != nil {
			// ctx errors get a dedicated return so the cron log shows
			// "cancelled" instead of "N decode failures".
			if errors.Is(evErr, context.Canceled) || errors.Is(evErr, context.DeadlineExceeded) {
				return evErr
			}
			decodeFailures++
			slog.Warn("source event decode failed", "err", evErr)
			continue
		}

		// Full-refetch stale-skip: with cursor=zero (new install, post-v9,
		// ecosystem change) the zip carries years of records most of which
		// retention deletes seconds later. Skipping them here saves the
		// roundtrip while keeping the cursor advancing so the next run
		// goes incremental.
		if ev.Modified.Before(retentionCutoff) {
			skippedStale++
			if ev.Modified.After(maxModified) {
				maxModified = ev.Modified
			}
			continue
		}

		if ev.Withdrawn {
			if err := st.DeleteVulnerability(ctx, ev.ID); err != nil {
				return fmt.Errorf("delete withdrawn %s: %w", ev.ID, err)
			}
			deleted++
			if ev.Modified.After(maxModified) {
				maxModified = ev.Modified
			}
			continue
		}

		vuln := ev.Vuln
		affected := filterAffected(vuln.Affected, configured, vuln.ID)
		if len(affected) == 0 {
			skipped++
			if ev.Modified.After(maxModified) {
				maxModified = ev.Modified
			}
			continue
		}

		baseScore, vector, kind, parseErr := model.ExtractFromOSV(vuln.Severity)
		if parseErr != nil {
			parseFailures++
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
		if ev.Modified.After(maxModified) {
			maxModified = ev.Modified
		}
	}

	if decodeFailures > 0 {
		return fmt.Errorf("%d source events failed to decode; state not advanced", decodeFailures)
	}

	nextCursor := state.Cursor
	if !maxModified.IsZero() {
		nextCursor = maxModified
	}
	if err := st.SaveSourceState(ctx, osv.UnifiedSourceCursorKey, store.SourceState{
		Cursor:     nextCursor,
		ETag:       result.ETag,
		Ecosystems: configuredKey,
	}); err != nil {
		return fmt.Errorf("save source state: %w", err)
	}

	if !maxModified.IsZero() {
		slog.Info("fetch complete",
			"saved", saved,
			"deleted_withdrawn", deleted,
			"skipped_other_ecosystems", skipped,
			"skipped_stale", skippedStale,
			"severity_parse_failures", parseFailures,
			"cursor", maxModified,
		)
	} else {
		slog.Info("fetch complete: no new records",
			"saved", 0,
			"skipped_stale", skippedStale,
		)
	}
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

// canonicalEcosystemKey normalises the configured ecosystems into a
// stable fingerprint stored in SourceState.Ecosystems. Sort+join means
// reordering the env var doesn't trigger a phantom full refetch.
// Newline is the join character because ecosystem names don't contain
// it and it stays readable in DB inspection.
func canonicalEcosystemKey(ecos []model.Ecosystem) string {
	names := make([]string, len(ecos))
	for i, e := range ecos {
		names[i] = string(e)
	}
	sort.Strings(names)
	return strings.Join(names, "\n")
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
