package app_test

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-report/internal/app"
	"github.com/pHo9UBenaA/osv-report/internal/config"
	"github.com/pHo9UBenaA/osv-report/internal/model"
	"github.com/pHo9UBenaA/osv-report/internal/osv"
	"github.com/pHo9UBenaA/osv-report/internal/store"
)

// fakeSource records every Fetch call and returns a scripted result.
// Tests set scriptedEvents and scriptedFetchErr before invoking
// app.Fetch; using a function for events lets a test surface the
// iterator output exactly as a real Source would.
type fakeSource struct {
	calls            []fakeSourceCall
	scriptedResult   *osv.FetchResult
	scriptedFetchErr error
}

type fakeSourceCall struct {
	Cursor   time.Time
	PrevETag string
}

func (f *fakeSource) Fetch(_ context.Context, cursor time.Time, prevETag string) (*osv.FetchResult, error) {
	f.calls = append(f.calls, fakeSourceCall{Cursor: cursor, PrevETag: prevETag})
	if f.scriptedFetchErr != nil {
		return nil, f.scriptedFetchErr
	}
	return f.scriptedResult, nil
}

// eventsFromSlice turns a slice of (event, error) pairs into the
// iter.Seq2 shape Source.Fetch returns.
func eventsFromSlice(items []eventOrErr) iter.Seq2[osv.SourceEvent, error] {
	return func(yield func(osv.SourceEvent, error) bool) {
		for _, it := range items {
			if !yield(it.Event, it.Err) {
				return
			}
		}
	}
}

type eventOrErr struct {
	Event osv.SourceEvent
	Err   error
}

// fakeFetchStore records every interaction so the test can assert on
// what app.Fetch did instead of what it logged.
type fakeFetchStore struct {
	state    store.SourceState
	stateErr error

	saveStateErr   error
	savedStates    []store.SourceState
	saveStateCalls int

	saveVulnErr error
	savedVulns  []savedVuln

	deleteErr  error
	deletedIDs []string

	retentionErr   error
	retentionCalls int
}

type savedVuln struct {
	V        store.Vulnerability
	Affected []store.Affected
}

func (f *fakeFetchStore) GetSourceState(_ context.Context, _ string) (store.SourceState, error) {
	if f.stateErr != nil {
		return store.SourceState{}, f.stateErr
	}
	return f.state, nil
}

func (f *fakeFetchStore) SaveSourceState(_ context.Context, _ string, st store.SourceState) error {
	f.saveStateCalls++
	if f.saveStateErr != nil {
		return f.saveStateErr
	}
	f.savedStates = append(f.savedStates, st)
	return nil
}

func (f *fakeFetchStore) SaveVulnerabilityWithAffected(_ context.Context, v store.Vulnerability, a []store.Affected) error {
	if f.saveVulnErr != nil {
		return f.saveVulnErr
	}
	f.savedVulns = append(f.savedVulns, savedVuln{V: v, Affected: a})
	return nil
}

func (f *fakeFetchStore) DeleteVulnerability(_ context.Context, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deletedIDs = append(f.deletedIDs, id)
	return nil
}

func (f *fakeFetchStore) DeleteVulnerabilitiesOlderThan(_ context.Context, _ time.Time) error {
	f.retentionCalls++
	return f.retentionErr
}

// withinRetention builds a Modified far in the future so the stale-skip
// branch never claims the event.
func withinRetention() time.Time {
	return time.Now().Add(24 * time.Hour)
}

func newEvent(id, ecosystem, pkg string, modified time.Time) osv.SourceEvent {
	return osv.SourceEvent{
		ID:       id,
		Modified: modified,
		Vuln: &model.Vulnerability{
			ID:       id,
			Modified: modified,
			Affected: []model.AffectedPackage{{Ecosystem: ecosystem, Name: pkg}},
		},
	}
}

func newWithdrawn(id string, modified time.Time) osv.SourceEvent {
	return osv.SourceEvent{ID: id, Modified: modified, Withdrawn: true}
}

func newCfg(eco ...string) *config.Config {
	c := &config.Config{RetentionDays: 7}
	for _, e := range eco {
		c.Ecosystems = append(c.Ecosystems, model.Ecosystem(e))
	}
	return c
}

// canonicalKey replicates app.canonicalEcosystemKey for assertions.
// Kept inline so the test does not import a private helper.
func canonicalKey(eco ...string) string {
	cp := append([]string(nil), eco...)
	sort.Strings(cp)
	return strings.Join(cp, "\n")
}

func TestFetch_GetSourceStateError_ReturnsErrorWithoutCallingSource(t *testing.T) {
	st := &fakeFetchStore{stateErr: errors.New("boom")}
	src := &fakeSource{}

	err := app.Fetch(context.Background(), newCfg("npm"), src, st, nil)
	if err == nil {
		t.Fatal("expected error from GetSourceState")
	}
	if len(src.calls) != 0 {
		t.Errorf("Source.Fetch must not be called when GetSourceState fails, got %d calls", len(src.calls))
	}
	if st.retentionCalls != 0 {
		t.Errorf("retention must not run before defer is registered, got %d", st.retentionCalls)
	}
	if st.saveStateCalls != 0 {
		t.Errorf("SaveSourceState must not be called, got %d", st.saveStateCalls)
	}
}

func TestFetch_SourceError_ReturnsErrorWithoutStateChange(t *testing.T) {
	st := &fakeFetchStore{state: store.SourceState{Ecosystems: canonicalKey("npm")}}
	src := &fakeSource{scriptedFetchErr: errors.New("network down")}

	err := app.Fetch(context.Background(), newCfg("npm"), src, st, nil)
	if err == nil {
		t.Fatal("expected error from Source.Fetch")
	}
	if st.saveStateCalls != 0 {
		t.Errorf("state must not be saved when Source.Fetch errors, got %d saves", st.saveStateCalls)
	}
	if st.retentionCalls != 1 {
		t.Errorf("retention must still run on Source error, got %d", st.retentionCalls)
	}
}

func TestFetch_PerEntryError_ReturnsErrorAndHoldsState(t *testing.T) {
	st := &fakeFetchStore{state: store.SourceState{Ecosystems: canonicalKey("npm")}}
	src := &fakeSource{
		scriptedResult: &osv.FetchResult{
			ETag: `"new"`,
			Events: eventsFromSlice([]eventOrErr{
				{Event: newEvent("OK", "npm", "p", withinRetention())},
				{Err: errors.New("bad json")},
			}),
		},
	}

	err := app.Fetch(context.Background(), newCfg("npm"), src, st, nil)
	if err == nil {
		t.Fatal("expected aggregated decode-failure error")
	}
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("error should mention decode failures, got %v", err)
	}
	if len(st.savedVulns) != 1 || st.savedVulns[0].V.ID != "OK" {
		t.Errorf("successful event should still be persisted, got %+v", st.savedVulns)
	}
	if st.saveStateCalls != 0 {
		t.Errorf("state must be held when decode failures > 0, got %d saves", st.saveStateCalls)
	}
	if st.retentionCalls != 1 {
		t.Errorf("retention must run even on decode-failure exit, got %d", st.retentionCalls)
	}
}

func TestFetch_StoreWriteError_ReturnsErrorAndHoldsState(t *testing.T) {
	cases := []struct {
		name string
		set  func(*fakeFetchStore)
		ev   osv.SourceEvent
	}{
		{
			name: "SaveVulnerabilityWithAffected",
			set:  func(f *fakeFetchStore) { f.saveVulnErr = errors.New("disk full") },
			ev:   newEvent("V", "npm", "p", withinRetention()),
		},
		{
			name: "DeleteVulnerability",
			set:  func(f *fakeFetchStore) { f.deleteErr = errors.New("locked") },
			ev:   newWithdrawn("W", withinRetention()),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &fakeFetchStore{state: store.SourceState{Ecosystems: canonicalKey("npm")}}
			tc.set(st)
			src := &fakeSource{scriptedResult: &osv.FetchResult{ETag: `"new"`, Events: eventsFromSlice([]eventOrErr{{Event: tc.ev}})}}

			err := app.Fetch(context.Background(), newCfg("npm"), src, st, nil)
			if err == nil {
				t.Fatal("expected store-write error to propagate")
			}
			if st.saveStateCalls != 0 {
				t.Errorf("state must be held on store-write fatal, got %d saves", st.saveStateCalls)
			}
			if st.retentionCalls != 1 {
				t.Errorf("retention must run on store-write fatal, got %d", st.retentionCalls)
			}
		})
	}
}

func TestFetch_RetentionRunsOnAllPathsExceptGetStateFailure(t *testing.T) {
	cfg := newCfg("npm")
	good := newEvent("OK", "npm", "p", withinRetention())

	cases := []struct {
		name           string
		store          *fakeFetchStore
		source         *fakeSource
		wantErr        bool
		wantRetention  int
		wantSaveStates int
	}{
		{
			name:          "304",
			store:         &fakeFetchStore{state: store.SourceState{ETag: `"old"`, Ecosystems: canonicalKey("npm")}},
			source:        &fakeSource{scriptedResult: &osv.FetchResult{NotModified: true}},
			wantRetention: 1,
		},
		{
			name:           "SuccessRun",
			store:          &fakeFetchStore{state: store.SourceState{Ecosystems: canonicalKey("npm")}},
			source:         &fakeSource{scriptedResult: &osv.FetchResult{ETag: `"new"`, Events: eventsFromSlice([]eventOrErr{{Event: good}})}},
			wantRetention:  1,
			wantSaveStates: 1,
		},
		{
			name:    "DecodeFailures",
			store:   &fakeFetchStore{state: store.SourceState{Ecosystems: canonicalKey("npm")}},
			source: &fakeSource{scriptedResult: &osv.FetchResult{ETag: `"new"`, Events: eventsFromSlice([]eventOrErr{
				{Err: errors.New("bad")},
			})}},
			wantErr:       true,
			wantRetention: 1,
		},
		{
			name:          "SourceError",
			store:         &fakeFetchStore{state: store.SourceState{Ecosystems: canonicalKey("npm")}},
			source:        &fakeSource{scriptedFetchErr: errors.New("net")},
			wantErr:       true,
			wantRetention: 1,
		},
		{
			name:    "SaveStateError",
			store:   &fakeFetchStore{state: store.SourceState{Ecosystems: canonicalKey("npm")}, saveStateErr: errors.New("disk")},
			source:  &fakeSource{scriptedResult: &osv.FetchResult{ETag: `"new"`, Events: eventsFromSlice([]eventOrErr{{Event: good}})}},
			wantErr: true,
			// SaveStateError still triggers SaveSourceState once.
			wantSaveStates: 1,
			wantRetention:  1,
		},
		{
			name:           "StoreWriteError",
			store:          &fakeFetchStore{state: store.SourceState{Ecosystems: canonicalKey("npm")}, saveVulnErr: errors.New("disk")},
			source:         &fakeSource{scriptedResult: &osv.FetchResult{ETag: `"new"`, Events: eventsFromSlice([]eventOrErr{{Event: good}})}},
			wantErr:        true,
			wantRetention:  1,
			wantSaveStates: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := app.Fetch(context.Background(), cfg, tc.source, tc.store, nil)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.store.retentionCalls != tc.wantRetention {
				t.Errorf("retention calls = %d, want %d", tc.store.retentionCalls, tc.wantRetention)
			}
			if tc.store.saveStateCalls != tc.wantSaveStates {
				t.Errorf("SaveSourceState calls = %d, want %d", tc.store.saveStateCalls, tc.wantSaveStates)
			}
		})
	}

	t.Run("GetStateError", func(t *testing.T) {
		st := &fakeFetchStore{stateErr: errors.New("parse")}
		src := &fakeSource{}
		if err := app.Fetch(context.Background(), cfg, src, st, nil); err == nil {
			t.Fatal("expected error from GetSourceState")
		}
		if st.retentionCalls != 0 {
			t.Errorf("retention must not run when GetSourceState fails: defer registers after, got %d", st.retentionCalls)
		}
	})

	t.Run("RetentionErrorJoined", func(t *testing.T) {
		st := &fakeFetchStore{
			state:        store.SourceState{Ecosystems: canonicalKey("npm")},
			retentionErr: errors.New("retention boom"),
		}
		src := &fakeSource{scriptedResult: &osv.FetchResult{ETag: `"e"`, Events: eventsFromSlice([]eventOrErr{{Event: good}})}}
		err := app.Fetch(context.Background(), cfg, src, st, nil)
		if err == nil || !strings.Contains(err.Error(), "retention boom") {
			t.Errorf("retention error should reach caller, got %v", err)
		}
	})
}

func TestFetch_SuccessRun_CommitsCursorAndETagAtomically(t *testing.T) {
	cursor := withinRetention()
	st := &fakeFetchStore{state: store.SourceState{Ecosystems: canonicalKey("npm")}}
	src := &fakeSource{scriptedResult: &osv.FetchResult{
		ETag: `"final"`,
		Events: eventsFromSlice([]eventOrErr{
			{Event: newEvent("V-1", "npm", "p", cursor.Add(-time.Hour))},
			{Event: newEvent("V-2", "npm", "q", cursor)},
		}),
	}}

	if err := app.Fetch(context.Background(), newCfg("npm"), src, st, nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if st.saveStateCalls != 1 {
		t.Fatalf("expected single SaveSourceState, got %d", st.saveStateCalls)
	}
	got := st.savedStates[0]
	if got.ETag != `"final"` {
		t.Errorf("ETag saved = %q, want \"final\"", got.ETag)
	}
	if !got.Cursor.Equal(cursor) {
		t.Errorf("cursor saved = %v, want %v", got.Cursor, cursor)
	}
	if got.Ecosystems != canonicalKey("npm") {
		t.Errorf("ecosystems key = %q, want %q", got.Ecosystems, canonicalKey("npm"))
	}
}

func TestFetch_NotModified_KeepsStateRunsRetention(t *testing.T) {
	saved := store.SourceState{
		Cursor:     time.Date(2025, 10, 4, 0, 0, 0, 0, time.UTC),
		ETag:       `"keep"`,
		Ecosystems: canonicalKey("npm"),
	}
	st := &fakeFetchStore{state: saved}
	src := &fakeSource{scriptedResult: &osv.FetchResult{NotModified: true}}

	if err := app.Fetch(context.Background(), newCfg("npm"), src, st, nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if st.saveStateCalls != 0 {
		t.Errorf("304 must not save state, got %d", st.saveStateCalls)
	}
	if st.retentionCalls != 1 {
		t.Errorf("304 must still run retention, got %d", st.retentionCalls)
	}
}

func TestFetch_AllEventsFiltered_AdvancesCursorToSkippedMax(t *testing.T) {
	// Two PyPI events with cfg=[npm]: ecosystem filter drops both as
	// 'skipped'. D2b advances maxModified anyway so the cursor moves to
	// the last skipped record's Modified.
	maxMod := withinRetention()
	st := &fakeFetchStore{state: store.SourceState{Ecosystems: canonicalKey("npm")}}
	src := &fakeSource{scriptedResult: &osv.FetchResult{
		ETag: `"new"`,
		Events: eventsFromSlice([]eventOrErr{
			{Event: newEvent("P1", "PyPI", "a", maxMod.Add(-time.Hour))},
			{Event: newEvent("P2", "PyPI", "b", maxMod)},
		}),
	}}

	if err := app.Fetch(context.Background(), newCfg("npm"), src, st, nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(st.savedVulns) != 0 {
		t.Errorf("no npm event present: nothing should be saved, got %d", len(st.savedVulns))
	}
	if st.saveStateCalls != 1 {
		t.Fatalf("expected one SaveSourceState, got %d", st.saveStateCalls)
	}
	got := st.savedStates[0]
	if !got.Cursor.Equal(maxMod) {
		t.Errorf("cursor should advance to max skipped Modified: got %v, want %v", got.Cursor, maxMod)
	}
	if got.ETag != `"new"` {
		t.Errorf("ETag still updated on full-skip run: got %q", got.ETag)
	}
}

func TestFetch_NoEventsAfterCursorFilter_KeepsCursorAdvancesETag(t *testing.T) {
	saved := store.SourceState{
		Cursor:     time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC),
		ETag:       `"old"`,
		Ecosystems: canonicalKey("npm"),
	}
	st := &fakeFetchStore{state: saved}
	src := &fakeSource{scriptedResult: &osv.FetchResult{ETag: `"new"`, Events: eventsFromSlice(nil)}}

	if err := app.Fetch(context.Background(), newCfg("npm"), src, st, nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if st.saveStateCalls != 1 {
		t.Fatalf("expected one SaveSourceState, got %d", st.saveStateCalls)
	}
	got := st.savedStates[0]
	if !got.Cursor.Equal(saved.Cursor) {
		t.Errorf("cursor should stay put when no events arrived: got %v, want %v", got.Cursor, saved.Cursor)
	}
	if got.ETag != `"new"` {
		t.Errorf("ETag should advance even when events are empty: got %q", got.ETag)
	}
}

func TestFetch_EcosystemsConfigChanged_ForcesFullRefetch(t *testing.T) {
	st := &fakeFetchStore{state: store.SourceState{
		Cursor:     time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
		ETag:       `"old"`,
		Ecosystems: canonicalKey("npm"),
	}}
	src := &fakeSource{scriptedResult: &osv.FetchResult{ETag: `"new"`, Events: eventsFromSlice(nil)}}

	if err := app.Fetch(context.Background(), newCfg("npm", "PyPI"), src, st, nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(src.calls) != 1 {
		t.Fatalf("Source.Fetch should be called once, got %d", len(src.calls))
	}
	if !src.calls[0].Cursor.IsZero() {
		t.Errorf("cursor should be cleared on ecosystem change, got %v", src.calls[0].Cursor)
	}
	if src.calls[0].PrevETag != "" {
		t.Errorf("ETag should be cleared on ecosystem change, got %q", src.calls[0].PrevETag)
	}
}

func TestFetch_EcosystemsConfigUnchanged_UsesCurrentState(t *testing.T) {
	saved := store.SourceState{
		Cursor:     time.Date(2025, 10, 1, 0, 0, 0, 0, time.UTC),
		ETag:       `"old"`,
		Ecosystems: canonicalKey("npm", "PyPI"),
	}
	st := &fakeFetchStore{state: saved}
	src := &fakeSource{scriptedResult: &osv.FetchResult{NotModified: true}}

	if err := app.Fetch(context.Background(), newCfg("PyPI", "npm"), src, st, nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !src.calls[0].Cursor.Equal(saved.Cursor) {
		t.Errorf("cursor must pass through when ecosystems match: got %v", src.calls[0].Cursor)
	}
	if src.calls[0].PrevETag != saved.ETag {
		t.Errorf("ETag must pass through when ecosystems match: got %q", src.calls[0].PrevETag)
	}
}

func TestFetch_RecordsOlderThanRetention_SkippedButAdvanceCursor(t *testing.T) {
	stale := time.Now().Add(-30 * 24 * time.Hour)  // way past 7d default
	fresh := withinRetention()

	st := &fakeFetchStore{state: store.SourceState{Ecosystems: canonicalKey("npm")}}
	src := &fakeSource{scriptedResult: &osv.FetchResult{ETag: `"e"`, Events: eventsFromSlice([]eventOrErr{
		{Event: newEvent("STALE", "npm", "p", stale)},
		{Event: newWithdrawn("STALE-W", stale.Add(time.Hour))},
		{Event: newEvent("FRESH", "npm", "q", fresh)},
	})}}

	if err := app.Fetch(context.Background(), newCfg("npm"), src, st, nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(st.savedVulns) != 1 || st.savedVulns[0].V.ID != "FRESH" {
		t.Errorf("only FRESH should be saved, got %+v", st.savedVulns)
	}
	if len(st.deletedIDs) != 0 {
		t.Errorf("stale withdrawn should be skipped (no DeleteVulnerability), got %+v", st.deletedIDs)
	}
	got := st.savedStates[0]
	if !got.Cursor.Equal(fresh) {
		t.Errorf("cursor must reach fresh event Modified: got %v, want %v", got.Cursor, fresh)
	}
}

func TestFetch_SkippedCursorAdvance_ThenEcosystemAdded_RecoversPastRecords(t *testing.T) {
	t0 := withinRetention()

	// Run 1: cfg=[npm], the only event is a PyPI record that gets skipped.
	// The skipped event still drives the cursor forward to t0.
	st := &fakeFetchStore{}
	src1 := &fakeSource{scriptedResult: &osv.FetchResult{ETag: `"e1"`, Events: eventsFromSlice([]eventOrErr{
		{Event: newEvent("P-old", "PyPI", "p", t0)},
	})}}
	if err := app.Fetch(context.Background(), newCfg("npm"), src1, st, nil); err != nil {
		t.Fatalf("run1: %v", err)
	}
	if len(st.savedStates) != 1 || !st.savedStates[0].Cursor.Equal(t0) {
		t.Fatalf("run1: cursor did not advance via skipped event: %+v", st.savedStates)
	}

	// Carry the saved state forward as the initial state of run 2.
	st.state = st.savedStates[len(st.savedStates)-1]
	src2 := &fakeSource{scriptedResult: &osv.FetchResult{ETag: `"e2"`, Events: eventsFromSlice([]eventOrErr{
		{Event: newEvent("P-old", "PyPI", "p", t0)},
	})}}
	if err := app.Fetch(context.Background(), newCfg("npm", "PyPI"), src2, st, nil); err != nil {
		t.Fatalf("run2: %v", err)
	}
	if !src2.calls[0].Cursor.IsZero() {
		t.Fatalf("run2: ecosystem change must clear cursor, got %v", src2.calls[0].Cursor)
	}
	if len(st.savedVulns) != 1 || st.savedVulns[0].V.ID != "P-old" {
		t.Errorf("run2: past PyPI record should be picked up, got %+v", st.savedVulns)
	}
}

func TestFetch_EcosystemFilter_DropsNonConfigured(t *testing.T) {
	st := &fakeFetchStore{state: store.SourceState{Ecosystems: canonicalKey("npm")}}
	src := &fakeSource{scriptedResult: &osv.FetchResult{ETag: `"e"`, Events: eventsFromSlice([]eventOrErr{
		{Event: newEvent("D-1", "Debian:11", "d", withinRetention())},
		{Event: newEvent("N-1", "npm", "n", withinRetention())},
		{Event: newEvent("D-2", "AlmaLinux:9", "a", withinRetention())},
	})}}
	if err := app.Fetch(context.Background(), newCfg("npm"), src, st, nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(st.savedVulns) != 1 || st.savedVulns[0].V.ID != "N-1" {
		t.Errorf("only npm record should be saved, got %+v", st.savedVulns)
	}
}

func TestFetch_Withdrawn_CallsDelete(t *testing.T) {
	st := &fakeFetchStore{state: store.SourceState{Ecosystems: canonicalKey("npm")}}
	src := &fakeSource{scriptedResult: &osv.FetchResult{ETag: `"e"`, Events: eventsFromSlice([]eventOrErr{
		{Event: newWithdrawn("W-1", withinRetention())},
	})}}
	if err := app.Fetch(context.Background(), newCfg("npm"), src, st, nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(st.deletedIDs) != 1 || st.deletedIDs[0] != "W-1" {
		t.Errorf("withdrawn event should trigger DeleteVulnerability, got %+v", st.deletedIDs)
	}
}

func TestFetch_DeleteOldVulnerabilitiesAlwaysRuns(t *testing.T) {
	st := &fakeFetchStore{state: store.SourceState{ETag: `"x"`, Ecosystems: canonicalKey("npm")}}
	src := &fakeSource{scriptedResult: &osv.FetchResult{NotModified: true}}
	if err := app.Fetch(context.Background(), newCfg("npm"), src, st, nil); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if st.retentionCalls != 1 {
		t.Errorf("304 path must run retention, got %d", st.retentionCalls)
	}
}

func TestFetch_RespectsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	st := &fakeFetchStore{state: store.SourceState{Ecosystems: canonicalKey("npm")}}
	src := &fakeSource{scriptedResult: &osv.FetchResult{ETag: `"e"`, Events: func(yield func(osv.SourceEvent, error) bool) {
		if !yield(newEvent("V-1", "npm", "p", withinRetention()), nil) {
			return
		}
		cancel()
		// Mimic the real Source.Fetch behaviour: surface ctx.Err once it
		// trips so app's errors.Is branch fires.
		yield(osv.SourceEvent{}, ctx.Err())
	}}}

	err := app.Fetch(ctx, newCfg("npm"), src, st, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if st.saveStateCalls != 0 {
		t.Errorf("cancelled run must not save state, got %d", st.saveStateCalls)
	}
	if st.retentionCalls != 0 {
		t.Errorf("cancelled run must not run retention (ctx already done), got %d", st.retentionCalls)
	}
}

// Sanity check the eventsFromSlice helper itself.
func TestEventsFromSlice_DeliversAllItems(t *testing.T) {
	seq := eventsFromSlice([]eventOrErr{{Event: osv.SourceEvent{ID: "A"}}, {Err: fmt.Errorf("e")}})
	var ids []string
	var errs int
	for ev, err := range seq {
		if err != nil {
			errs++
			continue
		}
		ids = append(ids, ev.ID)
	}
	if len(ids) != 1 || ids[0] != "A" || errs != 1 {
		t.Errorf("eventsFromSlice misbehaved: ids=%v errs=%d", ids, errs)
	}
}
