package osv

import (
	"context"
	"iter"
	"time"

	"github.com/pHo9UBenaA/osv-report/internal/model"
)

// SourceEvent is one entry emitted by a Source.Fetch stream. Exactly one
// of Vuln or Withdrawn is meaningful per event:
//
//   - For an active record, Vuln points to the parsed vulnerability and
//     Withdrawn is false.
//   - For a record that the upstream has withdrawn, Vuln is nil (the
//     details are no longer authoritative) and Withdrawn is true; the
//     caller treats this as a delete signal for the corresponding ID.
//
// ID is always set so the caller never has to dereference Vuln just to
// route a withdrawal. Modified is the record's upstream modified time:
// the app layer feeds it into the cursor watermark for every processed
// event (save / delete / skip) so that the cursor advances even when
// the only event in the window is a withdrawal or an ecosystem-skip.
type SourceEvent struct {
	ID        string
	Modified  time.Time
	Vuln      *model.Vulnerability
	Withdrawn bool
}

// FetchResult is what a Source returns from one Fetch call.
//
// Callers MUST only consume ETag when NotModified is false. On a 304
// response ETag is always empty and the caller should keep its
// previously persisted ETag (the contract is checked by
// TestUnifiedAllZipSource_304_SetsNotModified). Surfacing 304 with an
// explicit flag avoids relying on an empty-iterator side channel.
type FetchResult struct {
	Events      iter.Seq2[SourceEvent, error]
	ETag        string
	NotModified bool
}

// Source is the abstract OSV data feed.
//
// cursor is the last per-record timestamp the caller has fully processed.
// Implementations may filter the stream so only records with
// modified > cursor are emitted; older records are not promised to be
// absent (a re-fetch after a withdrawn record can resurface).
//
// prevETag is the ETag the caller persisted from the previous Fetch.
// When non-empty, implementations SHOULD send it as If-None-Match so an
// unchanged upstream answers 304. When empty the implementation MUST
// send an unconditional GET (sending an empty If-None-Match makes the
// server always answer 200, which defeats the optimisation).
//
// Persistence is not the Source's job: the caller alone reads and
// writes source_cursor, so a fatal Fetch error never leaks half-written
// state.
type Source interface {
	Fetch(ctx context.Context, cursor time.Time, prevETag string) (*FetchResult, error)
}
