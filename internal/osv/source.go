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
// route a withdrawal.
type SourceEvent struct {
	ID        string
	Vuln      *model.Vulnerability
	Withdrawn bool
}

// Source is the abstract OSV data feed. A concrete implementation
// decides how to discover and stream events; the app/fetch pipeline
// does not depend on which one is in use beyond this interface.
//
// cursor is the last per-record timestamp the caller has fully
// processed. Source implementations may filter the stream so only
// records with modified > cursor are emitted, but they MUST NOT
// promise that older records are absent (a re-fetch after a withdrawn
// record can resurface). The 0-S investigation memo found that the
// unified all.zip retains withdrawn records, so callers do not need
// an ID-set diff to detect deletions — withdrawn events are in-band.
type Source interface {
	Fetch(ctx context.Context, cursor time.Time) (iter.Seq2[SourceEvent, error], error)
}
