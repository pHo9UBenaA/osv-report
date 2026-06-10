package osv

import (
	"time"

	"github.com/pHo9UBenaA/osv-report/internal/model"
)

// rawPackage mirrors the OSV affected[].package object.
type rawPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// rawAffected mirrors one entry of the OSV affected[] array. Only the
// package identity matters here; version ranges are ignored because the
// store-level reporting unit is "(vuln, ecosystem, package)".
type rawAffected struct {
	Package rawPackage `json:"package"`
}

// rawSeverity mirrors one entry of the OSV severity[] array.
type rawSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// rawVulnerability is the wire shape of a single OSV record as it
// appears inside an all.zip entry. `withdrawn` is an optional RFC3339
// timestamp: the 0-S investigation confirmed that records remain in the
// zip even after they're withdrawn, so callers can treat a non-zero
// Withdrawn value as the authoritative delete signal.
type rawVulnerability struct {
	ID        string        `json:"id"`
	Modified  time.Time     `json:"modified"`
	Published time.Time     `json:"published,omitempty"`
	Withdrawn time.Time     `json:"withdrawn,omitempty"`
	Summary   string        `json:"summary,omitempty"`
	Details   string        `json:"details,omitempty"`
	Affected  []rawAffected `json:"affected,omitempty"`
	Severity  []rawSeverity `json:"severity,omitempty"`
}

// normalize is the pure conversion from the wire shape to the model
// domain type. Pure means: no I/O, no logging, no DB access — it just
// reshapes data. This makes the conversion trivially testable without
// HTTP or SQLite and lets multiple Source implementations share it.
func normalize(r *rawVulnerability) *model.Vulnerability {
	affected := make([]model.AffectedPackage, len(r.Affected))
	for i, a := range r.Affected {
		affected[i] = model.AffectedPackage{
			Ecosystem: a.Package.Ecosystem,
			Name:      a.Package.Name,
		}
	}

	severity := make([]model.SeverityEntry, len(r.Severity))
	for i, s := range r.Severity {
		severity[i] = model.SeverityEntry{
			Type:  s.Type,
			Score: s.Score,
		}
	}

	return &model.Vulnerability{
		ID:        r.ID,
		Modified:  r.Modified,
		Published: r.Published,
		Summary:   r.Summary,
		Details:   r.Details,
		Affected:  affected,
		Severity:  severity,
	}
}
