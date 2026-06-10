package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// JSONLFormatter renders entries as JSON Lines: one JSON object per
// line, no array wrapper, so consumers can stream the file.
//
// Unlike the Markdown/CSV formatters this one preserves native JSON
// types — a missing severity base score becomes JSON null rather than
// the string "NA", and empty timestamps stay as empty strings, so
// downstream tools can use type-aware parsers instead of string sniffs.
type JSONLFormatter struct{}

// jsonlEntry is the on-the-wire JSON Lines shape. SeverityBaseScore is
// a pointer so json.Encoder emits `null` for missing scores (not 0.0,
// which would silently look like a "score of zero").
type jsonlEntry struct {
	Ecosystem         string   `json:"ecosystem"`
	Package           string   `json:"package"`
	ID                string   `json:"id"`
	Published         string   `json:"published"`
	Modified          string   `json:"modified"`
	SeverityType      string   `json:"severity_type"`
	SeverityBaseScore *float64 `json:"severity_base_score"`
	SeverityVector    string   `json:"severity_vector"`
}

// Extension returns ".jsonl".
func (f *JSONLFormatter) Extension() string { return ".jsonl" }

// Format writes one JSON-encoded entry per line to w. The encoder's
// trailing newline preserves the JSONL contract.
func (f *JSONLFormatter) Format(w io.Writer, entries []VulnerabilityEntry) error {
	enc := json.NewEncoder(w)
	for _, e := range entries {
		row := jsonlEntry{
			Ecosystem:         e.Ecosystem,
			Package:           e.Package,
			ID:                e.ID,
			Published:         e.Published,
			Modified:          e.Modified,
			SeverityType:      e.SeverityType,
			SeverityBaseScore: e.SeverityBaseScore,
			SeverityVector:    e.SeverityVector,
		}
		if err := enc.Encode(row); err != nil {
			return fmt.Errorf("encode jsonl entry: %w", err)
		}
	}
	return nil
}
