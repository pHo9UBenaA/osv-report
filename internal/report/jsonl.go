package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

// FormatJSONL converts vulnerability entries to a JSONL string.
func FormatJSONL(entries []VulnerabilityEntry) (string, error) {
	var sb strings.Builder

	for _, e := range entries {
		obj := map[string]string{
			"ecosystem":           e.Ecosystem,
			"package":             e.Package,
			"id":                  e.ID,
			"published":           formatString(e.Published),
			"modified":            formatString(e.Modified),
			"severity_base_score": formatBaseScore(e.SeverityBaseScore),
			"severity_type":       formatString(e.SeverityType),
			"severity_vector":     formatString(e.SeverityVector),
		}

		data, err := json.Marshal(obj)
		if err != nil {
			return "", fmt.Errorf("marshal json: %w", err)
		}

		sb.Write(data)
		sb.WriteString("\n")
	}

	return sb.String(), nil
}
