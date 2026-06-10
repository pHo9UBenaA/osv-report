package model

import (
	"fmt"
	"strings"

	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"
)

// SeverityEntry represents severity information from OSV data.
// This mirrors the OSV API severity JSON structure but lives in model/
// to avoid a dependency on the osv/ package.
type SeverityEntry struct {
	Type  string
	Score string
}

// selectSeverity picks the highest-priority CVSS entry from an OSV severity list.
//
// Priority is v4 > v3 > v2; anything else (e.g. distro-specific "Ubuntu",
// "RedHat") is excluded. OSV's Type field only goes as far as "CVSS_V3" —
// the minor-version distinction (3.0 vs 3.1) lives in the vector prefix,
// so kind is refined by inspecting Score when Type is "CVSS_V3".
func selectSeverity(severities []SeverityEntry) (selected *SeverityEntry, kind string, err error) {
	priority := func(t string) int {
		switch t {
		case "CVSS_V4":
			return 3
		case "CVSS_V3":
			return 2
		case "CVSS_V2":
			return 1
		default:
			return 0
		}
	}

	var bestIdx = -1
	bestPriority := 0
	for i, s := range severities {
		p := priority(s.Type)
		if p > bestPriority {
			bestPriority = p
			bestIdx = i
		}
	}

	if bestIdx < 0 {
		return nil, "", nil
	}

	chosen := severities[bestIdx]
	vector := strings.TrimSpace(chosen.Score)
	k := chosen.Type
	switch chosen.Type {
	case "CVSS_V4":
		k = "CVSS_V4.0"
	case "CVSS_V3":
		switch {
		case strings.HasPrefix(vector, "CVSS:3.0/"):
			k = "CVSS_V3.0"
		case strings.HasPrefix(vector, "CVSS:3.1/"):
			k = "CVSS_V3.1"
		default:
			k = "CVSS_V3"
		}
	case "CVSS_V2":
		k = "CVSS_V2"
	}

	return &chosen, k, nil
}

// ParseVector parses a CVSS vector string and returns the base score.
// The CVSS version is determined by the vector prefix. Bare numeric scores
// are not accepted — OSV consistently supplies a vector for CVSS entries.
func ParseVector(vector string) (float64, error) {
	switch {
	case strings.HasPrefix(vector, "CVSS:2.0/"):
		// gocvss20 expects the bare metric list — the "CVSS:2.0/" prefix is
		// our own dispatch marker and is not part of the CVSS v2 spec.
		v, err := gocvss20.ParseVector(strings.TrimPrefix(vector, "CVSS:2.0/"))
		if err != nil {
			return 0, fmt.Errorf("parse cvss v2.0 vector: %w", err)
		}
		return v.BaseScore(), nil
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		v, err := gocvss30.ParseVector(vector)
		if err != nil {
			return 0, fmt.Errorf("parse cvss v3.0 vector: %w", err)
		}
		return v.BaseScore(), nil
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		v, err := gocvss31.ParseVector(vector)
		if err != nil {
			return 0, fmt.Errorf("parse cvss v3.1 vector: %w", err)
		}
		return v.BaseScore(), nil
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		v, err := gocvss40.ParseVector(vector)
		if err != nil {
			return 0, fmt.Errorf("parse cvss v4.0 vector: %w", err)
		}
		return v.Score(), nil
	default:
		return 0, fmt.Errorf("unsupported CVSS vector prefix")
	}
}

// ExtractFromOSV picks the highest-priority CVSS entry from OSV severity data
// and returns its base score, vector, and a kind tag (e.g. "CVSS_V3.1",
// "CVSS_V4.0"). The kind is persisted in the database alongside the vector so
// downstream consumers can distinguish CVSS versions without re-parsing.
//
// When no usable CVSS entry exists all return values are zero. When parsing
// the chosen vector fails the vector and kind are still returned (the caller
// can persist them even without a numeric score).
func ExtractFromOSV(severities []SeverityEntry) (*float64, string, string, error) {
	chosen, kind, err := selectSeverity(severities)
	if err != nil {
		return nil, "", "", err
	}
	if chosen == nil {
		return nil, "", "", nil
	}

	vector := strings.TrimSpace(chosen.Score)
	if vector == "" {
		return nil, "", kind, nil
	}

	base, err := ParseVector(vector)
	if err != nil {
		return nil, vector, kind, err
	}

	return &base, vector, kind, nil
}
