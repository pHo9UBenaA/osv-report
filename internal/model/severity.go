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
// so the kind tag is refined by inspecting Score when Type is "CVSS_V3".
// When no prefix is recognised the kind falls back to bare "CVSS_V3", which
// ParseVectorByKind treats as an immediate error rather than guessing.
func selectSeverity(severities []SeverityEntry) (*SeverityEntry, string) {
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
		return nil, ""
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

	return &chosen, k
}

// ParseVectorByKind parses a CVSS vector and returns the base score, using
// the OSV-derived kind tag to dispatch to the right library version.
//
// Supported kinds are exactly what selectSeverity emits: "CVSS_V2",
// "CVSS_V3.0", "CVSS_V3.1", "CVSS_V4.0", plus the fallback "CVSS_V3" for
// V3 entries whose vector lacks a recognised prefix. The fallback returns
// an error rather than guessing because a vector without a 3.x prefix
// would fail gocvss31 parsing anyway; surfacing it lets the caller record
// the bad vector without inventing a score.
//
// CVSS v2 accepts two forms: bare metrics ("AV:N/AC:L/Au:N/...") and the
// parenthesised form ("(AV:N/AC:L/Au:N/...)") occasionally seen in real
// OSV data. The "CVSS:2.0/" prefix is not supported because it is not in
// the CVSS v2 spec and not emitted by upstream OSV.
func ParseVectorByKind(kind, vector string) (float64, error) {
	vector = strings.TrimSpace(vector)
	switch kind {
	case "CVSS_V2":
		// Trim the optional surrounding parentheses; gocvss20 wants the
		// bare metric list.
		v2 := strings.TrimPrefix(strings.TrimSuffix(vector, ")"), "(")
		parsed, err := gocvss20.ParseVector(v2)
		if err != nil {
			return 0, fmt.Errorf("parse cvss v2 vector: %w", err)
		}
		return parsed.BaseScore(), nil
	case "CVSS_V3.0":
		parsed, err := gocvss30.ParseVector(vector)
		if err != nil {
			return 0, fmt.Errorf("parse cvss v3.0 vector: %w", err)
		}
		return parsed.BaseScore(), nil
	case "CVSS_V3.1":
		parsed, err := gocvss31.ParseVector(vector)
		if err != nil {
			return 0, fmt.Errorf("parse cvss v3.1 vector: %w", err)
		}
		return parsed.BaseScore(), nil
	case "CVSS_V4.0":
		parsed, err := gocvss40.ParseVector(vector)
		if err != nil {
			return 0, fmt.Errorf("parse cvss v4.0 vector: %w", err)
		}
		return parsed.Score(), nil
	case "CVSS_V3":
		// Reserved as a future extension point: when vector normalisation
		// is added, this branch can attempt the most likely minor version.
		// Today no real input would parse, so refuse rather than guess.
		return 0, fmt.Errorf("unrecognized CVSS_V3 vector prefix")
	default:
		return 0, fmt.Errorf("unsupported CVSS kind %q", kind)
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
	chosen, kind := selectSeverity(severities)
	if chosen == nil {
		return nil, "", "", nil
	}

	vector := strings.TrimSpace(chosen.Score)
	if vector == "" {
		return nil, "", kind, nil
	}

	base, err := ParseVectorByKind(kind, vector)
	if err != nil {
		return nil, vector, kind, err
	}

	return &base, vector, kind, nil
}
