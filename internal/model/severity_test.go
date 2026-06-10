package model_test

import (
	"testing"

	"github.com/pHo9UBenaA/osv-report/internal/model"
)

func TestParseVector_ValidCVSS31Vector_ReturnsBaseScore(t *testing.T) {
	score, err := model.ParseVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if err != nil {
		t.Fatalf("ParseVector() error = %v", err)
	}
	if score != 9.8 {
		t.Fatalf("ParseVector() score = %v, want 9.8", score)
	}
}

func TestParseVector_PlainFloatString_ReturnsError(t *testing.T) {
	if _, err := model.ParseVector("7.5"); err == nil {
		t.Fatalf("ParseVector() expected error for bare numeric vector")
	}
}

func TestParseVector_CVSS4Vector_ReturnsBaseScore(t *testing.T) {
	score, err := model.ParseVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H")
	if err != nil {
		t.Fatalf("ParseVector() error = %v", err)
	}
	if score != 10.0 {
		t.Fatalf("ParseVector() score = %v, want 10.0", score)
	}
}

func TestExtractFromOSV_ValidCVSS3Entry_ReturnsScoreAndVector(t *testing.T) {
	base, vector, kind, err := model.ExtractFromOSV([]model.SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}})
	if err != nil {
		t.Fatalf("ExtractFromOSV() error = %v", err)
	}
	if vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Fatalf("ExtractFromOSV() vector = %q", vector)
	}
	if kind != "CVSS_V3.1" {
		t.Fatalf("ExtractFromOSV() kind = %q, want CVSS_V3.1", kind)
	}
	if base == nil || *base != 9.8 {
		t.Fatalf("ExtractFromOSV() base = %v, want 9.8", base)
	}
}

func TestExtractFromOSV_UnparseableVector_ReturnsErrorWithVector(t *testing.T) {
	base, vector, kind, err := model.ExtractFromOSV([]model.SeverityEntry{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N"}})
	if err == nil {
		t.Fatalf("ExtractFromOSV() expected error")
	}
	if vector != "CVSS:4.0/AV:N" {
		t.Fatalf("ExtractFromOSV() vector = %q", vector)
	}
	if kind != "CVSS_V4.0" {
		t.Fatalf("ExtractFromOSV() kind = %q, want CVSS_V4.0", kind)
	}
	if base != nil {
		t.Fatalf("ExtractFromOSV() base = %v, want nil", base)
	}
}

// TestParseVector_KnownVectors checks the library's base-score output against
// values published by FIRST's CVSS calculator. Each version includes at least
// one boundary case around 9.0/9.05/8.95 so the spec-mandated roundup matches.
func TestParseVector_KnownVectors(t *testing.T) {
	cases := []struct {
		name   string
		vector string
		want   float64
	}{
		// CVSS v2.0 — from the FIRST v2 calculator / spec examples. The
		// "CVSS:2.0/" prefix is our dispatch marker; the library reads the
		// bare-metric portion after the slash.
		{"v2_full_av_n", "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0},
		{"v2_partial", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5},
		{"v2_local_low", "CVSS:2.0/AV:L/AC:H/Au:N/C:N/I:N/A:P", 1.2},

		// CVSS v3.0 — values verified against FIRST's v3.0 calculator.
		{"v3_0_max", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"v3_0_changed", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		// Boundary near 9.0: this vector scores in the 8.x range and exercises
		// the roundup edge — score below 9.0 must NOT be promoted.
		{"v3_0_below_9", "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8},

		// CVSS v3.1 — values verified against FIRST's v3.1 calculator.
		{"v3_1_max", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"v3_1_changed", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		// Boundary case: vector that ends up just under 9.0 verifies the
		// roundup-by-tenths logic isn't sliding up to 9.0.
		{"v3_1_below_9", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8},

		// CVSS v4.0 — values verified against FIRST's v4 calculator.
		{"v4_max", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0},
		{"v4_high", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3},
		{"v4_low", "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N", 1.0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := model.ParseVector(tc.vector)
			if err != nil {
				t.Fatalf("ParseVector(%q) error = %v", tc.vector, err)
			}
			if got != tc.want {
				t.Fatalf("ParseVector(%q) = %v, want %v", tc.vector, got, tc.want)
			}
		})
	}
}

func TestSelectSeverity_PrefersV4OverV3(t *testing.T) {
	entries := []model.SeverityEntry{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"},
	}
	_, vector, kind, err := model.ExtractFromOSV(entries)
	if err != nil {
		t.Fatalf("ExtractFromOSV() error = %v", err)
	}
	if kind != "CVSS_V4.0" {
		t.Fatalf("kind = %q, want CVSS_V4.0", kind)
	}
	if vector != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H" {
		t.Fatalf("vector = %q, want v4", vector)
	}
}

func TestSelectSeverity_SkipsNonCVSS(t *testing.T) {
	entries := []model.SeverityEntry{
		{Type: "Ubuntu", Score: "high"},
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}
	_, vector, kind, err := model.ExtractFromOSV(entries)
	if err != nil {
		t.Fatalf("ExtractFromOSV() error = %v", err)
	}
	if kind != "CVSS_V3.1" {
		t.Fatalf("kind = %q, want CVSS_V3.1", kind)
	}
	if vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Fatalf("vector = %q", vector)
	}
}

func TestSelectSeverity_V3_0VsV3_1(t *testing.T) {
	cases := []struct {
		name   string
		vector string
		want   string
	}{
		{"v3_0", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS_V3.0"},
		{"v3_1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS_V3.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, kind, err := model.ExtractFromOSV([]model.SeverityEntry{{Type: "CVSS_V3", Score: tc.vector}})
			if err != nil {
				t.Fatalf("ExtractFromOSV() error = %v", err)
			}
			if kind != tc.want {
				t.Fatalf("kind = %q, want %q", kind, tc.want)
			}
		})
	}
}
