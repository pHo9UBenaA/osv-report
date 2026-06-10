package model_test

import (
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-report/internal/model"
)

func mustParseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestMaxModified_InputVariants(t *testing.T) {
	cases := []struct {
		name    string
		entries []model.Entry
		want    time.Time
	}{
		{
			name: "MultipleEntries_ReturnsLatest",
			entries: []model.Entry{
				{ID: "GHSA-0001", Modified: mustParseTime("2025-10-04T09:00:00Z")},
				{ID: "GHSA-0002", Modified: mustParseTime("2025-10-04T13:00:00Z")},
				{ID: "GHSA-0003", Modified: mustParseTime("2025-10-04T11:00:00Z")},
			},
			want: mustParseTime("2025-10-04T13:00:00Z"),
		},
		{
			name:    "EmptySlice_ReturnsZeroTime",
			entries: nil,
			want:    time.Time{},
		},
		{
			name: "UnsortedEntries_StillReturnsMax",
			entries: []model.Entry{
				{ID: "GHSA-0003", Modified: mustParseTime("2025-10-04T13:00:00Z")},
				{ID: "GHSA-0001", Modified: mustParseTime("2025-10-04T09:00:00Z")},
				{ID: "GHSA-0002", Modified: mustParseTime("2025-10-04T11:00:00Z")},
			},
			want: mustParseTime("2025-10-04T13:00:00Z"),
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := model.MaxModified(tt.entries)
			if !got.Equal(tt.want) {
				t.Errorf("MaxModified() = %v, want %v", got, tt.want)
			}
		})
	}
}
