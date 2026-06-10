package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-report/internal/store"
)

// BenchmarkSaveVulnerability captures the per-record write cost of the
// current pre-Phase-A API. Phase A-1 will introduce
// SaveVulnerabilityWithAffected and re-baseline.
func BenchmarkSaveVulnerability(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")
	ctx := context.Background()

	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		b.Fatalf("NewStore() error = %v", err)
	}
	b.Cleanup(func() { s.Close() }) //nolint:errcheck

	base := time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := store.Vulnerability{
			ID:                fmt.Sprintf("BENCH-%d", i),
			Modified:          base.Add(time.Duration(i) * time.Second),
			Published:         base,
			Summary:           "bench summary",
			Details:           "bench details",
			SeverityBaseScore: sql.NullFloat64{Float64: 7.5, Valid: true},
			SeverityVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L",
		}
		if err := s.SaveVulnerability(ctx, v); err != nil {
			b.Fatalf("SaveVulnerability iteration %d: %v", i, err)
		}
	}
}
