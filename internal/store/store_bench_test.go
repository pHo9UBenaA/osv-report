package store_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/pHo9UBenaA/osv-report/internal/store"
)

// BenchmarkSaveVulnerabilityWithAffected captures the per-record write cost
// of the combined upsert + affected washout transaction.
func BenchmarkSaveVulnerabilityWithAffected(b *testing.B) {
	dbPath := filepath.Join(b.TempDir(), "bench.db")
	ctx := context.Background()

	s, err := store.NewStore(ctx, dbPath)
	if err != nil {
		b.Fatalf("NewStore() error = %v", err)
	}
	b.Cleanup(func() { _ = s.Close() })

	base := time.Date(2025, 10, 4, 12, 0, 0, 0, time.UTC)
	score := 7.5

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := fmt.Sprintf("BENCH-%d", i)
		v := store.Vulnerability{
			ID:                id,
			Modified:          base.Add(time.Duration(i) * time.Second),
			Published:         base,
			Summary:           "bench summary",
			Details:           "bench details",
			SeverityBaseScore: &score,
			SeverityVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L",
		}
		affected := []store.Affected{
			{VulnID: id, Ecosystem: "npm", Package: "bench-pkg"},
		}
		if err := s.SaveVulnerabilityWithAffected(ctx, v, affected); err != nil {
			b.Fatalf("SaveVulnerabilityWithAffected iteration %d: %v", i, err)
		}
	}
}
