package store

import "time"

// SetStoreClockForTesting injects a deterministic clock into a Store so
// tests can pin fetched_at to a known sequence of values. Lives in an
// _test.go file so the hook is invisible at link time in non-test builds.
func SetStoreClockForTesting(s *Store, clock func() time.Time) {
	s.clock = clock
}
