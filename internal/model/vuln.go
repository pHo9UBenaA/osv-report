package model

import "time"

// Entry represents a vulnerability entry with ID and modified timestamp.
// Used for sitemap/CSV parsing results before full vulnerability data is fetched.
type Entry struct {
	ID       string
	Modified time.Time
}

// AffectedPackage represents a package affected by a vulnerability.
type AffectedPackage struct {
	Ecosystem string
	Name      string
}

// Vulnerability represents a vulnerability with its core domain fields.
type Vulnerability struct {
	ID        string
	Modified  time.Time
	Published time.Time
	Summary   string
	Details   string
	Affected  []AffectedPackage
	Severity  []SeverityEntry
}

// MaxModified returns the latest Modified time from the given entries.
// Returns zero time if entries is empty.
func MaxModified(entries []Entry) time.Time {
	var max time.Time
	for _, e := range entries {
		if e.Modified.After(max) {
			max = e.Modified
		}
	}
	return max
}
