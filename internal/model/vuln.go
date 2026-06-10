package model

import "time"

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
