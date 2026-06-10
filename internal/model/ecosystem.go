package model

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var ErrInvalidEcosystem = errors.New("invalid ecosystem")

// Ecosystem represents an OSV ecosystem name.
type Ecosystem string

// Supported ecosystems.
const (
	NPM           Ecosystem = "npm"
	PyPI          Ecosystem = "PyPI"
	Go            Ecosystem = "Go"
	GitHubActions Ecosystem = "GitHub Actions"
	RubyGems      Ecosystem = "RubyGems"
	RedHat        Ecosystem = "Red Hat"
	Maven         Ecosystem = "Maven"
	NuGet         Ecosystem = "NuGet"
	OSSFuzz       Ecosystem = "OSS-Fuzz"
)

const baseURL = "https://osv-vulnerabilities.storage.googleapis.com"

// ModifiedCSVURL returns the URL for the all.zip file of this ecosystem.
func (e Ecosystem) ModifiedCSVURL() string {
	escapedName := url.PathEscape(string(e))
	return fmt.Sprintf("%s/%s/all.zip", baseURL, escapedName)
}

// SitemapURL returns the URL for the OSV sitemap XML of this ecosystem.
func (e Ecosystem) SitemapURL() string {
	name := strings.ReplaceAll(string(e), " ", "_")
	return fmt.Sprintf("https://osv.dev/sitemap_%s.xml", name)
}

// String returns the string representation of the ecosystem.
func (e Ecosystem) String() string {
	return string(e)
}

// ValidateEcosystems checks that every ecosystem is present in the allow list.
func ValidateEcosystems(ecosystems []Ecosystem, allowList []string) error {
	set := make(map[string]struct{}, len(allowList))
	for _, name := range allowList {
		set[name] = struct{}{}
	}

	var errs []error
	for _, eco := range ecosystems {
		if _, ok := set[string(eco)]; !ok {
			errs = append(errs, fmt.Errorf("invalid ecosystem %q: %w", eco, ErrInvalidEcosystem))
		}
	}
	return errors.Join(errs...)
}

// ParseEcosystems parses a comma-separated string into a slice of Ecosystems.
func ParseEcosystems(s string) []Ecosystem {
	s = strings.TrimSpace(s)
	if s == "" {
		return []Ecosystem{}
	}

	parts := strings.Split(s, ",")
	ecosystems := make([]Ecosystem, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		ecosystems = append(ecosystems, Ecosystem(trimmed))
	}

	return ecosystems
}
