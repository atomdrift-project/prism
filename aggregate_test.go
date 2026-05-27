package main

import (
	"strings"
	"testing"
)

// TestAggregateBackAttributesViaLocations covers the kops-style case where
// cleave rolled an inner-file match up to the archive container and recorded
// the original member path in the finding's `el` (Locations) field. The
// resulting Matches list must point at the inner file's SHA so the trait
// card can render a clickable row for the user.
func TestAggregateBackAttributesViaLocations(t *testing.T) {
	innerSHA := strings.Repeat("b", 64)
	containerSHA := strings.Repeat("a", 64)
	files := []cleaveFile{
		{
			Path:   "archive.zip",
			SHA256: containerSHA,
			Depth:  0,
			Findings: []finding{{
				ID:        "well-known/malware/rootkit/ebpfkit::ebpfkit-assets-package",
				Crit:      4,
				Conf:      0.9,
				Evidence:  []string{"package assets"},
				Locations: []string{"archive:pkg/assets/builder.go"},
			}},
		},
		{
			Path:   "archive.zip!!pkg/assets/builder.go",
			SHA256: innerSHA,
			Depth:  1,
		},
	}

	groups := aggregateArchiveCategories(files)
	// aggregateArchiveCategories collapses leaf trait IDs to their dir
	// path (segments 1..n-1), so this rootkit trait rolls up under
	// "malware/rootkit" rather than the full leaf.
	var got *FindingDisplay
	for i := range groups {
		for j := range groups[i].Findings {
			if groups[i].Findings[j].ID == "malware/rootkit" {
				got = &groups[i].Findings[j]
			}
		}
	}
	if got == nil {
		t.Fatalf("rootkit finding missing from aggregated output: %+v", groups)
	}
	if len(got.Matches) != 1 {
		t.Fatalf("expected exactly one match, got %d: %+v", len(got.Matches), got.Matches)
	}
	m := got.Matches[0]
	if m.Evidence != "package assets" {
		t.Errorf("match Evidence = %q, want %q", m.Evidence, "package assets")
	}
	if m.SHA256 != innerSHA {
		t.Errorf("match SHA256 = %q, want inner file SHA %q", m.SHA256, innerSHA)
	}
	if m.Path != "pkg/assets/builder.go" {
		t.Errorf("match Path = %q, want %q", m.Path, "pkg/assets/builder.go")
	}
}

// TestAggregateDropsUnresolvableContainerSources locks in the existing
// safety net: when a finding only fires on the container and we can't
// back-attribute via Locations (no `el` from older cleave builds, or a
// nested archive we don't have unpacked), the match drops the container
// SHA so the row renders as path-less evidence instead of a dead link.
func TestAggregateDropsUnresolvableContainerSources(t *testing.T) {
	containerSHA := strings.Repeat("a", 64)
	files := []cleaveFile{
		{
			Path:   "archive.zip",
			SHA256: containerSHA,
			Depth:  0,
			Findings: []finding{{
				ID:       "well-known/malware/rootkit/ebpfkit::ebpfkit-assets-package",
				Crit:     4,
				Conf:     0.9,
				Evidence: []string{"package assets"},
			}},
		},
	}

	groups := aggregateArchiveCategories(files)
	for _, g := range groups {
		for _, f := range g.Findings {
			for _, m := range f.Matches {
				if m.SHA256 == containerSHA {
					t.Errorf("container SHA leaked into matches: %+v", m)
				}
			}
		}
	}
}
