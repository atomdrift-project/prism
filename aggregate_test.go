package main

import (
	"strings"
	"testing"
)

// TestAggregateBackAttributesViaLocations covers the kops-style case where
// cleave rolled an inner-file match up to the archive container and recorded
// the original member path in the finding's `el` (Locations) field. The
// resulting Matches list must carry the inner file's name so the trait card
// can render its "filename — location — evidence" row.
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
				Spans:     [][2]int64{{0x3718c0, 14}},
				Locations: []string{"archive:pkg/assets/builder.go"},
			}},
		},
		{
			Path:   "archive.zip!!pkg/assets/builder.go",
			SHA256: innerSHA,
			Depth:  1,
		},
	}

	groups, _, _ := aggregateArchiveCategories(files)
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
	// v8 envelopes carry no evidence string; the span offset stands in as the
	// evidence for a finding with no decoded ctx window.
	if m.Evidence != "0x3718c0" {
		t.Errorf("match Evidence = %q, want span offset %q", m.Evidence, "0x3718c0")
	}
	if m.Filename != "builder.go" {
		t.Errorf("match Filename = %q, want %q", m.Filename, "builder.go")
	}
	if m.Path != "pkg/assets/builder.go" {
		t.Errorf("match Path = %q, want %q", m.Path, "pkg/assets/builder.go")
	}
	if m.Location != "" {
		t.Errorf("match Location = %q, want empty (legacy archive: form has no offset)", m.Location)
	}
}

// TestAggregateBackAttributesViaFileIndex covers the v6 compact `el` form,
// where the member path is replaced by the inner file's fs id ("1") with the
// byte offset preserved ("1:0x3718c0"). resolveMatchFile must resolve the id to
// the same inner file the legacy path-based form pointed at.
func TestAggregateBackAttributesViaFileIndex(t *testing.T) {
	innerSHA := strings.Repeat("b", 64)
	containerSHA := strings.Repeat("a", 64)
	files := []cleaveFile{
		{
			Path:   "archive.zip",
			SHA256: containerSHA,
			Depth:  0,
			ID:     0,
			Findings: []finding{{
				ID:        "well-known/malware/rootkit/ebpfkit::ebpfkit-assets-package",
				Crit:      4,
				Conf:      0.9,
				Spans:     [][2]int64{{0x3718c0, 14}},
				Locations: []string{"1:0x3718c0"},
			}},
		},
		{
			Path:   "archive.zip!!pkg/assets/builder.go",
			SHA256: innerSHA,
			Depth:  1,
			ID:     1,
		},
	}

	groups, _, _ := aggregateArchiveCategories(files)
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
	if m.Filename != "builder.go" {
		t.Errorf("match Filename = %q, want %q", m.Filename, "builder.go")
	}
	if m.Path != "pkg/assets/builder.go" {
		t.Errorf("match Path = %q, want %q", m.Path, "pkg/assets/builder.go")
	}
	if m.Location != "0x3718c0" {
		t.Errorf("match Location = %q, want the byte offset %q", m.Location, "0x3718c0")
	}
}

// TestParseLocationID locks in the v6-vs-legacy `el` discrimination.
func TestParseLocationID(t *testing.T) {
	cases := []struct {
		in     string
		wantID int
		wantOK bool
	}{
		{"1:0x3718c0", 1, true},
		{"42", 42, true},
		{"archive:pkg/assets/builder.go", 0, false},
		{"archive:0a8ab3.macho:0x10", 0, false}, // digit-led member stays legacy via prefix
		{"offset:0x1234", 0, false},
		{"0x1234", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		id, ok := parseLocationID(c.in)
		if ok != c.wantOK || (ok && id != c.wantID) {
			t.Errorf("parseLocationID(%q) = (%d, %t), want (%d, %t)", c.in, id, ok, c.wantID, c.wantOK)
		}
	}
}

// TestAggregateDropsUnresolvableContainerSources locks in the existing
// safety net: when a finding only fires on the container and we can't
// back-attribute via Locations (no `el` from older cleave builds, or a
// nested archive we don't have unpacked), the match drops the container
// attribution so the row renders as bare evidence with no filename column.
func TestAggregateDropsUnresolvableContainerSources(t *testing.T) {
	containerSHA := strings.Repeat("a", 64)
	files := []cleaveFile{
		{
			Path:   "archive.zip",
			SHA256: containerSHA,
			Depth:  0,
			Findings: []finding{{
				ID:    "well-known/malware/rootkit/ebpfkit::ebpfkit-assets-package",
				Crit:  4,
				Conf:  0.9,
				Spans: [][2]int64{{0x3718c0, 14}},
			}},
		},
	}

	groups, _, _ := aggregateArchiveCategories(files)
	for _, g := range groups {
		for _, f := range g.Findings {
			for _, m := range f.Matches {
				if m.Path != "" || m.Filename != "" {
					t.Errorf("container leaked into match attribution: %+v", m)
				}
			}
		}
	}
}

// TestLocationOffset locks in offset extraction across the three `loc`
// generations: v7 "<file-id>:<offset>", legacy "offset:<n>", and forms that
// carry no position at all.
func TestLocationOffset(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"1:0x3718c0", "0x3718c0"},
		{"42", ""},
		{"offset:0x1234", "0x1234"},
		{"archive:pkg/assets/builder.go", ""},
		{"archive:0a8ab3.macho:0x10", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := locationOffset(c.in); got != c.want {
			t.Errorf("locationOffset(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestHighlightEvidence exercises the chroma path: a JS filename yields
// classed tokens whose concatenation reproduces the evidence exactly, and
// an unknown filename falls back to nil (plain-text rendering).
func TestHighlightEvidence(t *testing.T) {
	ev := "require('child_process').exec(cmd)"
	tokens := highlightEvidence(ev, "index.js")
	if len(tokens) == 0 {
		t.Fatal("expected chroma tokens for a .js filename, got none")
	}
	var sb strings.Builder
	for _, tok := range tokens {
		sb.WriteString(tok.Text)
	}
	if sb.String() != ev {
		t.Errorf("token concatenation = %q, want original evidence %q", sb.String(), ev)
	}
	if highlightEvidence(ev, "") != nil {
		t.Error("empty filename should disable highlighting")
	}
	if highlightEvidence("", "index.js") != nil {
		t.Error("empty evidence should yield no tokens")
	}
}

// TestAggregateConfidenceFloor locks in the display rule: a finding whose
// confidence is below minTraitConfidence is hidden, while one at or above the
// floor is kept. The floor itself (0.65) is inclusive.
func TestAggregateConfidenceFloor(t *testing.T) {
	files := []cleaveFile{{
		Path:   "sample.bin",
		SHA256: strings.Repeat("a", 64),
		Depth:  1,
		Findings: []finding{
			{ID: "objectives/keep-high/x", Desc: "high", Crit: 3, Conf: 0.9},
			{ID: "objectives/drop-low/x", Desc: "low", Crit: 3, Conf: 0.5},
			{ID: "objectives/keep-boundary/x", Desc: "boundary", Crit: 3, Conf: minTraitConfidence},
		},
	}}

	groups, total, shown := aggregateArchiveCategories(files)
	got := make(map[string]bool)
	for _, g := range groups {
		for _, f := range g.Findings {
			got[f.ID] = true
		}
	}
	if !got["keep-high"] {
		t.Error("high-confidence trait should be shown")
	}
	if !got["keep-boundary"] {
		t.Error("trait exactly at the confidence floor should be shown (floor is inclusive)")
	}
	if got["drop-low"] {
		t.Error("trait with confidence below the floor should be hidden")
	}
	if total != 2 || shown != 2 {
		t.Errorf("counts: got total=%d shown=%d, want 2 and 2", total, shown)
	}
}
