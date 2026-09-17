package main

import (
	"fmt"
	"strings"
	"testing"
)

// These tests lock in the two bounds added on 2026-09-17 after a heap profile
// showed highlightEvidence accounting for 89% of 6.43 TB of cumulative
// allocation — the churn that drove prism's heap_sys to 53 GB against a ~3 GB
// live set and got it OOM-killed 15 times on bilbo.
//
// Both bounds are invisible in rendered output (the template falls back to
// plain Evidence when Tokens is empty), so without these tests a regression
// would silently either stop highlighting everything or resume highlighting
// thousands of discarded rows. Neither shows up as a failure anywhere else.

// TestHighlightEvidenceSizeCap pins the snippet ceiling. Just under the cap
// still highlights; just over degrades to plain text rather than tokenising a
// fragment whose regexp2 match buffers dominate the heap.
func TestHighlightEvidenceSizeCap(t *testing.T) {
	// Repeat a lexable JS statement so chroma has real tokens to emit at both
	// sizes; only the length differs between the two cases.
	unit := "var x = 1; "
	under := strings.Repeat(unit, maxHighlightBytes/len(unit)/2)
	if len(under) > maxHighlightBytes {
		t.Fatalf("test setup: under-cap input is %d bytes, cap is %d", len(under), maxHighlightBytes)
	}
	if got := highlightEvidence(under, "postinstall.js"); got == nil {
		t.Errorf("evidence of %d bytes (under the %d cap) should be highlighted, got nil tokens",
			len(under), maxHighlightBytes)
	}

	over := strings.Repeat(unit, (maxHighlightBytes/len(unit))+2)
	if len(over) <= maxHighlightBytes {
		t.Fatalf("test setup: over-cap input is %d bytes, cap is %d", len(over), maxHighlightBytes)
	}
	if got := highlightEvidence(over, "postinstall.js"); got != nil {
		t.Errorf("evidence of %d bytes (over the %d cap) must not be highlighted, got %d tokens",
			len(over), maxHighlightBytes, len(got))
	}
}

// TestPerFileMatchesHighlightedAfterCap covers the per-file aggregation path.
// Highlighting is deferred until after the top-N truncation, so this asserts
// the rows that actually render did still get tokens — the regression that
// deferral could introduce.
func TestPerFileMatchesHighlightedAfterCap(t *testing.T) {
	const rows = 40 // comfortably above the per-file cap of 8
	f := cleaveFile{
		Path:     "postinstall.js",
		FileType: "javascript",
		Depth:    0,
		Findings: []finding{{
			ID:   "objectives/execution/interpreter/eval::dynamic",
			Crit: 3, Conf: 0.9, Desc: "dynamic eval",
		}},
	}
	// Distinct evidence per row so nothing dedups away, each independently
	// lexable as JavaScript.
	for i := range rows {
		off := int64(0x100 + i*0x40)
		f.Findings[0].Spans = append(f.Findings[0].Spans, [2]int64{off, 20})
		f.Ctx = append(f.Ctx, contextWindow{
			Offset: off,
			Data:   []byte(fmt.Sprintf("child_process.exec(%02d)", i)),
		})
	}

	got := buildStructuredFindings([]cleaveFile{f})
	if len(got) != 1 {
		t.Fatalf("expected findings for one file, got %d", len(got))
	}
	m := findMatches(t, got[0].Categories, "execution/interpreter")
	if len(m) == 0 {
		t.Fatal("expected at least one match")
	}
	if len(m) > 8 {
		t.Errorf("per-file matches = %d, want the cap of 8 to hold", len(m))
	}
	for i := range m {
		if m[i].Tokens == nil {
			t.Errorf("match %d (%q) rendered without tokens; highlighting after the cap regressed",
				i, m[i].Evidence)
		}
	}
}
