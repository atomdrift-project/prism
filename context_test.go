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

// TestContextProvidesEvidence locks in the v8 path: a finding's `spans` index
// into the file's `ctx` bytes, and the evidence column renders the matched
// content the same way the Content tab does. A binary (hex) window yields a
// hex+ascii dump, a 0x-formatted offset, and no syntax-highlight tokens.
func TestContextProvidesEvidence(t *testing.T) {
	files := []cleaveFile{{
		Path:     "stub.bin",
		FileType: "elf", // binary type → hex view
		Depth:    0,
		Findings: []finding{
			{ID: "objectives/execution/interpreter/eval::dynamic", Crit: 3, Conf: 0.9, Desc: "dynamic eval",
				Spans: [][2]int64{{0x6b, 4}}},
		},
		Ctx: []contextWindow{{
			Offset: 0x6b,
			Data:   []byte{0xea, 0xfb, 0x32, 0xd5},
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
		t.Errorf("evidence = %q, want the hex dump of the ctx bytes", m[0].Evidence)
	}
	if m[0].Location != "0x6b" {
		t.Errorf("location = %q, want hex offset 0x6b (107)", m[0].Location)
	}
	if m[0].Tokens != nil {
		t.Errorf("hex evidence should not be syntax-highlighted, got %d tokens", len(m[0].Tokens))
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
			Findings: []finding{{ID: "objectives/execution/interpreter/eval::call", Crit: 3, Conf: 0.9, Desc: "eval",
				Spans: [][2]int64{{40, 7}}}},
			Ctx: []contextWindow{{
				Offset: 40,
				Addr:   ptrInt64(40),
				Data:   []byte("eval(s)"),
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
