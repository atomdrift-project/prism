package main

import (
	"bytes"
	"strings"
	"testing"
)

func ptrInt64(v int64) *int64 { p := v; return &p }

// TestZ85DecodeVector checks the canonical ZeroMQ RFC 32 vector and a partial
// trailing group, matching cleave's encoder.
func TestZ85DecodeVector(t *testing.T) {
	got, err := z85Decode("HelloWorld")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []byte{0x86, 0x4f, 0xd2, 0x6f, 0xb5, 0x59, 0xf7, 0x5b}
	if !bytes.Equal(got, want) {
		t.Errorf("decode = % x, want % x", got, want)
	}
	if _, err := z85Decode("x"); err == nil {
		t.Error("a one-character group must be rejected")
	}
}

// TestSourceContextHighlights confirms a source window numbers its line and
// lights only the matched span at the note's severity.
func TestSourceContextHighlights(t *testing.T) {
	file := &cleaveFile{Ctx: []contextWindow{{
		Offset: 5,
		Addr:   ptrInt64(100),
		Data:   []byte("exec(data)"),
		Notes:  []contextNote{{ID: "t/x", Offset: 100, Size: 4, Crit: 5}},
	}}}
	blocks := buildContextBlocks(file, "t/x")
	if len(blocks) != 1 || len(blocks[0].Rows) != 1 {
		t.Fatalf("want one block/row, got %+v", blocks)
	}
	row := blocks[0].Rows[0]
	if row.Loc != "5" || row.Crit != "hostile" {
		t.Errorf("loc/crit = %q/%q, want 5/hostile", row.Loc, row.Crit)
	}
	if len(row.Segs) != 2 || row.Segs[0].Text != "exec" || row.Segs[0].Crit != "hostile" || row.Segs[1].Crit != "" {
		t.Errorf("segs = %+v, want [exec:hostile][(data):plain]", row.Segs)
	}
}

// TestSourceContextSyntaxHighlight confirms source context carries chroma
// syntax classes while still lighting the matched span.
func TestSourceContextSyntaxHighlight(t *testing.T) {
	file := &cleaveFile{Path: "payload.js", FileType: "javascript", Ctx: []contextWindow{{
		Offset: 1,
		Addr:   ptrInt64(0),
		Data:   []byte("eval(x)"),
		Notes:  []contextNote{{ID: "t/x", Offset: 0, Size: 4, Crit: 5}},
	}}}
	blocks := buildContextBlocks(file, "t/x")
	if len(blocks) != 1 || len(blocks[0].Rows) != 1 {
		t.Fatalf("want one block/row, got %+v", blocks)
	}
	segs := blocks[0].Rows[0].Segs
	var lit, classed bool
	for _, s := range segs {
		if s.Text == "eval" && s.Crit == "hostile" {
			lit = true
		}
		if s.Class != "" {
			classed = true
		}
	}
	if !lit {
		t.Errorf("matched 'eval' span not lit: %+v", segs)
	}
	if !classed {
		t.Errorf("no chroma syntax classes applied: %+v", segs)
	}
}

// TestHighlightedSegsReconstructsLine guards the production panic where chroma
// emitted a trailing newline (token bytes > line bytes) and the renderer sliced
// out of range. The segments must always rebuild the original line exactly —
// no dropped or leaked bytes — for any lexer, with or without a match span.
func TestHighlightedSegsReconstructsLine(t *testing.T) {
	cases := []struct {
		filename string
		line     string
	}{
		{"a.py", "    data = base64.b64decode(payload).decode(\"utf-8\").strip()"},
		{"x.js", "const x = require('child_process').exec(cmd);"},
		{"x.toml", "name = \"mureo\""},
		{"setup.cfg", "[metadata]"},
		{"unknown.zzz", "no lexer matches this filename at all"},
	}
	for _, tc := range cases {
		spans := []rowSpan{{Crit: "hostile", Start: 0, End: 4}}
		segs := highlightedSegs(tc.line, spans, tc.filename) // must not panic
		var b strings.Builder
		for _, s := range segs {
			b.WriteString(s.Text)
		}
		if b.String() != tc.line {
			t.Errorf("%s: reconstructed %q, want %q", tc.filename, b.String(), tc.line)
		}
	}
}

// TestRowAnnoSingleStrongest locks in cleave's rule: a row carries at most one
// trailing annotation — the strongest match that begins on it — even when two
// traits match the same line. Both spans still highlight; only one label shows.
func TestRowAnnoSingleStrongest(t *testing.T) {
	file := &cleaveFile{Path: "x.js", FileType: "javascript", Ctx: []contextWindow{{
		Offset: 7,
		Addr:   ptrInt64(0),
		Data:   []byte("getnameinfo(); lookupAccountName();"),
		Notes: []contextNote{
			{ID: "net/resolve::getnameinfo", Desc: "Resolve endpoint with getnameinfo", Offset: 0, Size: 11, Crit: 3},
			{ID: "account/enumerate::lookup", Desc: "Enumerate account names from IDs", Offset: 15, Size: 17, Crit: 4},
		},
	}}}
	blocks := buildContextBlocksForFileView(t, file)
	if len(blocks) != 1 || len(blocks[0].Rows) != 1 {
		t.Fatalf("want one block/row, got %+v", blocks)
	}
	annos := blocks[0].Rows[0].Annos
	if len(annos) != 1 {
		t.Fatalf("want exactly one annotation on the row, got %d: %+v", len(annos), annos)
	}
	if annos[0].Desc != "Enumerate account names from IDs" || annos[0].Crit != "suspicious" {
		t.Errorf("annotation = %+v, want the stronger (suspicious) trait", annos[0])
	}
}

// TestLongLineClipsAroundMatch confirms a long minified line is clipped to a
// window holding its match, with leading/trailing ellipsis, and the match stays
// highlighted at the right place after the shift.
func TestLongLineClipsAroundMatch(t *testing.T) {
	prefix := strings.Repeat("a", 400)
	suffix := strings.Repeat("b", 400)
	line := prefix + "eval(x)" + suffix
	matchOff := int64(len(prefix))
	file := &cleaveFile{Path: "min.js", FileType: "javascript", Ctx: []contextWindow{{
		Offset: 1,
		Addr:   ptrInt64(0),
		Data:   []byte(line),
		Notes:  []contextNote{{ID: "t/x", Desc: "dynamic eval", Offset: matchOff, Size: 4, Crit: 5}},
	}}}
	blocks := buildContextBlocksForFileView(t, file)
	row := blocks[0].Rows[0]
	if !row.Lead || !row.Trail {
		t.Errorf("a match mid-line should clip both sides: lead=%v trail=%v", row.Lead, row.Trail)
	}
	var text string
	var litEval bool
	for _, s := range row.Segs {
		text += s.Text
		if s.Text == "eval" && s.Crit == "hostile" {
			litEval = true
		}
	}
	if len(text) > maxSrcCols+8 {
		t.Errorf("clipped text too long: %d chars", len(text))
	}
	if !strings.Contains(text, "eval(x)") {
		t.Errorf("clip dropped the match; got %q", text)
	}
	if !litEval {
		t.Error("the matched 'eval' should stay highlighted after the clip shift")
	}
}

// buildContextBlocksForFileView renders a file's windows the way the Content tab
// does (every note lit, inline annotations on), for tests.
func buildContextBlocksForFileView(t *testing.T, file *cleaveFile) []contextBlock {
	t.Helper()
	var out []contextBlock
	for _, lw := range labeledWindows(file) {
		out = append(out, lw.Block)
	}
	return out
}

// TestHexContextHighlights confirms a hex unit wraps into rows and lights only
// the matched bytes, with a dotted ascii gutter for non-printables.
func TestHexContextHighlights(t *testing.T) {
	data := []byte{0x90, 0x90, 0x41, 0x42, 0x00, 0x7f, 'A', 'B'}
	file := &cleaveFile{Ctx: []contextWindow{{
		Offset: 0x40,
		Hex:    true,
		Data:   data,
		Notes:  []contextNote{{ID: "t/x", Offset: 0x42, Size: 2, Crit: 4}},
	}}}
	blocks := buildContextBlocks(file, "")
	if len(blocks) != 1 || !blocks[0].Hex || len(blocks[0].Rows) != 1 {
		t.Fatalf("want one hex block/row, got %+v", blocks)
	}
	row := blocks[0].Rows[0]
	if row.Loc != "0x40" || row.Crit != "suspicious" {
		t.Errorf("loc/crit = %q/%q, want 0x40/suspicious", row.Loc, row.Crit)
	}
	if row.Segs[2].Crit != "suspicious" || row.Segs[3].Crit != "suspicious" {
		t.Errorf("bytes 2-3 should be lit: %+v", row.Segs)
	}
	if row.Segs[0].Crit != "" || row.Segs[4].Crit != "" {
		t.Error("non-matched bytes should not be lit")
	}
	if row.ASCII[0].Text != "." || row.ASCII[6].Text != "A" {
		t.Errorf("ascii gutter wrong: %q %q", row.ASCII[0].Text, row.ASCII[6].Text)
	}
}

// TestContiguousSourceLinesMerge confirms adjacent source lines collapse into a
// single block while a gap starts a new one.
func TestContiguousSourceLinesMerge(t *testing.T) {
	file := &cleaveFile{Ctx: []contextWindow{
		{Offset: 5, Addr: ptrInt64(100), Data: []byte("a")},
		{Offset: 6, Addr: ptrInt64(102), Data: []byte("b"), Notes: []contextNote{{ID: "t/x", Offset: 102, Size: 1, Crit: 3}}},
		{Offset: 20, Addr: ptrInt64(300), Data: []byte("c"), Notes: []contextNote{{ID: "t/x", Offset: 300, Size: 1, Crit: 3}}},
	}}
	blocks := buildContextBlocks(file, "")
	if len(blocks) != 2 {
		t.Fatalf("want 2 blocks (gap splits), got %d: %+v", len(blocks), blocks)
	}
	if len(blocks[0].Rows) != 2 {
		t.Errorf("first block should merge lines 5-6, got %d rows", len(blocks[0].Rows))
	}
}

// TestNoRichContextFallsBack confirms legacy text-only windows yield no blocks
// so the caller uses the inline-evidence path.
func TestNoRichContextFallsBack(t *testing.T) {
	file := &cleaveFile{Ctx: []contextWindow{{Offset: 0, Text: "ea fb 32", Hex: true}}}
	if blocks := buildContextBlocks(file, ""); blocks != nil {
		t.Errorf("legacy window should yield nil blocks, got %+v", blocks)
	}
}
