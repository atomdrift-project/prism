package main

import "testing"

func ptrInt(v int) *int { p := v; return &p }

// TestFileViewsNativeVsInherited locks in the archive rule: only native
// findings (Src == nil) show on a file; inherited ones are omitted (they render
// in their origin member). A cross-file composite shows with a linkable member
// trail, and files order by criticality.
func TestFileViewsNativeVsInherited(t *testing.T) {
	files := []cleaveFile{
		{ // archive container
			ID: 0, Depth: 0, SHA256: "aaa", Path: "app.zip", FileType: "zip",
			Findings: []finding{
				// native cross-file composite aimed at the archive
				{
					ID: "objectives/c2/beacon", Crit: 4, Conf: 0.9,
					Sources: []compactSource{{File: 1, Line: ptrInt64(10)}},
				},
				// inherited atomic — must NOT render on the container
				{ID: "objectives/execution/eval", Crit: 5, Conf: 0.9, Src: ptrInt(1)},
			},
			Ctx: []contextWindow{{Offset: 0, Hex: true, Data: []byte{0x90}}},
		},
		{ // member
			ID: 1, Depth: 1, SHA256: "bbb", Path: "app.zip!!main.py", FileType: "python",
			Findings: []finding{
				{ID: "objectives/execution/eval", Crit: 5, Conf: 0.9},
			},
			Ctx: []contextWindow{{
				Offset: 3, Addr: ptrInt64(40), Data: []byte("eval(x)"),
				Notes: []contextNote{{ID: "objectives/execution/eval", Offset: 40, Size: 4, Crit: 5}},
			}},
		},
	}

	views := buildFileViews(files)
	if len(views) != 2 {
		t.Fatalf("want 2 file views, got %d: %+v", len(views), views)
	}
	// Highest-criticality file (member, crit 5) leads, with a labeled window.
	if views[0].SHA256 != "bbb" {
		t.Errorf("first view = %q, want member bbb (crit 5)", views[0].SHA256)
	}
	if len(views[0].Windows) != 1 {
		t.Fatalf("member should have one window, got %d", len(views[0].Windows))
	}
	// The trait labels the line inline; with no description it falls back to the
	// short trait id.
	if annos := windowAnnos(views[0].Windows[0]); len(annos) != 1 || annos[0] != "execution/eval" {
		t.Errorf("member window annotations = %v, want [execution/eval]", annos)
	}

	// The container shows only its native composite (no window), never the
	// inherited atomic, with a linkable member trail.
	c := views[1]
	if c.SHA256 != "aaa" || len(c.Windows) != 0 || len(c.Composites) != 1 {
		t.Fatalf("container view = %+v, want one composite and no windows", c)
	}
	if c.Composites[0].ID != "c2/beacon" {
		t.Errorf("container composite = %q, want c2/beacon", c.Composites[0].ID)
	}
	src := c.Composites[0].Sources
	if len(src) != 1 || src[0].Label != "main.py" || src[0].Anchor != "file-bbb" || src[0].Loc != "10" {
		t.Errorf("composite trail = %+v, want main.py @ file-bbb:10", src)
	}
}

// TestFileViewsDropsContextless confirms cleave's model: a finding whose match
// was overlap-deduped (no context window, no composite sources) is dropped
// rather than shown as a bare row, while a located trait in the same file stays.
func TestFileViewsDropsContextless(t *testing.T) {
	file := cleaveFile{
		ID: 0, Depth: 0, SHA256: "aaa", Path: "x.js", FileType: "javascript",
		Findings: []finding{
			// located: has a context note
			{ID: "objectives/execution/eval", Crit: 5, Conf: 0.9},
			// overlap-deduped: no note in ctx, no sources → must be dropped
			{ID: "fs/write/file/direct", Crit: 4, Conf: 0.9},
		},
		Ctx: []contextWindow{{
			Offset: 1, Addr: ptrInt64(0), Data: []byte("eval(x)"),
			Notes: []contextNote{{ID: "objectives/execution/eval", Offset: 0, Size: 4, Crit: 5}},
		}},
	}
	views := buildFileViews([]cleaveFile{file})
	if len(views) != 1 {
		t.Fatalf("want 1 view, got %d", len(views))
	}
	if len(views[0].Windows) != 1 || len(views[0].Composites) != 0 {
		t.Fatalf("want one window and no context-less rows, got %+v", views[0])
	}
	if annos := windowAnnos(views[0].Windows[0]); len(annos) != 1 || annos[0] != "execution/eval" {
		t.Errorf("want only the located trait annotated; got %v", annos)
	}
}

// windowAnnos flattens the trait annotations across a window's rows for tests.
func windowAnnos(w fileWindow) []string {
	var out []string
	for _, b := range w.Blocks {
		for _, r := range b.Rows {
			for _, a := range r.Annos {
				out = append(out, a.Desc)
			}
		}
	}
	return out
}

// TestFileViewsNoContextNil confirms a legacy report with no current-format
// context yields no File tab, so the page keeps Traits as its default.
func TestFileViewsNoContextNil(t *testing.T) {
	files := []cleaveFile{{
		ID: 0, Depth: 0, SHA256: "aaa", Path: "x.py",
		Findings: []finding{{ID: "objectives/execution/eval", Crit: 5, Conf: 0.9}},
	}}
	if views := buildFileViews(files); views != nil {
		t.Errorf("no rich context should yield nil views, got %+v", views)
	}
}
