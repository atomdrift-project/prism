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
	// Highest-criticality file (member, crit 5) leads.
	if views[0].SHA256 != "bbb" {
		t.Errorf("first view = %q, want member bbb (crit 5)", views[0].SHA256)
	}
	if len(views[0].Findings) != 1 || views[0].Findings[0].ID != "execution/eval" {
		t.Errorf("member finding = %+v, want execution/eval", views[0].Findings)
	}
	if len(views[0].Findings[0].Context) == 0 {
		t.Error("member finding should carry source context")
	}

	// The container shows only its native composite, never the inherited atomic.
	c := views[1]
	if c.SHA256 != "aaa" || len(c.Findings) != 1 {
		t.Fatalf("container view = %+v, want one native finding", c)
	}
	if c.Findings[0].ID != "c2/beacon" {
		t.Errorf("container finding = %q, want the native composite c2/beacon", c.Findings[0].ID)
	}
	src := c.Findings[0].Sources
	if len(src) != 1 || src[0].Label != "main.py" || src[0].Anchor != "file-bbb" || src[0].Loc != "line 10" {
		t.Errorf("composite trail = %+v, want main.py @ file-bbb line 10", src)
	}
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
