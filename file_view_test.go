package main

import "testing"

// TestFileViewsNativeVsInherited locks in the archive rule: only native
// findings (Src == nil) show on a file; inherited ones are omitted (they render
// in their origin member). A cross-file composite shows with a linkable member
// trail, and files order by criticality.
func TestFileViewsNativeVsInherited(t *testing.T) {
	files := []cleaveFile{
		{ // archive container
			ID: 0, Depth: 0, SHA256: "aaa", Path: "app.zip", FileType: "zip",
			Findings: []finding{
				// native cross-file composite aimed at the archive (multi-member From)
				{
					ID: "objectives/c2/beacon", Crit: 4, Conf: 0.9,
					From: []compactSource{{File: 1, Line: ptrInt64(10)}, {File: 2, Line: ptrInt64(3)}},
				},
				// inherited atomic (single-member From) — must NOT render on the container
				{ID: "objectives/execution/eval", Crit: 5, Conf: 0.9, From: []compactSource{{File: 1}}},
			},
			Ctx: []contextWindow{{Offset: 0, Data: []byte{0x90}}},
		},
		{ // member
			ID: 1, Depth: 1, SHA256: "bbb", Path: "app.zip!!main.py", FileType: "python",
			Findings: []finding{
				{ID: "objectives/execution/eval", Crit: 5, Conf: 0.9, Spans: [][2]int64{{40, 4}}},
			},
			Ctx: []contextWindow{{
				Offset: 3, Addr: ptrInt64(40), Data: []byte("eval(x)"),
			}},
		},
	}

	views, _ := buildFileViews(files)
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

// TestFileViewsInheritedSpanNoFalseAnno is the v8 archive regression: a
// container's findings are rollups inherited from members, carrying
// member-relative spans, while the container's own ctx is only a short header
// sample of the compressed stream. A member-relative span that happens to land
// within that sample's byte range must NOT light the container's header line
// (e.g. an inner test fixture's "Arabic script" note annotating the gzip
// header). The container shows no window; the member is attributed elsewhere.
func TestFileViewsInheritedSpanNoFalseAnno(t *testing.T) {
	files := []cleaveFile{
		{ // archive container: ctx is a 4-byte header sample at offset 0
			ID: 0, Depth: 0, SHA256: "aaa", Path: "src.tar.gz", FileType: "tar.gz",
			Findings: []finding{
				// inherited from a member; span [19,10] is relative to the
				// member's bytes but overlaps the container's [0,33) sample.
				{
					ID:   "metadata/file/profile/language::lang-arabic-urdu",
					Crit: 1, Conf: 0.9, Desc: "Arabic script detection (Arabic/Urdu)",
					From:  []compactSource{{File: 1}},
					Spans: [][2]int64{{19, 10}},
				},
			},
			Ctx: []contextWindow{{Offset: 0, Data: []byte{0x1f, 0x8b, 0x08, 0x00}}},
		},
		{ // member: content omitted by the envelope, so no ctx
			ID: 1, Depth: 1, SHA256: "bbb",
			Path: "src.tar.gz!!tests/fixtures/unicode/input.md", FileType: "markdown",
		},
	}

	views, _ := buildFileViews(files)
	for _, v := range views {
		if len(v.Windows) != 0 {
			t.Fatalf("no file should render a window (container=header sample, member=no ctx); got %+v", v)
		}
	}
}

// TestFileViewsDropsContextless confirms cleave's model: a finding whose match
// was overlap-deduped (no context window, no composite sources) is dropped
// rather than shown as a bare row, while a located trait in the same file stays.
func TestFileViewsDropsContextless(t *testing.T) {
	file := cleaveFile{
		ID: 0, Depth: 0, SHA256: "aaa", Path: "x.js", FileType: "javascript",
		Findings: []finding{
			// located: a span lands in the window below
			{ID: "objectives/execution/eval", Crit: 5, Conf: 0.9, Spans: [][2]int64{{0, 4}}},
			// overlap-deduped: no span in ctx, no sources → must be dropped
			{ID: "fs/write/file/direct", Crit: 4, Conf: 0.9},
		},
		Ctx: []contextWindow{{
			Offset: 1, Addr: ptrInt64(0), Data: []byte("eval(x)"),
		}},
	}
	views, _ := buildFileViews([]cleaveFile{file})
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

// TestFileViewsFileCap confirms the Content tab shows at most maxFilesShown
// files (by criticality) and reports the omitted files and their results.
func TestFileViewsFileCap(t *testing.T) {
	total := maxFilesShown + 3
	files := make([]cleaveFile, 0, total)
	for i := range total {
		sha := "sha" + itoaTest(i)
		// Higher index → higher criticality, so the first maxFilesShown by
		// criticality are the last ones built; the rest are omitted.
		crit := 3 + i%3
		files = append(files, cleaveFile{
			ID: i, Depth: 1, SHA256: sha, Path: "a.zip!!f" + itoaTest(i) + ".py", FileType: "python",
			Findings: []finding{{ID: "objectives/execution/eval", Crit: crit, Conf: 0.9, Spans: [][2]int64{{0, 4}}}},
			Ctx: []contextWindow{{
				Offset: 1, Addr: ptrInt64(0), Data: []byte("eval(x)"),
			}},
		})
	}
	views, omitted := buildFileViews(files)
	if len(views) != maxFilesShown {
		t.Errorf("rendered %d files, want the cap of %d", len(views), maxFilesShown)
	}
	if omitted.Files != total-maxFilesShown {
		t.Errorf("omitted.Files = %d, want %d", omitted.Files, total-maxFilesShown)
	}
	// Each omitted file held exactly one window (one result).
	if omitted.Results != total-maxFilesShown {
		t.Errorf("omitted.Results = %d, want %d", omitted.Results, total-maxFilesShown)
	}
}

// TestFileViewsNoContextNil confirms a legacy report with no current-format
// context yields no File tab, so the page keeps Traits as its default.
func TestFileViewsNoContextNil(t *testing.T) {
	files := []cleaveFile{{
		ID: 0, Depth: 0, SHA256: "aaa", Path: "x.py",
		Findings: []finding{{ID: "objectives/execution/eval", Crit: 5, Conf: 0.9}},
	}}
	if views, _ := buildFileViews(files); views != nil {
		t.Errorf("no rich context should yield nil views, got %+v", views)
	}
}

// TestFileViewsDropsLowCritMembers confirms archive members below the content
// criticality floor (component/filtered) get no content view, while the depth-0
// file and members at/above the floor still render.
func TestFileViewsDropsLowCritMembers(t *testing.T) {
	mk := func(id, depth, crit int, sha string) cleaveFile {
		return cleaveFile{
			ID: id, Depth: depth, SHA256: sha, Path: "a.zip!!f" + itoaTest(id) + ".py", FileType: "python",
			Findings: []finding{{ID: "objectives/execution/eval", Crit: crit, Conf: 0.9, Spans: [][2]int64{{0, 4}}}},
			Ctx: []contextWindow{{
				Offset: 1, Addr: ptrInt64(0), Data: []byte("eval(x)"),
			}},
		}
	}
	files := []cleaveFile{
		mk(0, 0, 1, "container"),  // depth-0 container, low crit — always shown
		mk(1, 1, 1, "lowmember"),  // component (crit 1) member — dropped
		mk(2, 1, 3, "highmember"), // notable (crit 3) member — kept
	}
	views, _ := buildFileViews(files)
	shown := make(map[string]bool, len(views))
	for _, v := range views {
		shown[v.SHA256] = true
	}
	if !shown["container"] {
		t.Error("depth-0 file should always render content regardless of crit")
	}
	if shown["lowmember"] {
		t.Error("archive member below the content-crit floor should be dropped")
	}
	if !shown["highmember"] {
		t.Error("archive member at/above the content-crit floor should render")
	}
}
