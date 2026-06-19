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

	views, top, _ := buildFileViews(files)
	// Only the member renders a section (it has a window); the container has no
	// window of its own, so it is not a file card — composite cards are gone.
	if len(views) != 1 || views[0].SHA256 != "bbb" {
		t.Fatalf("want one file view (member bbb), got %+v", views)
	}
	if len(views[0].Windows) != 1 {
		t.Fatalf("member should have one window, got %d", len(views[0].Windows))
	}
	// The trait labels the line inline; with no description it falls back to the
	// short trait id.
	if annos := windowAnnos(views[0].Windows[0]); len(annos) != 1 || annos[0] != "execution/eval" {
		t.Errorf("member window annotations = %v, want [execution/eval]", annos)
	}

	// The cross-file composite (suspicious) now surfaces in the top-traits
	// headline with its linkable member trail, not as a bare card. (The hostile
	// eval also headlines; we only assert the composite's trail here.)
	var beacon *topTrait
	for i := range top {
		if top[i].Desc == "c2/beacon" {
			beacon = &top[i]
		}
	}
	if beacon == nil {
		t.Fatalf("top traits = %+v, want one to be the c2/beacon composite", top)
	}
	if src := beacon.Sources; len(src) != 1 ||
		src[0].Label != "main.py" || src[0].Anchor != "file-bbb" || src[0].Loc != "10" {
		t.Errorf("composite trail = %+v, want main.py @ file-bbb:10", beacon.Sources)
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

	views, _, _ := buildFileViews(files)
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
	views, _, _ := buildFileViews([]cleaveFile{file})
	if len(views) != 1 {
		t.Fatalf("want 1 view, got %d", len(views))
	}
	if len(views[0].Windows) != 1 {
		t.Fatalf("want one window and no context-less rows, got %+v", views[0])
	}
	if annos := windowAnnos(views[0].Windows[0]); len(annos) != 1 || annos[0] != "execution/eval" {
		t.Errorf("want only the located trait annotated; got %v", annos)
	}
}

// TestFileViewsCompositePromotesMembers locks the cross-file composite contract:
// every leg's member renders its own window even below the content floor, the
// primary leg (From[0]) carries the composite description inline, the other legs
// keep the native trait that fired there, and the composite trail links to both.
func TestFileViewsCompositePromotesMembers(t *testing.T) {
	files := []cleaveFile{
		{ // archive container holds the cross-file composite
			ID: 0, Depth: 0, SHA256: "aaa", Path: "wheel.whl", FileType: "zip",
			Findings: []finding{
				{
					ID: "micro-behaviors/net/http-client", Crit: 3, Conf: 0.9,
					Desc: "Performs HTTP request",
					From: []compactSource{{File: 1, Line: ptrInt64(12)}, {File: 2, Line: ptrInt64(31)}},
				},
			},
			Ctx: []contextWindow{{Offset: 0, Data: []byte{0x50, 0x4b}}},
		},
		{ // primary leg: crit 1 on its own (below the floor), force-rendered
			ID: 1, Depth: 1, SHA256: "bbb", Path: "wheel.whl!!gpfs_client.py", FileType: "python",
			Findings: []finding{
				{ID: "micro-behaviors/net/http-client", Crit: 1, Conf: 0.9, Desc: "http client", Spans: [][2]int64{{1, 12}}},
			},
			Ctx: []contextWindow{{Offset: 12, Addr: ptrInt64(0), Data: []byte("requests.get(u)")}},
		},
		{ // secondary leg: keeps its native trait label
			ID: 2, Depth: 1, SHA256: "ccc", Path: "wheel.whl!!weka_client.py", FileType: "python",
			Findings: []finding{
				{ID: "micro-behaviors/net/http-client", Crit: 1, Conf: 0.9, Desc: "http client", Spans: [][2]int64{{1, 10}}},
			},
			Ctx: []contextWindow{{Offset: 31, Addr: ptrInt64(0), Data: []byte("httpx.post(e)")}},
		},
	}

	views, _, _ := buildFileViews(files)

	bySHA := make(map[string]fileView, len(views))
	for _, v := range views {
		bySHA[v.SHA256] = v
	}
	// Both legs render their own section; the container (no window of its own) is
	// not a card. The composite is folded into the source view, not shown as a
	// card.
	if len(views) != 2 {
		t.Fatalf("want 2 views (both legs), got %d: %+v", len(views), views)
	}
	if _, ok := bySHA["aaa"]; ok {
		t.Errorf("container should not render a section (no window of its own)")
	}

	// Primary leg renders, annotated with the composite description folded onto
	// the row at its leg location (not its own low-crit native trait).
	primary, ok := bySHA["bbb"]
	if !ok || len(primary.Windows) != 1 {
		t.Fatalf("primary leg bbb = %+v, want one window", primary)
	}
	if annos := windowAnnos(primary.Windows[0]); len(annos) != 1 || annos[0] != "Performs HTTP request" {
		t.Errorf("primary leg annotations = %v, want [Performs HTTP request]", annos)
	}

	// Secondary leg renders too, keeping the native trait that fired there.
	secondary, ok := bySHA["ccc"]
	if !ok || len(secondary.Windows) != 1 {
		t.Fatalf("secondary leg ccc = %+v, want one window", secondary)
	}
	if annos := windowAnnos(secondary.Windows[0]); len(annos) != 1 || annos[0] != "http client" {
		t.Errorf("secondary leg annotations = %v, want [http client]", annos)
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
			// Span off byte 0 so the offset-0 sub-suspicious noise filter doesn't
			// touch these fixtures — this test exercises the file cap, not that.
			Findings: []finding{{ID: "objectives/execution/eval", Crit: crit, Conf: 0.9, Spans: [][2]int64{{1, 4}}}},
			Ctx: []contextWindow{{
				Offset: 1, Addr: ptrInt64(0), Data: []byte("eval(x)"),
			}},
		})
	}
	views, _, omitted := buildFileViews(files)
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

// TestOffsetZeroNoiseFiltered locks the offset-0 noise rule: a sub-suspicious
// trait whose match sits at byte 0 (a format/whole-file marker like a zip's "PK"
// header) is dropped from the content view, while a suspicious+ trait at byte 0,
// or a sub-suspicious trait off byte 0, is kept.
func TestOffsetZeroNoiseFiltered(t *testing.T) {
	file := cleaveFile{
		ID: 0, Depth: 0, SHA256: "aaa", Path: "app.zip", FileType: "zip",
		Findings: []finding{
			{ID: "metadata/library/web-frameworks::bundle-marker", Crit: 2, Conf: 0.9, Desc: "bundle marker", Spans: [][2]int64{{0, 4}}},
			{ID: "objectives/execution/eval", Crit: 5, Conf: 0.9, Desc: "eval", Spans: [][2]int64{{0, 4}}},
		},
		Ctx: []contextWindow{{Offset: 1, Addr: ptrInt64(0), Data: []byte("PK\x03\x04eval")}},
	}
	views, top, _ := buildFileViews([]cleaveFile{file})
	if len(views) != 1 {
		t.Fatalf("want one view, got %d", len(views))
	}
	annos := windowAnnos(views[0].Windows[0])
	for _, a := range annos {
		if a == "bundle marker" {
			t.Errorf("offset-0 sub-suspicious trait should be filtered; annos=%v", annos)
		}
	}
	// The suspicious+ trait at offset 0 survives and headlines, with a clickable
	// location pointing back at the file's own section.
	if len(top) != 1 || top[0].Desc != "eval" {
		t.Fatalf("top traits = %+v, want [eval]", top)
	}
	if src := top[0].Sources; len(src) != 1 || src[0].Label != "app.zip" || src[0].Anchor != "file-aaa" {
		t.Errorf("eval source = %+v, want app.zip @ file-aaa", top[0].Sources)
	}
}

// TestFileViewsNoContextNil confirms a legacy report with no current-format
// context yields no File tab, so the page keeps Traits as its default.
func TestFileViewsNoContextNil(t *testing.T) {
	files := []cleaveFile{{
		ID: 0, Depth: 0, SHA256: "aaa", Path: "x.py",
		Findings: []finding{{ID: "objectives/execution/eval", Crit: 5, Conf: 0.9}},
	}}
	if views, _, _ := buildFileViews(files); views != nil {
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
			// Span off byte 0 so the offset-0 sub-suspicious noise filter doesn't
			// interfere — this test exercises the content-criticality floor.
			Findings: []finding{{ID: "objectives/execution/eval", Crit: crit, Conf: 0.9, Spans: [][2]int64{{1, 4}}}},
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
	views, _, _ := buildFileViews(files)
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
