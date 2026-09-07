package main

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// maleculeTestGraph builds a graph from trait keys and severities. Edges are
// given as from->to pairs of indexes, matching cleave's uses relation.
func maleculeTestGraph(keys []string, crits []string, edges [][2]int) maleculeGraph {
	var g maleculeGraph
	for i, k := range keys {
		crit := "notable"
		if i < len(crits) {
			crit = crits[i]
		}
		cat := k
		if parts := strings.Split(k, "/"); len(parts) > 2 {
			cat = strings.Join(parts[:2], "/")
		}
		g.Atoms = append(g.Atoms, maleculeAtom{
			Key: k, Category: cat, Symbol: categorySymbol(k), Crit: crit, Members: 1,
		})
	}
	for _, e := range edges {
		g.Atoms[e[0]].Uses = append(g.Atoms[e[0]].Uses, e[1])
		g.Atoms[e[1]].UsedBy = append(g.Atoms[e[1]].UsedBy, e[0])
		g.Atoms[e[0]].IsRule = true
	}
	return g
}

var (
	maleculeCircleRE = regexp.MustCompile(`<circle cx="([\d.-]+)" cy="([\d.-]+)" r="([\d.-]+)" fill="(#[0-9a-fA-F]{6}|none|#ffffff)"`)
	maleculeDashRE   = regexp.MustCompile(`stroke-dasharray="1\.8 1\.5"`)
)

// maleculeVertices returns the drawn vertex centres — the filled atom dots and
// hollow stubs, but not the coordination shells, which are concentric with the
// centre they belong to.
func maleculeVertices(svg string) []maleculePoint {
	var out []maleculePoint
	for _, m := range maleculeCircleRE.FindAllStringSubmatch(svg, -1) {
		if m[4] == "none" {
			continue
		}
		x, errX := strconv.ParseFloat(m[1], 64)
		y, errY := strconv.ParseFloat(m[2], 64)
		if errX != nil || errY != nil {
			continue
		}
		out = append(out, maleculePoint{x, y})
	}
	return out
}

func TestMaleculeSVGEmpty(t *testing.T) {
	if got := maleculeSVG(maleculeGraph{}, 196, 168); got != "" {
		t.Errorf("empty graph drew %q, want the empty string so the card can be dropped", got)
	}
}

// The explicit hierarchy builds the skeleton: a composite nothing depends on
// is a limb, and what it uses hangs beneath it. Its bonds are full strength,
// which is what separates found structure from taxonomy fill.
func TestMaleculeSVGDrawsDependencyChain(t *testing.T) {
	g := maleculeTestGraph(
		[]string{"objectives/exfil/dns", "micro-behaviors/net/socket", "micro-behaviors/data/encode"},
		[]string{"hostile", "notable", "notable"},
		[][2]int{{0, 1}, {1, 2}},
	)
	svg := maleculeSVG(g, 196, 168)
	if n := strings.Count(svg, "<line"); n < 2 {
		t.Errorf("dependency chain drew %d bonds, want at least the 2 edges", n)
	}
	for _, key := range []string{"objectives/exfil/dns", "micro-behaviors/net/socket"} {
		if !strings.Contains(svg, key) {
			t.Errorf("drawing omits %q; every kept behaviour should be titled", key)
		}
	}
	// A taxonomy graft is drawn at reduced opacity; a pure dependency chain
	// has nothing grafted, so nothing should be faded.
	if strings.Contains(svg, `fill-opacity="0.65"`) {
		t.Error("chain drew a faded vertex, but every atom here is reachable by dependency")
	}
}

// A sample whose analysis recorded no dependencies at all still has to draw a
// molecule: the taxonomy carries it. One live sample in ten is in this state.
func TestMaleculeSVGTaxonomyFallback(t *testing.T) {
	g := maleculeTestGraph(
		[]string{
			"objectives/persistence/cron", "micro-behaviors/fs/path",
			"micro-behaviors/fs/chmod", "metadata/file/profile",
		},
		[]string{"suspicious", "notable", "notable", "baseline"},
		nil,
	)
	svg := maleculeSVG(g, 196, 168)
	if svg == "" {
		t.Fatal("graph with no dependency edges drew nothing")
	}
	if got := len(maleculeVertices(svg)); got < 4 {
		t.Errorf("drew %d vertices, want at least the 4 behaviours plus their stubs", got)
	}
	// Everything here arrived by taxonomy, so the fill must read as secondary.
	if !strings.Contains(svg, `fill-opacity="0.65"`) {
		t.Error("taxonomy-grafted atoms should be drawn faded, to rank below found structure")
	}
}

// A behaviour two rules share is the one relation the spanning tree cannot
// hold. It becomes a coordination centre: a shell, plus a dashed bond from the
// user the tree did not already connect it to.
func TestMaleculeSVGCoordinationCentre(t *testing.T) {
	g := maleculeTestGraph(
		[]string{
			"objectives/exfil/dns", "objectives/credential-access/browser",
			"micro-behaviors/net/socket",
		},
		[]string{"hostile", "hostile", "notable"},
		[][2]int{{0, 2}, {1, 2}}, // both rules need the socket
	)
	svg := maleculeSVG(g, 196, 168)
	if n := len(maleculeDashRE.FindAllString(svg, -1)); n != 1 {
		t.Errorf("drew %d coordination bonds, want exactly 1: the tree already draws the other user", n)
	}
	if !strings.Contains(svg, `fill="none"`) {
		t.Error("a coordination centre should carry a shell")
	}
}

// The duplicate-bond regression: a hub's parent in the spanning tree is one of
// its users and is already drawn solid, so a dashed bond to it repeats a line
// that is there. Half the coordination ink used to be that repeat.
func TestMaleculeSVGSkipsRedundantCoordinationBond(t *testing.T) {
	g := maleculeTestGraph(
		[]string{"objectives/exfil/dns", "micro-behaviors/net/socket"},
		[]string{"hostile", "notable"},
		[][2]int{{0, 1}},
	)
	g.Atoms[1].UsedBy = append(g.Atoms[1].UsedBy, 0) // seen twice, still one user
	if n := len(maleculeDashRE.FindAllString(maleculeSVG(g, 196, 168), -1)); n != 0 {
		t.Errorf("drew %d coordination bonds for a behaviour with a single user, want 0", n)
	}
}

// Crowding regression. A small molecule where most behaviours are shared used
// to draw four overlapping shells and put vertices 2.5px apart carrying 2.6px
// dots. The hub cap, the wedge rule and the relaxation pass are what hold it
// open; this fails if any of them regresses.
func TestMaleculeSVGKeepsVerticesApart(t *testing.T) {
	keys := []string{
		"objectives/exfil/dns", "objectives/persistence/cron", "objectives/discovery/host",
		"micro-behaviors/net/socket", "micro-behaviors/fs/path", "micro-behaviors/os/exec",
		"micro-behaviors/data/encode", "metadata/file/profile",
	}
	crits := []string{"hostile", "hostile", "suspicious", "notable", "notable", "notable", "notable", "baseline"}
	edges := [][2]int{{0, 3}, {1, 3}, {2, 3}, {0, 4}, {1, 4}, {2, 5}, {0, 5}, {1, 6}, {2, 6}}
	g := maleculeTestGraph(keys, crits, edges)

	for _, size := range []struct {
		name          string
		w, h, wantSep float64
	}{
		{"detail", 196, 168, 4.2},
		{"row", 132, 62, 3.4},
	} {
		pts := maleculeVertices(maleculeSVG(g, size.w, size.h))
		worst, wi, wj := math.Inf(1), 0, 0
		for i := range pts {
			for j := i + 1; j < len(pts); j++ {
				if d := math.Hypot(pts[i].X-pts[j].X, pts[i].Y-pts[j].Y); d < worst {
					worst, wi, wj = d, i, j
				}
			}
		}
		if worst < size.wantSep {
			t.Errorf("%s: closest vertices %.2fpx apart (want >= %.1f), at %v and %v",
				size.name, worst, size.wantSep, pts[wi], pts[wj])
		}
	}
}

// A small molecule must not be mostly coordination centres, or the shells
// swallow vertices that have nothing to do with them.
func TestMaleculeSVGCapsCoordinationCentres(t *testing.T) {
	keys := []string{
		"objectives/a/one", "objectives/b/two", "objectives/c/three", "objectives/d/four",
		"micro-behaviors/x/p", "micro-behaviors/x/q", "micro-behaviors/x/r", "micro-behaviors/x/s",
	}
	// Every micro-behaviour is shared by two objectives, so all four qualify.
	edges := [][2]int{
		{0, 4}, {1, 4}, {0, 5}, {1, 5}, {2, 6}, {3, 6}, {2, 7}, {3, 7},
	}
	g := maleculeTestGraph(keys, nil, edges)
	shells := strings.Count(maleculeSVG(g, 196, 168), `fill="none"`)
	if shells > 2 {
		t.Errorf("drew %d coordination shells for 8 behaviours, want at most 2 (one per %d atoms)",
			shells, maleculeHubAtoms)
	}
}

// Past the budget the drawing stops being read and starts being decoration, so
// the remainder is counted rather than drawn. Live samples reach 163
// behaviours.
func TestMaleculeSVGBudgetsAtoms(t *testing.T) {
	var keys []string
	for i := range 60 {
		keys = append(keys, "micro-behaviors/fs/path"+strconv.Itoa(i))
	}
	g := maleculeTestGraph(keys, nil, nil)

	detail := maleculeSVG(g, 196, 168)
	if want := "+" + strconv.Itoa(60-maleculeDetailBudget); !strings.Contains(detail, want) {
		t.Errorf("detail card should count the %s behaviours it did not draw", want)
	}
	row := maleculeSVG(g, 132, 62)
	if want := "+" + strconv.Itoa(60-maleculeRowBudget); !strings.Contains(row, want) {
		t.Errorf("feed row should count the %s behaviours it did not draw", want)
	}
	// The row is a glance, not a document: no labels at that size.
	if strings.Contains(row, "<text x=") && strings.Contains(row, "font-weight=\"600\"") {
		t.Error("feed row drew element labels; there is no room for them at 132x62")
	}
}

// The same report must always draw the same molecule — the picture is cached
// with the page, and a drawing that shuffled between renders would read as the
// sample having changed.
func TestMaleculeSVGDeterministic(t *testing.T) {
	g := maleculeTestGraph(
		[]string{
			"objectives/exfil/dns", "objectives/persistence/cron",
			"micro-behaviors/net/socket", "micro-behaviors/fs/path", "metadata/file/profile",
		},
		[]string{"hostile", "suspicious", "notable", "notable", "baseline"},
		[][2]int{{0, 2}, {1, 2}, {1, 3}},
	)
	first := maleculeSVG(g, 196, 168)
	for range 5 {
		if got := maleculeSVG(g, 196, 168); got != first {
			t.Fatal("maleculeSVG is not deterministic for one graph")
		}
	}
}

// Both pages run this renderer, and a feed row is the same molecule drawn
// smaller — not a different picture.
func TestMaleculeSVGRendersBothSizes(t *testing.T) {
	g := maleculeTestGraph(
		[]string{"objectives/exfil/dns", "micro-behaviors/net/socket", "metadata/file/profile"},
		[]string{"hostile", "notable", "baseline"},
		[][2]int{{0, 1}},
	)
	for _, size := range []struct{ w, h float64 }{{196, 168}, {132, 62}} {
		svg := maleculeSVG(g, size.w, size.h)
		if !strings.HasPrefix(svg, "<svg viewBox=") || !strings.HasSuffix(svg, "</svg>") {
			t.Errorf("%.0fx%.0f: malformed svg", size.w, size.h)
		}
		if want := "viewBox=\"0 0 " + strconv.Itoa(int(size.w)) + " " + strconv.Itoa(int(size.h)) + "\""; !strings.Contains(svg, want) {
			t.Errorf("%.0fx%.0f: missing %s", size.w, size.h, want)
		}
	}
}

// The row splits the circle: what the report reasoned its way to goes above
// the core, the taxonomy graft below it. Interleaved, the graft's larger
// population buries the dependency limbs and a page of samples that share a
// file type comes out as a page of the same sunburst.
func TestMaleculeSVGRowSplitsDependenciesFromTaxonomy(t *testing.T) {
	g := maleculeTestGraph(
		[]string{
			"objectives/exfil/dns", "micro-behaviors/net/socket", "micro-behaviors/net/dns",
			"objectives/discovery/host", "objectives/collection/screenshot",
			"micro-behaviors/fs/write", "metadata/file/profile",
		},
		[]string{"hostile", "suspicious", "suspicious", "notable", "notable", "notable", "baseline"},
		[][2]int{{0, 1}, {1, 2}},
	)
	const w, h = 132, 62
	svg := maleculeSVG(g, w, h)
	above, below := 0, 0
	for _, p := range maleculeVertices(svg) {
		if math.Abs(p.Y-h/2) < 0.5 {
			continue // the core itself
		}
		if p.Y < h/2 {
			above++
		} else {
			below++
		}
	}
	if above == 0 || below == 0 {
		t.Fatalf("row drew %d vertices above the core and %d below; want both halves used", above, below)
	}
	// The dependency chain is three atoms deep and the graft has four leaves,
	// so a drawing that split by anything but kind would not land 3 above.
	if above != 3 {
		t.Errorf("above the core = %d vertices, want the 3 of the dependency chain", above)
	}
}

// A molecule with nothing to separate keeps the whole circle: half a drawing
// would say something about the sample that is not true.
func TestMaleculeSVGRowKeepsWholeCircleWithoutGraft(t *testing.T) {
	g := maleculeTestGraph(
		[]string{"objectives/exfil/dns", "micro-behaviors/net/socket", "micro-behaviors/net/dns"},
		[]string{"hostile", "suspicious", "suspicious"},
		[][2]int{{0, 1}, {0, 2}},
	)
	const w, h = 132, 62
	below := 0
	for _, p := range maleculeVertices(maleculeSVG(g, w, h)) {
		if p.Y > h/2+0.5 {
			below++
		}
	}
	if below == 0 {
		t.Error("an all-dependency molecule was squeezed into the top half")
	}
}

// Bond lengths come from depth and from the arc a child needs, neither of
// which knows how far the deepest limb ended up — so the finished layout is
// scaled to the frame rather than trusted to have landed inside it.
func TestMaleculeSVGStaysInsideTheFrame(t *testing.T) {
	keys := make([]string, 0, 24)
	crits := make([]string, 0, 24)
	edges := make([][2]int, 0, 12)
	for i := range 24 {
		keys = append(keys, "objectives/exfil/dns"+strconv.Itoa(i))
		crits = append(crits, "hostile")
		if i > 0 && i%2 == 0 {
			edges = append(edges, [2]int{i - 2, i})
		}
	}
	g := maleculeTestGraph(keys, crits, edges)
	for _, size := range []struct{ w, h float64 }{{196, 168}, {132, 62}} {
		for _, p := range maleculeVertices(maleculeSVG(g, size.w, size.h)) {
			if p.X < 0 || p.X > size.w || p.Y < 0 || p.Y > size.h {
				t.Errorf("%.0fx%.0f: vertex (%.1f, %.1f) fell outside the frame", size.w, size.h, p.X, p.Y)
			}
		}
	}
}
