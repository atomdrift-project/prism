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
	// A sphere is the only <circle> the drawing emits; the specular highlight
	// is an <ellipse> and there are no rings or shells any more.
	maleculeSphereRE = regexp.MustCompile(
		`<circle cx="([\d.-]+)" cy="([\d.-]+)" r="([\d.-]+)" fill="url\(#m[0-9a-f]{8}([a-z]+)(\d)\)"`)
	maleculeLineRE = regexp.MustCompile(`<line [^>]*?/>`)
)

func maleculeSpheres(svg string) []maleculePoint {
	var out []maleculePoint
	for _, m := range maleculeSphereRE.FindAllStringSubmatch(svg, -1) {
		x, errX := strconv.ParseFloat(m[1], 64)
		y, errY := strconv.ParseFloat(m[2], 64)
		if errX != nil || errY != nil {
			continue
		}
		out = append(out, maleculePoint{x, y})
	}
	return out
}

// maleculeBonds counts the strokes the drawing laid down, split by whether
// they are dashed. A dependency is a solid double bond — two offset sticks,
// each drawn as a shaded half and a lit core, so eight solid strokes. A family
// link is one dashed stroke.
func maleculeBonds(svg string) (solid, dashed int) {
	for _, l := range maleculeLineRE.FindAllString(svg, -1) {
		if strings.Contains(l, "stroke-dasharray") {
			dashed++
			continue
		}
		solid++
	}
	return solid, dashed
}

func TestMaleculeSVGEmpty(t *testing.T) {
	if got := maleculeSVG(maleculeGraph{}, 196, 168); got != "" {
		t.Errorf("empty graph drew %q, want the card dropped", got)
	}
}

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
		want := `viewBox="0 0 ` + strconv.Itoa(int(size.w)) + ` ` + strconv.Itoa(int(size.h)) + `"`
		if !strings.Contains(svg, want) {
			t.Errorf("%.0fx%.0f: missing %s", size.w, size.h, want)
		}
		if n := len(maleculeSpheres(svg)); n != len(g.Atoms) {
			t.Errorf("%.0fx%.0f: drew %d spheres, want %d", size.w, size.h, n, len(g.Atoms))
		}
	}
}

// The shipped bond rule: a dependency is a covalent double bond, a family link
// is a dashed contact. Both channels differ — count and continuity — because
// the family links are the larger population and one channel alone stops
// separating them at row size.
func TestMaleculeSVGDrawsBothBondKinds(t *testing.T) {
	// Two behaviours in one family (share 3) plus one dependency between
	// atoms that share nothing.
	g := maleculeTestGraph(
		[]string{"objectives/exfil/dns", "micro-behaviors/net/socket", "micro-behaviors/net/http"},
		[]string{"hostile", "notable", "notable"},
		[][2]int{{0, 1}},
	)
	svg := maleculeSVG(g, 196, 168)
	solid, dashed := maleculeBonds(svg)
	if want := 8; solid != want {
		t.Errorf("one dependency drew %d solid strokes, want %d (a double bond, shaded and lit)",
			solid, want)
	}
	if want := 1; dashed != want {
		t.Errorf("one family link drew %d dashed strokes, want %d", dashed, want)
	}
}

// A shared namespace is too loose a claim to spend a line on: the spring still
// gathers the two atoms, but nothing is drawn between them.
func TestMaleculeSVGSkipsNamespaceOnlyKinship(t *testing.T) {
	g := maleculeTestGraph(
		[]string{"micro-behaviors/net/socket", "micro-behaviors/fs/write"},
		[]string{"notable", "notable"},
		nil,
	)
	if _, dashed := maleculeBonds(maleculeSVG(g, 196, 168)); dashed != 0 {
		t.Errorf("atoms sharing only a namespace drew %d contacts, want none", dashed)
	}
}

// Depth is the verdict, so nothing may be painted in front of the worst
// finding — including a label, which is where this went wrong before. The
// worst atom here is deliberately not an objective: ranking depth by namespace
// instead of by severity is exactly what used to bury it.
func TestMaleculeSVGPaintsWorstAtomLast(t *testing.T) {
	g := maleculeTestGraph(
		[]string{
			"objectives/exfil/dns", "objectives/persistence/cron", "objectives/discovery/host",
			"well-known/malware/backdoor",
			"micro-behaviors/net/socket", "micro-behaviors/fs/write",
		},
		[]string{"notable", "notable", "notable", "hostile", "notable", "notable"},
		[][2]int{{0, 4}, {1, 5}},
	)
	for _, size := range []struct{ w, h float64 }{{196, 168}, {132, 62}} {
		svg := maleculeSVG(g, size.w, size.h)
		last := strings.LastIndex(svg, "<circle")
		if last < 0 {
			t.Fatalf("%.0fx%.0f: no spheres drawn", size.w, size.h)
		}
		if want := "<title>well-known/malware/backdoor</title>"; !strings.Contains(svg[last:], want) {
			t.Errorf("%.0fx%.0f: the last sphere painted is not the hostile atom", size.w, size.h)
		}
	}
}

// Spheres are drawn at a fraction of the bond length, so two that land on top
// of each other hide a behaviour outright.
func TestMaleculeSVGKeepsSpheresApart(t *testing.T) {
	keys := []string{
		"objectives/exfil/dns", "objectives/persistence/cron", "objectives/discovery/host",
		"micro-behaviors/net/socket", "micro-behaviors/fs/path", "micro-behaviors/os/exec",
		"micro-behaviors/data/encode", "metadata/file/profile",
	}
	crits := []string{"hostile", "hostile", "suspicious", "notable", "notable", "notable", "notable", "baseline"}
	edges := [][2]int{{0, 3}, {1, 3}, {2, 3}, {0, 4}, {1, 4}, {2, 5}, {0, 5}, {1, 6}, {2, 6}}
	g := maleculeTestGraph(keys, crits, edges)

	for _, size := range []struct {
		name    string
		w, h    float64
		wantSep float64
	}{
		{"detail", 196, 168, 3.5},
		{"row", 132, 62, 2.5},
	} {
		pts := maleculeSpheres(maleculeSVG(g, size.w, size.h))
		worst, wi, wj := math.Inf(1), 0, 0
		for i := range pts {
			for j := i + 1; j < len(pts); j++ {
				if d := math.Hypot(pts[i].X-pts[j].X, pts[i].Y-pts[j].Y); d < worst {
					worst, wi, wj = d, i, j
				}
			}
		}
		if worst < size.wantSep {
			t.Errorf("%s: closest spheres %.2fpx apart (want >= %.1f), at %v and %v",
				size.name, worst, size.wantSep, pts[wi], pts[wj])
		}
	}
}

// The layout is settled in spring units that know nothing about the frame, so
// the finished drawing is scaled into it rather than trusted to have landed
// inside.
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
		for _, p := range maleculeSpheres(maleculeSVG(g, size.w, size.h)) {
			if p.X < 0 || p.X > size.w || p.Y < 0 || p.Y > size.h {
				t.Errorf("%.0fx%.0f: sphere (%.1f, %.1f) fell outside the frame",
					size.w, size.h, p.X, p.Y)
			}
		}
	}
}

func TestMaleculeSVGBudgetsAtoms(t *testing.T) {
	keys := make([]string, 0, 60)
	for i := range 60 {
		keys = append(keys, "micro-behaviors/net/socket"+strconv.Itoa(i))
	}
	g := maleculeTestGraph(keys, nil, nil)
	for _, size := range []struct {
		w, h   float64
		budget int
	}{
		{196, 168, maleculeDetailBudget},
		{132, 62, maleculeRowBudget},
	} {
		svg := maleculeSVG(g, size.w, size.h)
		if n := len(maleculeSpheres(svg)); n != size.budget {
			t.Errorf("%.0fx%.0f: drew %d spheres, want the budget of %d", size.w, size.h, n, size.budget)
		}
		if want := "+" + strconv.Itoa(len(keys)-size.budget); !strings.Contains(svg, want) {
			t.Errorf("%.0fx%.0f: missing the %q counter for the atoms left out", size.w, size.h, want)
		}
	}
}

func TestMaleculeSVGDeterministic(t *testing.T) {
	g := maleculeTestGraph(
		[]string{
			"objectives/exfil/dns", "micro-behaviors/net/socket", "micro-behaviors/net/http",
			"micro-behaviors/fs/write", "metadata/file/profile", "well-known/malware/backdoor",
		},
		[]string{"hostile", "notable", "notable", "notable", "baseline", "suspicious"},
		[][2]int{{0, 1}, {0, 2}, {5, 3}},
	)
	first := maleculeSVG(g, 196, 168)
	for range 3 {
		if got := maleculeSVG(g, 196, 168); got != first {
			t.Fatal("the same graph drew two different molecules")
		}
	}
}

// A page of feed rows puts many drawings in one document, so the gradients one
// molecule defines must not be picked up by the next.
func TestMaleculeSVGGradientIDsDoNotCollide(t *testing.T) {
	a := maleculeTestGraph([]string{"objectives/exfil/dns"}, []string{"hostile"}, nil)
	b := maleculeTestGraph([]string{"objectives/persistence/cron"}, []string{"hostile"}, nil)
	idRE := regexp.MustCompile(`<radialGradient id="(m[0-9a-f]{8})`)
	ma := idRE.FindStringSubmatch(maleculeSVG(a, 132, 62))
	mb := idRE.FindStringSubmatch(maleculeSVG(b, 132, 62))
	if ma == nil || mb == nil {
		t.Fatal("no gradient ids emitted")
	}
	if ma[1] == mb[1] {
		t.Errorf("two different molecules share the gradient prefix %q", ma[1])
	}
}

// The card names the atoms worth naming; the row has no room and names none.
func TestMaleculeSVGLabelsOnlyOnTheCard(t *testing.T) {
	g := maleculeTestGraph(
		[]string{"objectives/exfil/dns", "micro-behaviors/net/socket"},
		[]string{"hostile", "notable"},
		[][2]int{{0, 1}},
	)
	if !strings.Contains(maleculeSVG(g, 196, 168), "<text") {
		t.Error("the detail card drew no glyphs")
	}
	if strings.Contains(maleculeSVG(g, 132, 62), "<text") {
		t.Error("the feed row drew a glyph it has no room for")
	}
}

// A feed row's atoms are keyed two segments deep and a sample page's three, so
// whether a family link earns a contact has to be about siblinghood rather
// than absolute path depth. Judged on depth alone the row drew no contacts at
// all and its atoms scattered.
func TestMaleculeSVGDrawsShallowSiblings(t *testing.T) {
	g := maleculeFromFormula("O₂(SXe)H₃(CmDbPo)", []feedTrait{
		{Full: "objectives/supply-chain/hidden-payload::x", Crit: "hostile"},
	})
	if len(g.Atoms) < 4 {
		t.Fatalf("formula built %d atoms, want a graph worth drawing", len(g.Atoms))
	}
	if _, dashed := maleculeBonds(maleculeSVG(g, 132, 62)); dashed == 0 {
		t.Error("a feed row drew no family contacts; its atoms are siblings two segments deep")
	}
}

// The feed carries no dependency graph, so the lead element's edge to its
// group is a guess. Making it once is a skeleton; making it to every member
// draws a dozen bonds out of one atom, which is a shape no molecule has.
func TestMaleculeFromFormulaGivesLeadOneDependency(t *testing.T) {
	g := maleculeFromFormula("H₅(CmCrDbPoU)", nil)
	for i := range g.Atoms {
		if n := len(g.Atoms[i].Uses); n > 1 {
			t.Errorf("atom %q claims %d dependencies, want at most 1", g.Atoms[i].Key, n)
		}
	}
}
