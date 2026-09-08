package main

// Drawing the malecule as a ball-and-stick model. The picture is a molecule
// built from the sample's own structure, so two samples differ in shape rather
// than only in colour.
//
// Two relations go into it and they are not equals. The explicit one — a
// composite rule depending on an atomic behaviour — is a covalent bond: a
// solid double stick, split at the midpoint so each half carries its own
// atom's severity. The implicit one — the trait id's own path,
// objectives/credential-access/browser — is a contact rather than a bond, a
// single dashed stick in neutral grey, because a shared family says two
// behaviours are alike and says nothing about which came first.
//
// Both channels change at once between them, count and continuity, and that
// is deliberate: measured across live samples the implicit relation is the
// larger population by up to three to one, so a single channel that separates
// them at card size disappears at row size.
//
// Depth is the verdict. The worst finding sits on the near plane and the rest
// recede, which makes the one thing the card exists to say the one thing
// nothing can be painted in front of. Distance is carried by colour rather
// than by scale — near atoms stay saturated, far ones wash toward the page —
// so sphere size is left free to mean only how many findings folded into the
// atom.

import (
	"cmp"
	"fmt"
	"html"
	"math"
	"slices"
	"strings"
)

func critColor(crit string) string {
	switch crit {
	case "hostile":
		return "#e11d48"
	case "suspicious":
		return "#d97706"
	case "notable":
		return "#2563eb"
	case "baseline":
		return "#9a7d90"
	default:
		return "#c9b3c3"
	}
}

type maleculePoint struct{ X, Y float64 }

// maleculeEdge is one dependency: the composite required the behaviour.
type maleculeEdge struct{ From, To int }

// maleculeKin is one family link. Share is the number of leading path segments
// the two behaviours have in common — the depth of the taxonomy node they last
// shared. Sib says they are siblings under it rather than two families joined
// at their representatives, which is the distinction that decides whether the
// link is worth ink: a sample page's keys are three segments deep and a feed
// row's are two, so an absolute depth would draw every contact on one and none
// on the other.
type maleculeKin struct {
	A, B, Share int
	Sib         bool
}

const (
	// maleculeFont is the glyph face. An element symbol on a sphere wants a
	// bold grotesque, which is what every molecular viewer uses.
	maleculeFont = "Helvetica Neue, Helvetica, Arial, sans-serif"
	// maleculeRowHeight is the size below which we are drawing a feed row
	// rather than a detail card: fewer atoms and no labels.
	maleculeRowHeight = 80
	// maleculeDetailBudget caps the atoms drawn on the detail card and
	// maleculeRowBudget on a feed row. Past these the drawing stops being read
	// and starts being decoration, so the remainder is counted instead. Live
	// samples reach 163 behaviours; drawing all of them cost 108KB of SVG and
	// put neighbouring atoms 3.9px apart.
	maleculeDetailBudget = 30
	maleculeRowBudget    = 11
	// maleculeKinDepth is the shallowest family-to-family link worth a drawn
	// contact. Two behaviours joined only under a shared namespace
	// ("everything reads files") are barely related; the spring still gathers
	// them, but drawing the line costs more than it says. Siblings are drawn
	// whatever their depth.
	maleculeKinDepth = 2
	// maleculeBall is the sphere radius as a fraction of bond length. Ball and
	// stick only works when the stick shows: at four tenths, two bonded atoms
	// nearly touch and the bond between them is a stub, which makes every bond
	// rule unreadable because there is almost no bond to read.
	maleculeBall = 0.29
	// maleculeStick is stick width as a fraction of bond length, and
	// maleculeDouble the offset of each line of a double bond from the axis.
	maleculeStick  = 0.155
	maleculeDouble = 0.62
	// maleculePersp is how much the near plane is enlarged. Shallow on
	// purpose: depth is spent on colour here, and scale would confound the
	// sphere size that carries the member count.
	maleculePersp = 0.28
	// maleculeHaze is how far the furthest atoms wash toward the ground, and
	// maleculeGround is that ground: the mist the rail card and the feed row
	// are both drawn on. Distance washes colour toward the paper the drawing
	// sits on, so the card's own background is the far plane and the drawing
	// needs no ground of its own.
	maleculeHaze = 0.62
)

// maleculeGround is --mist from the page's palette, as an RGB triple.
var maleculeGround = [3]int{0xfd, 0xf5, 0xfc}

// maleculeNamespace ranks a trait's top-level namespace. Every sample reads
// files, spawns processes and touches the OS, so micro-behaviours are the
// background hum of all software: left to rank on severity alone they fill the
// budget and every drawing comes out looking like every other one. What the
// sample is trying to do is worth the ink.
func maleculeNamespace(key string) int {
	ns, _, _ := strings.Cut(key, "/")
	switch ns {
	case "objectives":
		return 3
	case "well-known", "third_party":
		return 2
	case "micro-behaviors":
		return 1
	default: // metadata, and anything the taxonomy grows later
		return 0
	}
}

// maleculeRank orders atoms by what earns a place in the budget: severity
// first, then whether the atom is part of a dependency chain at all, then
// namespace, then how much of the graph leans on the atom, then how much it
// stands for. Deterministic to the key, so the same report always draws the
// same molecule.
//
// Severity stays first because colour is how the card states its verdict. The
// tie-break under it is the drawing's whole argument: among behaviours the
// verdict weighs the same, one the report reached by a dependency edge is a
// step in a chain of reasoning and one it did not is a lone observation, and
// the chain is what the budget should be spent on.
func maleculeRank(g *maleculeGraph) []int {
	rank := make([]int, len(g.Atoms))
	for i := range rank {
		rank[i] = i
	}
	slices.SortStableFunc(rank, func(x, y int) int {
		a, b := &g.Atoms[x], &g.Atoms[y]
		return cmp.Or(
			cmp.Compare(critFromString(b.Crit), critFromString(a.Crit)),
			cmp.Compare(boolRank(len(b.Uses)+len(b.UsedBy) > 0), boolRank(len(a.Uses)+len(a.UsedBy) > 0)),
			cmp.Compare(maleculeNamespace(b.Key), maleculeNamespace(a.Key)),
			cmp.Compare(len(b.UsedBy)+len(b.Uses), len(a.UsedBy)+len(a.Uses)),
			cmp.Compare(b.conf, a.conf),
			cmp.Compare(b.Members, a.Members),
			cmp.Compare(a.Key, b.Key))
	})
	return rank
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// maleculeBudget picks the atoms that earn ink and the dependency edges
// between them.
func maleculeBudget(g *maleculeGraph, budget int) ([]int, []maleculeEdge) {
	rank := maleculeRank(g)
	if len(rank) > budget {
		rank = rank[:budget]
	}
	keep := make(map[int]bool, len(rank))
	for _, i := range rank {
		keep[i] = true
	}
	var edges []maleculeEdge
	for _, i := range rank {
		for _, j := range g.Atoms[i].Uses {
			if j >= 0 && j < len(g.Atoms) && keep[j] && j != i {
				edges = append(edges, maleculeEdge{i, j})
			}
		}
	}
	return rank, edges
}

func maleculeIsComposite(i int, edges []maleculeEdge) bool {
	for _, e := range edges {
		if e.From == i {
			return true
		}
	}
	return false
}

func maleculeConnected(edges []maleculeEdge) map[int]bool {
	m := make(map[int]bool, len(edges)*2)
	for _, e := range edges {
		m[e.From], m[e.To] = true, true
	}
	return m
}

// maleculeKinEdges reads the taxonomy as the tree it is, contracted onto the
// atoms being drawn. Every family — every path prefix — nominates its
// strongest member as the point the rest of the family hangs off, and a family
// hangs off its parent family the same way.
//
// Within a family the members branch rather than radiate. Attaching all eleven
// of them to the first gives that atom eleven bonds and the drawing comes out
// as a sea urchin; attaching each to an earlier one caps any atom at three or
// four and produces the branched chains a molecule actually has. Chemists call
// the constraint valence and it is the single change that made this read as a
// molecule rather than as a graph.
func maleculeKinEdges(g *maleculeGraph, rank []int) []maleculeKin {
	order := make(map[int]int, len(rank))
	for n, i := range rank {
		order[i] = n
	}
	rep := make(map[string]int, len(rank)*2)
	for _, i := range rank {
		parts := strings.Split(g.Atoms[i].Key, "/")
		for d := 1; d <= len(parts); d++ {
			p := strings.Join(parts[:d], "/")
			if cur, ok := rep[p]; !ok || order[i] < order[cur] {
				rep[p] = i
			}
		}
	}
	best := map[[2]int]maleculeKin{}
	add := func(a, b, share int, sib bool) {
		if a == b {
			return
		}
		key := [2]int{min(a, b), max(a, b)}
		cur, ok := best[key]
		if !ok || share > cur.Share {
			cur.A, cur.B, cur.Share = key[0], key[1], share
		}
		cur.Sib = cur.Sib || sib
		best[key] = cur
	}
	families := map[string][]int{}
	for _, i := range rank {
		parts := strings.Split(g.Atoms[i].Key, "/")
		if len(parts) < 2 {
			continue
		}
		p := strings.Join(parts[:len(parts)-1], "/")
		families[p] = append(families[p], i)
	}
	names := make([]string, 0, len(families))
	for p := range families {
		names = append(names, p)
	}
	slices.Sort(names) // map order is not a drawing decision
	for _, p := range names {
		m := families[p]
		slices.SortStableFunc(m, func(a, b int) int { return cmp.Compare(order[a], order[b]) })
		share := len(strings.Split(p, "/"))
		for i := 1; i < len(m); i++ {
			add(m[(i-1)/2], m[i], share, true)
		}
	}
	seen := map[string]bool{}
	for _, i := range rank {
		parts := strings.Split(g.Atoms[i].Key, "/")
		for d := len(parts) - 1; d >= 2; d-- {
			p := strings.Join(parts[:d], "/")
			if seen[p] {
				break
			}
			seen[p] = true
			add(rep[strings.Join(parts[:d-1], "/")], rep[p], d-1, false)
		}
	}
	kin := make([]maleculeKin, 0, len(best))
	for _, k := range best {
		kin = append(kin, k)
	}
	slices.SortFunc(kin, func(a, b maleculeKin) int {
		return cmp.Or(cmp.Compare(a.A, b.A), cmp.Compare(a.B, b.B))
	})
	return kin
}

// maleculeSpring is one bond the layout honours. Stiff and short for a
// dependency, slack and long for a family link: the two relations pull on the
// same layout with different authority, which is the whole idea.
type maleculeSpring struct {
	a, b    int
	rest, k float64
}

// maleculeKinSpring grades a family link by how much taxonomy the two
// behaviours share. A shared namespace is the loosest tie there is — long and
// nearly slack, so it gathers without dragging anything across the frame.
func maleculeKinSpring(k maleculeKin) (rest, stiff float64) {
	switch {
	case !maleculeKinDrawn(k):
		return 26, 0.016
	case k.Share >= 3:
		return 10, 0.16
	default:
		return 10.5, 0.13
	}
}

// maleculeKinDrawn reports whether a family link earns a contact. Siblings
// always do; two families joined at their representatives do only once the
// shared path is more than a namespace.
func maleculeKinDrawn(k maleculeKin) bool { return k.Sib || k.Share >= maleculeKinDepth }

// maleculeSolve settles atoms under spring, repulsion and a pin. A pinned atom
// is sprung to where the chain layout put it rather than nailed there, so the
// skeleton keeps its shape while still yielding a little to what hangs off it.
// Bounded rather than run to convergence: a drawing is not worth an unbounded
// loop on the request path.
func maleculeSolve(x, y []float64, springs []maleculeSpring, pinX, pinY, pinK []float64) {
	const iters, repel = 460, 190.0
	n := len(x)
	fx, fy := make([]float64, n), make([]float64, n)
	for step := range iters {
		cool := 1 - float64(step)/float64(iters+40)
		clear(fx)
		clear(fy)
		for a := range n {
			for b := a + 1; b < n; b++ {
				dx, dy := x[b]-x[a], y[b]-y[a]
				d2 := dx*dx + dy*dy + 0.01
				d := math.Sqrt(d2)
				f := repel / d2
				fx[a] -= dx / d * f
				fy[a] -= dy / d * f
				fx[b] += dx / d * f
				fy[b] += dy / d * f
			}
		}
		for _, s := range springs {
			dx, dy := x[s.b]-x[s.a], y[s.b]-y[s.a]
			d := math.Hypot(dx, dy) + 0.01
			f := (d - s.rest) * s.k
			fx[s.a] += dx / d * f
			fy[s.a] += dy / d * f
			fx[s.b] -= dx / d * f
			fy[s.b] -= dy / d * f
		}
		for a := range n {
			if pinK[a] > 0 {
				fx[a] += (pinX[a] - x[a]) * pinK[a]
				fy[a] += (pinY[a] - y[a]) * pinK[a]
			} else {
				fx[a] -= x[a] * 0.012 // nothing holds it; drift home slowly
				fy[a] -= y[a] * 0.012
			}
			if m := math.Hypot(fx[a], fy[a]); m > 3*cool {
				fx[a], fy[a] = fx[a]/m*3*cool, fy[a]/m*3*cool
			}
			x[a] += fx[a]
			y[a] += fy[a]
		}
	}
}

// maleculeChains lays out the explicit structure alone: each connected run of
// dependencies becomes its own little molecule, packed toward the middle.
// Nothing is rooted at a shared centre, so a composite sits at the head of the
// chain it actually required rather than on the rim of a sunburst.
// maleculeCluster is one connected run of dependencies, laid out on its own.
type maleculeCluster struct {
	nodes  []int
	crit   int
	r      float64
	cx, cy float64
}

// maleculeComponents groups the drawn atoms into connected runs of the
// dependency relation, so each can be laid out as its own little molecule.
func maleculeComponents(core []int, edges []maleculeEdge) map[int][]int {
	parent := make(map[int]int, len(core))
	var find func(int) int
	find = func(x int) int {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}
	for _, i := range core {
		parent[i] = i
	}
	for _, e := range edges {
		if a, b := find(e.From), find(e.To); a != b {
			parent[a] = b
		}
	}
	comps := map[int][]int{}
	for _, i := range core {
		comps[find(i)] = append(comps[find(i)], i)
	}
	return comps
}

// maleculeGrow lays one component out about its own centroid. A composite fans
// its dependencies downward, so the chain reads the way it is written: what
// required, then what was required.
func maleculeGrow(g *maleculeGraph, nodes []int, kids map[int][]int, indeg map[int]int,
	inCore map[int]bool, pos map[int]maleculePoint,
) maleculeCluster {
	slices.Sort(nodes)
	placed := make(map[int]bool, len(nodes))
	var roots []int
	for _, n := range nodes {
		if indeg[n] == 0 {
			roots = append(roots, n)
		}
	}
	if len(roots) == 0 {
		roots = nodes[:1] // a cycle: start anywhere, deterministically
	}
	var place func(n int, x, y, a0, a1 float64)
	place = func(n int, x, y, a0, a1 float64) {
		placed[n] = true
		pos[n] = maleculePoint{x, y}
		var ch []int
		for _, k := range kids[n] {
			if !placed[k] && inCore[k] {
				ch = append(ch, k)
			}
		}
		if len(ch) == 0 {
			return
		}
		slices.SortStableFunc(ch, func(a, b int) int {
			return cmp.Or(
				cmp.Compare(critFromString(g.Atoms[b].Crit), critFromString(g.Atoms[a].Crit)),
				cmp.Compare(g.Atoms[a].Key, g.Atoms[b].Key))
		})
		span := (a1 - a0) / float64(len(ch))
		for ci, k := range ch {
			mid := a0 + span*(float64(ci)+0.5)
			place(k, x+math.Cos(mid), y+math.Sin(mid), mid-0.75, mid+0.75)
		}
	}
	for ri, rt := range roots {
		if !placed[rt] {
			place(rt, (float64(ri)-float64(len(roots)-1)/2)*1.5, 0, math.Pi/2-1.15, math.Pi/2+1.15)
		}
	}
	c := maleculeCluster{nodes: nodes}
	var mx, my float64
	for _, n := range nodes {
		if _, ok := pos[n]; !ok {
			pos[n] = maleculePoint{} // unreachable from any root
		}
		mx, my = mx+pos[n].X, my+pos[n].Y
		c.crit = max(c.crit, critFromString(g.Atoms[n].Crit))
	}
	mx, my = mx/float64(len(nodes)), my/float64(len(nodes))
	for _, n := range nodes {
		p := pos[n]
		pos[n] = maleculePoint{p.X - mx, p.Y - my}
		c.r = math.Max(c.r, math.Hypot(p.X-mx, p.Y-my))
	}
	c.r += 0.5
	return c
}

// maleculePack places the clusters in the frame. Push apart, then pull in:
// repulsion alone settles into whatever the seeding happened to spread, and
// the drawing wants the chains touching rather than marooned in their own
// corners of the frame.
func maleculePack(clusters []maleculeCluster, aspect float64) {
	for i := range clusters {
		t := 2.39996 * float64(i) // phyllotaxis: no two clusters start together
		rad := 1.5 * math.Sqrt(float64(i))
		clusters[i].cx, clusters[i].cy = rad*math.Cos(t)*aspect, rad*math.Sin(t)
	}
	for range 300 {
		for i := range clusters {
			for j := i + 1; j < len(clusters); j++ {
				dx := clusters[j].cx - clusters[i].cx
				dy := (clusters[j].cy - clusters[i].cy) * aspect
				d := math.Hypot(dx, dy)
				want := clusters[i].r + clusters[j].r + 0.5
				if d >= want {
					continue
				}
				if d < 0.01 {
					dx, dy, d = 1, 0, 1 // coincident: separate along x
				}
				push := (want - d) / 2
				clusters[i].cx -= dx / d * push
				clusters[i].cy -= dy / d * push / aspect
				clusters[j].cx += dx / d * push
				clusters[j].cy += dy / d * push / aspect
			}
		}
		for i := range clusters {
			clusters[i].cx *= 0.985
			clusters[i].cy *= 0.985
		}
	}
}

// maleculeChains lays out the explicit structure alone: each connected run of
// dependencies becomes its own little molecule, packed toward the middle.
// Nothing is rooted at a shared centre, so a composite sits at the head of the
// chain it actually required rather than on the rim of a sunburst.
func maleculeChains(g *maleculeGraph, core []int, edges []maleculeEdge, aspect float64) map[int]maleculePoint {
	kids := map[int][]int{}
	indeg := map[int]int{}
	inCore := make(map[int]bool, len(core))
	for _, i := range core {
		inCore[i] = true
	}
	for _, e := range edges {
		kids[e.From] = append(kids[e.From], e.To)
		indeg[e.To]++
	}
	comps := maleculeComponents(core, edges)
	pos := make(map[int]maleculePoint, len(core))
	clusters := make([]maleculeCluster, 0, len(comps))
	for _, nodes := range comps {
		clusters = append(clusters, maleculeGrow(g, nodes, kids, indeg, inCore, pos))
	}
	// Worst and largest first, so the sample's verdict sits near the middle.
	slices.SortStableFunc(clusters, func(a, b maleculeCluster) int {
		return cmp.Or(cmp.Compare(b.crit, a.crit), cmp.Compare(len(b.nodes), len(a.nodes)),
			cmp.Compare(a.nodes[0], b.nodes[0]))
	})
	maleculePack(clusters, aspect)
	for _, c := range clusters {
		for _, n := range c.nodes {
			p := pos[n]
			pos[n] = maleculePoint{c.cx + p.X, c.cy + p.Y}
		}
	}
	return pos
}

// maleculeLayout places every drawn atom. The dependency runs are laid out
// first and pinned; the taxonomy is then hung off them by weak springs. The
// pin is stiffer than any family spring, so the implicit hierarchy fills the
// frame without ever bending the explicit one out of shape.
func maleculeLayout(g *maleculeGraph, rank []int, edges []maleculeEdge, kin []maleculeKin,
	aspect float64,
) map[int]maleculePoint {
	conn := maleculeConnected(edges)
	core := make([]int, 0, len(rank))
	for _, i := range rank {
		if conn[i] || critFromString(g.Atoms[i].Crit) >= 4 {
			core = append(core, i)
		}
	}
	chain := maleculeChains(g, core, edges, aspect)

	idx := make(map[int]int, len(rank))
	for n, i := range rank {
		idx[i] = n
	}
	n := len(rank)
	x, y := make([]float64, n), make([]float64, n)
	pinX, pinY, pinK := make([]float64, n), make([]float64, n), make([]float64, n)
	for i, a := range rank {
		if p, ok := chain[a]; ok {
			// The chain layout works in bond lengths; the solver works in px.
			x[i], y[i] = p.X*10, p.Y*10
			pinX[i], pinY[i], pinK[i] = x[i], y[i], 0.22
			continue
		}
		t := 2.39996 * float64(i)
		r := 4 * math.Sqrt(float64(i)+0.5)
		x[i], y[i] = r*math.Cos(t), r*math.Sin(t)
	}
	springs := make([]maleculeSpring, 0, len(edges)+len(kin))
	for _, e := range edges {
		springs = append(springs, maleculeSpring{idx[e.From], idx[e.To], 10, 0.42})
	}
	for _, k := range kin {
		rest, stiff := maleculeKinSpring(k)
		springs = append(springs, maleculeSpring{idx[k.A], idx[k.B], rest, stiff})
	}
	maleculeSolve(x, y, springs, pinX, pinY, pinK)

	pos := make(map[int]maleculePoint, n)
	for i, a := range rank {
		pos[a] = maleculePoint{x[i], y[i]}
	}
	return pos
}

// maleculeFit scales and centres the finished layout so the drawing uses the
// frame it was given. Spring rest lengths do not know how far the outermost
// atom ended up, so without this a sparse molecule sits in the middle of an
// empty box and a crowded one runs off the edge. Scaling is uniform, so every
// relative distance the layout worked out survives.
func maleculeFit(pos map[int]maleculePoint, order []int, w, h, margin float64) {
	if len(order) == 0 {
		return
	}
	minX, minY := math.Inf(1), math.Inf(1)
	maxX, maxY := math.Inf(-1), math.Inf(-1)
	for _, i := range order {
		p := pos[i]
		minX, maxX = math.Min(minX, p.X), math.Max(maxX, p.X)
		minY, maxY = math.Min(minY, p.Y), math.Max(maxY, p.Y)
	}
	s := math.Min((w-2*margin)/math.Max(maxX-minX, 1e-6), (h-2*margin)/math.Max(maxY-minY, 1e-6))
	ox, oy := (w-(maxX-minX)*s)/2, (h-(maxY-minY)*s)/2
	for _, i := range order {
		p := pos[i]
		pos[i] = maleculePoint{ox + (p.X-minX)*s, oy + (p.Y-minY)*s}
	}
}

// maleculeRelax pushes overlapping spheres apart. The layout settles bond
// lengths, not clearances, so two atoms in different chains can land on top of
// each other and hide a behaviour outright. Bounded rather than run to
// convergence: a handful of passes settles every real graph, and a drawing is
// not worth an unbounded loop on the request path.
func maleculeRelax(pos map[int]maleculePoint, order []int, minSep float64) {
	for range 24 {
		moved := false
		for a := range order {
			for b := a + 1; b < len(order); b++ {
				p, q := pos[order[a]], pos[order[b]]
				dx, dy := q.X-p.X, q.Y-p.Y
				d := math.Hypot(dx, dy)
				if d >= minSep {
					continue
				}
				if d < 0.01 {
					dx, dy, d = 1, 0, 1 // coincident: separate along x
				}
				push := (minSep - d) / 2
				ux, uy := dx/d*push, dy/d*push
				pos[order[a]] = maleculePoint{p.X - ux, p.Y - uy}
				pos[order[b]] = maleculePoint{q.X + ux, q.Y + uy}
				moved = true
			}
		}
		if !moved {
			return
		}
	}
}

// maleculeBondLen is the median drawn bond length. Every dimension of the
// drawing is derived from it — stick width, sphere radius, glyph size — which
// is what keeps the proportions of a molecular model at any density: they are
// fixed relative to the bond, not to the frame.
func maleculeBondLen(edges []maleculeEdge, kin []maleculeKin, pos map[int]maleculePoint) float64 {
	ls := make([]float64, 0, len(edges)+len(kin))
	for _, e := range edges {
		p, q := pos[e.From], pos[e.To]
		ls = append(ls, math.Hypot(q.X-p.X, q.Y-p.Y))
	}
	for _, k := range kin {
		if !maleculeKinDrawn(k) {
			continue
		}
		p, q := pos[k.A], pos[k.B]
		ls = append(ls, math.Hypot(q.X-p.X, q.Y-p.Y))
	}
	if len(ls) == 0 {
		return 24 // a molecule with no bonds at all: pick a plausible scale
	}
	slices.Sort(ls)
	return ls[len(ls)/2]
}

// maleculeMix moves a hex colour a fraction of the way toward a target. Used
// for the three things shading needs: a highlight, a terminator, and the haze
// that stands in for distance.
func maleculeMix(hex string, f float64, tr, tg, tb int) string {
	var r, g, b int
	if _, err := fmt.Sscanf(hex, "#%02x%02x%02x", &r, &g, &b); err != nil {
		return hex // the palette is a fixed set of literals; this cannot happen
	}
	m := func(v, t int) int { return max(0, min(255, int(float64(v)+(float64(t)-float64(v))*f))) }
	return fmt.Sprintf("#%02x%02x%02x", m(r, tr), m(g, tg), m(b, tb))
}

func maleculeShade(hex string, f float64) string   { return maleculeMix(hex, f, 0, 0, 0) }
func maleculeLighten(hex string, f float64) string { return maleculeMix(hex, f, 255, 255, 255) }

// maleculeFade pushes a colour toward the ground the drawing sits on, which is
// what distance does to colour in air.
func maleculeFade(hex string, f float64) string {
	return maleculeMix(hex, f, maleculeGround[0], maleculeGround[1], maleculeGround[2])
}

func maleculeStroke(b *strings.Builder, p, q maleculePoint, col string, wid float64, dash string) {
	if dash != "" {
		dash = fmt.Sprintf(` stroke-dasharray=%q`, dash)
	}
	// stroke=%q rather than "%s": the palette is a fixed set of hex literals,
	// so the quoting is identical and the linter stays satisfied.
	fmt.Fprintf(b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke=%q`+
		` stroke-width="%.2f" stroke-linecap="round"%s/>`, p.X, p.Y, q.X, q.Y, col, wid, dash)
}

// maleculeCylinder is one stick: a shaded body with a lighter core down the
// middle, which is as much of a lit cylinder as two strokes can manage.
func maleculeCylinder(b *strings.Builder, p, q maleculePoint, col string, wid float64) {
	maleculeStroke(b, p, q, maleculeShade(col, 0.22), wid, "")
	maleculeStroke(b, p, q, maleculeLighten(col, 0.45), wid*0.30, "")
}

// maleculeCovalent is a dependency: each half in its own atom's colour, the way
// every ball-and-stick viewer draws a bond between unlike atoms, and doubled,
// because the relation it stands for is the one the report reasoned its way to.
func maleculeCovalent(b *strings.Builder, p, q maleculePoint, ca, cb string, wid float64) {
	gap := wid * maleculeDouble
	dx, dy := q.X-p.X, q.Y-p.Y
	l := math.Hypot(dx, dy)
	if l < 0.5 {
		return
	}
	nx, ny := -dy/l*gap, dx/l*gap
	for _, s := range [2]float64{1, -1} {
		a := maleculePoint{p.X + nx*s, p.Y + ny*s}
		c := maleculePoint{q.X + nx*s, q.Y + ny*s}
		m := maleculePoint{(a.X + c.X) / 2, (a.Y + c.Y) / 2}
		maleculeCylinder(b, a, m, ca, wid*0.68)
		maleculeCylinder(b, m, c, cb, wid*0.68)
	}
}

// maleculeVerdictZ puts the worst finding on the near plane. If the drawing is
// going to put something in front, the verdict is the only defensible
// candidate: it is what the card exists to say, and the one thing a reader
// should never have to hunt for behind another sphere.
func maleculeVerdictZ(crit string) float64 {
	switch critFromString(crit) {
	case 5:
		return 1
	case 4:
		return 0.45
	case 3:
		return -0.25
	default:
		return -1
	}
}

// maleculeSVG draws the graph at w×h. Returns "" when there is nothing to say,
// so the template can drop the card rather than frame an empty box.
func maleculeSVG(graph maleculeGraph, width, height float64) string {
	if len(graph.Atoms) == 0 {
		return ""
	}
	budget, labels := maleculeDetailBudget, true
	if math.Min(width, height) < maleculeRowHeight {
		budget, labels = maleculeRowBudget, false
	}
	rank, edges := maleculeBudget(&graph, budget)
	kin := maleculeKinEdges(&graph, rank)
	pos := maleculeLayout(&graph, rank, edges, kin, width/height)
	maleculeFit(pos, rank, width, height, 13)
	bond := maleculeBondLen(edges, kin, pos)
	// Two spheres that touch hide a behaviour between them, so clear them by
	// rather more than their own diameter, then fit again: relaxing can push
	// an outlying atom past the edge the first fit had it inside.
	maleculeRelax(pos, rank, bond*maleculeBall*2.6)
	maleculeFit(pos, rank, width, height, 13)
	bond = maleculeBondLen(edges, kin, pos)

	cx, cy := width/2, height/2
	depth := make(map[int]float64, len(rank))
	proj := make(map[int]maleculePoint, len(rank))
	fade := make(map[int]float64, len(rank))
	scale := make(map[int]float64, len(rank))
	for _, i := range rank {
		depth[i] = maleculeVerdictZ(graph.Atoms[i].Crit)
		s := 3.4 / (3.4 - depth[i]*maleculePersp)
		scale[i] = s
		p := pos[i]
		proj[i] = maleculePoint{cx + (p.X-cx)*s, cy + (p.Y-cy)*s}
		fade[i] = (1 - depth[i]) / 2 // 0 at the front, 1 at the back
	}
	conn := maleculeConnected(edges)
	radius := func(i int) float64 {
		a := &graph.Atoms[i]
		var f float64
		switch {
		case maleculeIsComposite(i, edges):
			f = 1.18 // a composite is the head of a chain of reasoning
		case conn[i]:
			f = 1
		default:
			f = 0.80 // a lone observation
		}
		if critFromString(a.Crit) >= 4 {
			f *= 1.14
		}
		// Mass is how many findings folded into the atom.
		f *= 0.84 + 0.22*math.Cbrt(float64(a.Members))/1.6
		return bond * maleculeBall * f * scale[i]
	}
	stick := bond * maleculeStick
	tint := func(i int, hex string) string { return maleculeFade(hex, fade[i]*maleculeHaze) }

	var out strings.Builder
	fmt.Fprintf(&out, `<svg viewBox="0 0 %.0f %.0f" class="malecule" role="img" aria-label="malecule">`,
		width, height)
	// One gradient per severity per depth tier, so a sphere is lit rather than
	// flat and a distant one is lit in its own hazed colour.
	out.WriteString(`<defs>`)
	uid := maleculeGradientID(&graph, rank)
	for _, c := range [...]string{"hostile", "suspicious", "notable", "baseline", "component"} {
		for tier := range 3 {
			col := maleculeFade(critColor(c), float64(tier)*0.31)
			fmt.Fprintf(&out, `<radialGradient id="m%s%s%d" cx="32%%" cy="28%%" r="76%%">`+
				`<stop offset="0%%" stop-color="%s"/><stop offset="18%%" stop-color="%s"/>`+
				`<stop offset="62%%" stop-color="%s"/><stop offset="100%%" stop-color="%s"/>`+
				`</radialGradient>`,
				uid, c, tier, maleculeLighten(col, 0.90), maleculeLighten(col, 0.42),
				col, maleculeShade(col, 0.52))
		}
	}
	out.WriteString(`</defs>`)

	// Everything goes into one list keyed by depth and is painted back to
	// front, glyphs included. Drawing the labels in a pass of their own let a
	// distant atom's glyph land on top of a nearer sphere, which is the one
	// way this drawing can state the wrong verdict.
	type mark struct {
		draw func()
		z    float64
	}
	marks := make([]mark, 0, len(rank)*2+len(edges)+len(kin))
	for _, k := range kin {
		if !maleculeKinDrawn(k) {
			continue
		}
		p, q := proj[k.A], proj[k.B]
		f := math.Max(fade[k.A], fade[k.B])
		wid := stick * (0.34 + 0.10*float64(min(max(k.Share, 2), 3)))
		marks = append(marks, mark{func() {
			// A contact, not a bond: the dashed stick a molecular viewer uses
			// for an interaction that is not covalent.
			maleculeStroke(&out, p, q, maleculeFade("#b9a6b4", f*maleculeHaze), wid*1.25,
				fmt.Sprintf("%.1f %.1f", wid*1.4, wid*1.5))
		}, math.Min(depth[k.A], depth[k.B]) - 0.02})
	}
	for _, e := range edges {
		p, q := proj[e.From], proj[e.To]
		ca := tint(e.From, critColor(graph.Atoms[e.From].Crit))
		cb := tint(e.To, critColor(graph.Atoms[e.To].Crit))
		wid := stick * math.Min(scale[e.From], scale[e.To])
		marks = append(marks, mark{func() {
			maleculeCovalent(&out, p, q, ca, cb, wid)
		}, math.Min(depth[e.From], depth[e.To]) - 0.01})
	}
	for _, i := range rank {
		a := &graph.Atoms[i]
		p, r := proj[i], radius(i)
		title := html.EscapeString(a.Key)
		crit, rim := a.Crit, maleculeShade(tint(i, critColor(a.Crit)), 0.55)
		tier := min(2, int(fade[i]*3))
		marks = append(marks, mark{func() {
			fmt.Fprintf(&out, `<circle cx="%.1f" cy="%.1f" r="%.1f" fill="url(#m%s%s%d)"`+
				` stroke="%s" stroke-width="%.2f" stroke-opacity="0.55"><title>%s</title></circle>`,
				p.X, p.Y, r, uid, crit, tier, rim, r*0.055, title)
			// The specular blob. A plastic ball is only plastic because of it.
			fmt.Fprintf(&out, `<ellipse cx="%.1f" cy="%.1f" rx="%.2f" ry="%.2f" fill="#ffffff"`+
				` fill-opacity="0.55" transform="rotate(-34 %.1f %.1f)"/>`,
				p.X-r*0.34, p.Y-r*0.38, r*0.28, r*0.19, p.X-r*0.34, p.Y-r*0.38)
		}, depth[i]})
		if !labels || (!maleculeIsComposite(i, edges) && critFromString(a.Crit) < 4) {
			continue
		}
		font := math.Max(7, math.Min(r*0.95, bond*0.42))
		sym := html.EscapeString(a.Symbol)
		marks = append(marks, mark{func() {
			fmt.Fprintf(&out, `<text x="%.1f" y="%.1f" text-anchor="middle" font-family="%s"`+
				` font-size="%.1f" font-weight="700" fill="#ffffff" fill-opacity="0.96"`+
				` paint-order="stroke" stroke="%s" stroke-width="%.1f" stroke-linejoin="round">`+
				`<title>%s</title>%s</text>`,
				p.X, p.Y+font*0.35, maleculeFont, font, rim, font*0.22, title, sym)
		}, depth[i] + 1e-6})
	}
	slices.SortStableFunc(marks, func(x, y mark) int { return cmp.Compare(x.z, y.z) })
	for _, m := range marks {
		m.draw()
	}

	if hidden := len(graph.Atoms) - len(rank); hidden > 0 {
		fmt.Fprintf(&out, `<text x="%.1f" y="%.1f" text-anchor="end" font-family="%s"`+
			` font-size="7.5" fill="#8A6080">+%d</text>`, width-3, height-3, maleculeFont, hidden)
	}
	out.WriteString(`</svg>`)
	return out.String()
}

// maleculeGradientID keeps one drawing's gradient ids from colliding with
// another's when several malecules share a page, as they do on the feed.
// Derived from the drawn keys so it stays stable for a given report.
func maleculeGradientID(g *maleculeGraph, rank []int) string {
	var h uint32 = 2166136261 // FNV-1a
	for _, i := range rank {
		for _, c := range []byte(g.Atoms[i].Key) {
			h = (h ^ uint32(c)) * 16777619
		}
	}
	return fmt.Sprintf("%08x", h)
}
