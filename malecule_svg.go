package main

// Drawing the malecule. The picture is a molecule built from the sample's own
// structure, so two samples differ in shape rather than only in colour.
//
// Two hierarchies go into it, and they are not equals. The explicit one — a
// composite rule depending on an atomic behaviour — builds the skeleton: each
// rule nothing else depends on becomes a limb, and its dependency subtree is
// the chain of behaviours it actually needed. The implicit one — the trait id's
// own path, objectives/credential-access/browser — only fills what dependencies
// never reach, drawn thinner and paler so the eye reads the real structure
// first. Measured across live samples, dependency edges cover 0-75% of a
// sample's behaviours (one carries none at all), so the taxonomy has to remain
// a genuine fallback rather than a decoration.
//
// The one relation a spanning tree cannot express is a behaviour that several
// rules share, and that is spent on layout rather than ink: such a behaviour
// becomes a coordination centre and moves toward the centroid of everything
// that needs it, bending its limbs together. A sample whose rules keep reaching
// for the same behaviour visibly leans inward; one whose rules are independent
// stays spread.

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

const (
	// maleculeFont is the vertex face: an element symbol wants the same
	// monospace the rest of the page uses for identifiers.
	maleculeFont = "SF Mono, Menlo, monospace"
	// maleculeRowHeight is the size below which we are drawing a feed row
	// rather than a detail card, and everything scales off that: fewer atoms,
	// no labels, tighter shells.
	maleculeRowHeight = 80
	// maleculeDetailBudget caps the atoms drawn on the detail card and
	// maleculeRowBudget on a feed row. Past these the drawing stops being read
	// and starts being decoration, so the remainder is counted instead. Live
	// samples reach 163 behaviours; drawing all of them cost 108KB of SVG and
	// put neighbouring atoms 3.9px apart.
	maleculeDetailBudget = 30
	maleculeRowBudget    = 16
	// maleculeWedge is the arc, in px, a child is guaranteed at the radius it
	// lands on. Deep siblings share a narrow angular span, and a bond that
	// also shortens with depth stacks them on top of each other; pushing the
	// bond out until its wedge is this wide is what keeps them apart.
	maleculeWedge = 7
	// maleculeHubAtoms is how many behaviours must be drawn before another
	// coordination centre is allowed. Without it a small molecule becomes
	// mostly hubs — one live sample had four among eight behaviours, which put
	// ten vertices inside a shell that was not theirs.
	maleculeHubAtoms = 6
	// maleculeSphere is how far a coordination centre travels toward the
	// centroid of the behaviours that need it. Short of 1 so it leans toward
	// its partners while keeping enough of its own limb to stay legible.
	maleculeSphere = 0.55
)

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
// first, then namespace, then how much of the graph leans on the atom, then
// how much it stands for. Deterministic to the key, so the same report always
// draws the same molecule.
func maleculeRank(g *maleculeGraph) []int {
	rank := make([]int, len(g.Atoms))
	for i := range rank {
		rank[i] = i
	}
	slices.SortStableFunc(rank, func(x, y int) int {
		a, b := &g.Atoms[x], &g.Atoms[y]
		return cmp.Or(
			cmp.Compare(critFromString(b.Crit), critFromString(a.Crit)),
			cmp.Compare(maleculeNamespace(b.Key), maleculeNamespace(a.Key)),
			cmp.Compare(len(b.UsedBy)+len(b.Uses), len(a.UsedBy)+len(a.Uses)),
			cmp.Compare(b.conf, a.conf),
			cmp.Compare(b.Members, a.Members),
			cmp.Compare(a.Key, b.Key))
	})
	return rank
}

// maleculeNode is one vertex of the skeleton: either an atom, or a taxonomy
// stub standing in for a path segment the dependency graph never mentioned.
type maleculeNode struct {
	name    string
	crit    string
	kids    []*maleculeNode
	atom    int  // index into maleculeGraph.Atoms, -1 for a stub
	implied bool // reached by taxonomy rather than by a dependency edge
	weight  int  // subtree weight, for dividing the angular span
}

// maleculeSkeleton walks the dependency edges into a spanning forest and
// grafts everything they miss on by taxonomy. Returns the forest's root, whose
// children are the limbs.
func maleculeSkeleton(graph *maleculeGraph, budget int) *maleculeNode {
	rank := maleculeRank(graph)
	if len(rank) > budget {
		rank = rank[:budget]
	}
	keep := make(map[int]bool, len(rank))
	for _, i := range rank {
		keep[i] = true
	}
	usedBy := make(map[int]int, len(rank))
	for i := range graph.Atoms {
		if !keep[i] {
			continue
		}
		for _, j := range graph.Atoms[i].Uses {
			if j >= 0 && j < len(graph.Atoms) && keep[j] {
				usedBy[j]++
			}
		}
	}

	root := &maleculeNode{atom: -1, crit: "baseline"}
	placed := make(map[int]bool, len(rank))
	var build func(i int) *maleculeNode
	build = func(i int) *maleculeNode {
		placed[i] = true
		n := &maleculeNode{atom: i, name: graph.Atoms[i].Key, crit: graph.Atoms[i].Crit}
		kids := slices.Clone(graph.Atoms[i].Uses)
		slices.SortStableFunc(kids, func(a, b int) int {
			if a < 0 || b < 0 || a >= len(graph.Atoms) || b >= len(graph.Atoms) {
				return cmp.Compare(a, b)
			}
			return cmp.Or(
				cmp.Compare(critFromString(graph.Atoms[b].Crit), critFromString(graph.Atoms[a].Crit)),
				cmp.Compare(graph.Atoms[a].Key, graph.Atoms[b].Key))
		})
		for _, j := range kids {
			// An edge back to something already placed is the shared
			// dependency the tree cannot hold; it is drawn later as a
			// coordination bond rather than duplicated here.
			if j < 0 || j >= len(graph.Atoms) || !keep[j] || placed[j] {
				continue
			}
			n.kids = append(n.kids, build(j))
		}
		return n
	}
	// A composite nothing else depends on is the top of a real chain of
	// reasoning, so it earns its own limb.
	for _, i := range rank {
		if usedBy[i] == 0 && len(graph.Atoms[i].Uses) > 0 && !placed[i] {
			root.kids = append(root.kids, build(i))
		}
	}

	// The graft. Nesting it by path segment matters: a flat one stub per
	// category gave every sample the same uniform outer fringe, and the
	// silhouette stopped saying anything about the sample.
	stubs := map[string]*maleculeNode{}
	for _, i := range rank {
		if placed[i] {
			continue
		}
		node := root
		parts := strings.Split(graph.Atoms[i].Key, "/")
		for d, seg := range parts {
			if d == len(parts)-1 {
				node.kids = append(node.kids, &maleculeNode{
					atom: i, name: graph.Atoms[i].Key, crit: graph.Atoms[i].Crit, implied: true,
				})
				break
			}
			// Keyed by the path so far, so two behaviours under one category
			// share the branch point rather than each growing their own.
			path := strings.Join(parts[:d+1], "/")
			next, ok := stubs[path]
			if !ok {
				next = &maleculeNode{atom: -1, name: seg, crit: graph.Atoms[i].Crit, implied: true}
				stubs[path] = next
				node.kids = append(node.kids, next)
			}
			if critFromString(graph.Atoms[i].Crit) > critFromString(next.crit) {
				next.crit = graph.Atoms[i].Crit
			}
			node = next
		}
	}
	maleculeWeigh(root)
	return root
}

// maleculeWeigh sizes each subtree's claim on the circle and orders siblings.
// An explicit leaf counts double: dependency edges cover well under half a
// sample's behaviours, and weighting by population alone lets the filler win
// the drawing.
func maleculeWeigh(n *maleculeNode) int {
	if len(n.kids) == 0 {
		n.weight = 2
		if n.implied {
			n.weight = 1
		}
		return n.weight
	}
	total := 0
	for _, k := range n.kids {
		total += maleculeWeigh(k)
	}
	slices.SortStableFunc(n.kids, func(a, b *maleculeNode) int {
		return cmp.Or(
			cmp.Compare(boolRank(a.implied), boolRank(b.implied)), // explicit limbs first
			cmp.Compare(critFromString(b.crit), critFromString(a.crit)),
			cmp.Compare(b.weight, a.weight),
			cmp.Compare(a.name, b.name))
	})
	n.weight = total
	return total
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// maleculeHub is a behaviour at least two drawn rules depend on, with the users
// the skeleton did not already connect it to.
type maleculeHub struct {
	node   *maleculeNode
	extras []*maleculeNode
	atom   int
}

// maleculeSVG draws the graph at w×h. Returns "" when there is nothing to say,
// so the template can drop the card rather than frame an empty box.
func maleculeSVG(graph maleculeGraph, width, height float64) string {
	if len(graph.Atoms) == 0 {
		return ""
	}
	budget := maleculeDetailBudget
	if math.Min(width, height) < maleculeRowHeight {
		budget = maleculeRowBudget
	}
	root := maleculeSkeleton(&graph, budget)

	cx, cy := width/2, height/2
	// The card is wider than it is tall, so the circle is drawn as an ellipse
	// rather than leaving the sides empty.
	aspect := (width / height) * 0.66
	unit := math.Min(width/aspect, height) * 0.185

	pos := map[*maleculeNode]maleculePoint{root: {cx, cy}}
	var drawn []*maleculeNode
	var place func(n *maleculeNode, px, py, a0, a1 float64, depth int)
	place = func(n *maleculeNode, px, py, a0, a1 float64, depth int) {
		span := a1 - a0
		at := a0
		for _, k := range n.kids {
			frac := float64(k.weight) / math.Max(float64(n.weight), 1)
			mid := at + span*frac/2
			length := unit * math.Pow(0.78, float64(depth))
			if k.implied {
				length *= 0.72 // the taxonomy is filling in; say so
			}
			if arc := span * frac; arc > 0 {
				length = math.Max(length, math.Min(maleculeWedge/arc, unit*1.9))
			}
			q := maleculePoint{px + length*math.Cos(mid)*aspect, py + length*math.Sin(mid)}
			pos[k] = q
			drawn = append(drawn, k)
			place(k, q.X, q.Y, at+span*frac*0.08, at+span*frac*0.92, depth+1)
			at += span * frac
		}
	}
	place(root, cx, cy, -math.Pi, math.Pi, 0)

	hubs, parent := maleculeHubs(&graph, root, len(drawn))
	// Coordination: each centre leans toward the centroid of everything that
	// needs it, taking its own subtree along.
	for _, hub := range hubs {
		sx, sy, n := 0.0, 0.0, 0.0
		for _, u := range hub.extras {
			sx, sy, n = sx+pos[u].X, sy+pos[u].Y, n+1
		}
		if p, ok := parent[hub.node]; ok {
			sx, sy, n = sx+pos[p].X, sy+pos[p].Y, n+1
		}
		if n == 0 {
			continue
		}
		q := pos[hub.node]
		maleculeShift(hub.node, pos, (sx/n-q.X)*maleculeSphere, (sy/n-q.Y)*maleculeSphere)
	}
	// That move happens after the layout, so it can drop a centre on a vertex
	// the layout had already spaced — relax whatever it landed on.
	maleculeRelax(pos, drawn, math.Max(4.2, math.Min(width, height)*0.042))

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %.0f %.0f" class="malecule" role="img" aria-label="malecule">`,
		width, height)

	// Bonds first, so vertices sit on top of them.
	var bonds func(n *maleculeNode, depth int)
	bonds = func(n *maleculeNode, depth int) {
		p := pos[n]
		for _, k := range n.kids {
			q := pos[k]
			stroke := math.Max(0.75, 1.75-float64(depth)*0.3)
			opacity := 0.95 - float64(depth)*0.1
			if k.implied {
				stroke, opacity = math.Max(0.6, stroke*0.6), opacity*0.55
			}
			fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s"`+
				` stroke-width="%.2f" stroke-opacity="%.2f" stroke-linecap="round"/>`,
				p.X, p.Y, q.X, q.Y, critColor(k.crit), stroke, opacity)
			bonds(k, depth+1)
		}
	}
	bonds(root, 0)

	for _, hub := range hubs {
		q := pos[hub.node]
		col := critColor(graph.Atoms[hub.atom].Crit)
		for _, u := range hub.extras {
			p := pos[u]
			dx, dy := q.X-p.X, q.Y-p.Y
			l := math.Hypot(dx, dy)
			if l < 1 {
				continue
			}
			// Stop short of the centre so its shell stays readable.
			fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s"`+
				` stroke-width="0.9" stroke-opacity="0.65" stroke-dasharray="1.8 1.5"><title>%s</title></line>`,
				p.X, p.Y, q.X-dx/l*4.4, q.Y-dy/l*4.4, col, html.EscapeString(graph.Atoms[hub.atom].Key))
		}
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="%.1f" fill="none" stroke="%s"`+
			` stroke-width="0.85" stroke-opacity="0.5"/>`,
			q.X, q.Y, maleculeShellR(hub, hubs, pos, drawn, math.Min(5.6, height*0.068)), col)
	}

	labels := height > maleculeRowHeight
	for _, k := range drawn {
		b.WriteString(maleculeVertexSVG(&graph, k, pos[k], labels))
	}
	// The core anchors the drawing even when every limb is a graft.
	fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="%.1f" fill="#ffffff" stroke="%s" stroke-width="1.5"/>`,
		cx, cy, math.Min(height*0.05, 4.2), critColor(root.crit))

	if hidden := len(graph.Atoms) - min(len(graph.Atoms), budget); hidden > 0 {
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="end" font-family="%s" font-size="7.5" fill="#8A6080">+%d</text>`,
			width-3, height-3, maleculeFont, hidden)
	}
	b.WriteString(`</svg>`)
	return b.String()
}

// maleculeHubs finds the coordination centres: behaviours at least two drawn
// rules depend on. The user the skeleton already draws as a solid bond is
// skipped — including it laid a dashed line exactly over the bond it repeated,
// which was about half the coordination ink.
func maleculeHubs(graph *maleculeGraph, root *maleculeNode, drawn int) (hubs []maleculeHub, parent map[*maleculeNode]*maleculeNode) {
	byAtom := map[int]*maleculeNode{}
	parent = map[*maleculeNode]*maleculeNode{}
	var walk func(n *maleculeNode)
	walk = func(n *maleculeNode) {
		if n.atom >= 0 {
			byAtom[n.atom] = n
		}
		for _, k := range n.kids {
			parent[k] = n
			walk(k)
		}
	}
	walk(root)

	for i := range graph.Atoms {
		n, ok := byAtom[i]
		if !ok || len(graph.Atoms[i].UsedBy) < 2 {
			continue
		}
		hub := maleculeHub{atom: i, node: n}
		for _, u := range graph.Atoms[i].UsedBy {
			if un, ok := byAtom[u]; ok && un != parent[n] {
				hub.extras = append(hub.extras, un)
			}
		}
		if len(hub.extras) > 0 {
			hubs = append(hubs, hub)
		}
	}
	slices.SortStableFunc(hubs, func(a, b maleculeHub) int {
		return cmp.Or(
			cmp.Compare(len(b.extras), len(a.extras)),
			cmp.Compare(critFromString(graph.Atoms[b.atom].Crit), critFromString(graph.Atoms[a.atom].Crit)),
			cmp.Compare(graph.Atoms[a.atom].Key, graph.Atoms[b.atom].Key))
	})
	if limit := max(2, drawn/maleculeHubAtoms); len(hubs) > limit {
		hubs = hubs[:limit]
	}
	return hubs, parent
}

// maleculeShellR fits a coordination shell to its neighbourhood, so a centre
// never swallows a vertex that has nothing to do with it and two centres
// sitting close together never draw intersecting shells.
func maleculeShellR(hub maleculeHub, hubs []maleculeHub, pos map[*maleculeNode]maleculePoint,
	drawn []*maleculeNode, base float64,
) float64 {
	q := pos[hub.node]
	fit := base
	for _, n := range drawn {
		p := pos[n]
		if d := math.Hypot(p.X-q.X, p.Y-q.Y); d > 0.5 && d-1.3 < fit {
			fit = d - 1.3
		}
	}
	for _, other := range hubs {
		if other.node == hub.node {
			continue
		}
		p := pos[other.node]
		if d := math.Hypot(p.X-q.X, p.Y-q.Y); d/2 < fit {
			fit = d / 2
		}
	}
	return math.Max(fit, 2.6)
}

func maleculeShift(n *maleculeNode, pos map[*maleculeNode]maleculePoint, dx, dy float64) {
	p := pos[n]
	pos[n] = maleculePoint{p.X + dx, p.Y + dy}
	for _, k := range n.kids {
		maleculeShift(k, pos, dx, dy)
	}
}

// maleculeRelax pushes overlapping vertices apart. Bounded rather than run to
// convergence: a handful of passes settles every real graph, and a drawing is
// not worth an unbounded loop on the request path.
func maleculeRelax(pos map[*maleculeNode]maleculePoint, nodes []*maleculeNode, minSep float64) {
	for range 24 {
		moved := false
		for i := range nodes {
			for j := i + 1; j < len(nodes); j++ {
				p, q := pos[nodes[i]], pos[nodes[j]]
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
				pos[nodes[i]] = maleculePoint{p.X - ux, p.Y - uy}
				pos[nodes[j]] = maleculePoint{q.X + ux, q.Y + uy}
				moved = true
			}
		}
		if !moved {
			return
		}
	}
}

// maleculeVertexSVG draws one vertex: a lettered atom where there is room and
// the behaviour is worth naming, a plain dot otherwise, and a hollow ring for a
// taxonomy stub, which stands for a path segment rather than for a finding. An
// atom assembled from a finer grain of itself carries a second ring.
func maleculeVertexSVG(g *maleculeGraph, n *maleculeNode, p maleculePoint, labels bool) string {
	if n.atom < 0 {
		return fmt.Sprintf(`<circle cx="%.1f" cy="%.1f" r="2" fill="#ffffff" stroke="%s"`+
			` stroke-width="0.9" stroke-opacity="0.7"><title>%s</title></circle>`,
			p.X, p.Y, critColor(n.crit), html.EscapeString(n.name))
	}
	a := &g.Atoms[n.atom]
	col := critColor(a.Crit)
	if labels && !n.implied && critFromString(a.Crit) >= 4 {
		var b strings.Builder
		if a.Internal > 0 {
			fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="6.2" fill="none" stroke="%s"`+
				` stroke-width="0.7" stroke-opacity="0.5"/>`, p.X, p.Y, col)
		}
		// The glyph is the atom, knocked out of whatever it sits on — the way
		// a heteroatom reads in a structural formula.
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="middle" font-family="%s" font-size="8.5"`+
			` font-weight="600" fill="%s" paint-order="stroke" stroke="#ffffff" stroke-width="2.6"`+
			` stroke-linejoin="round"><title>%s</title>%s</text>`,
			p.X, p.Y+3.1, maleculeFont, col, html.EscapeString(a.Key), html.EscapeString(a.Symbol))
		return b.String()
	}
	r := 1.7
	if critFromString(a.Crit) >= 4 {
		r = 2.6
	}
	opacity := 1.0
	if n.implied {
		r *= 0.8
		opacity = 0.65
	}
	// fill=%q rather than "%s": the palette is a fixed set of hex literals,
	// so the quoting is identical and the linter stays satisfied.
	return fmt.Sprintf(`<circle cx="%.1f" cy="%.1f" r="%.1f" fill=%q fill-opacity="%.2f"><title>%s</title></circle>`,
		p.X, p.Y, r, col, opacity, html.EscapeString(a.Key))
}
