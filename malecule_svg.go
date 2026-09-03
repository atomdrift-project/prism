package main

// The sorted-orbital drawing: the strongest behaviour at the centre, what it
// depends on around it, and everything else on a second ring — both rings
// ordered by category so kin land beside each other and their ties stay short
// arcs along the ring instead of chords across the middle.
//
// Rendered server-side and deterministically. The same sample draws identically
// every time, which matters when one package appears twice in a list.

import (
	"cmp"
	"fmt"
	"html"
	"math"
	"slices"
	"strings"
)

// critColor is the severity palette. Structure is drawn in ink, so colour here
// only ever means criticality.
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

// maleculeSVG draws the graph at w×h. Returns "" when there is nothing to say,
// so the template can drop the card rather than frame an empty box.
func maleculeSVG(graph maleculeGraph, width, height float64) string {
	if len(graph.Atoms) == 0 {
		return ""
	}
	pos := make(map[int]maleculePoint, len(graph.Atoms))
	cx, cy := width/2, height/2
	aspect := (width / height) * 0.6
	r1, r2 := math.Min(width, height)*0.27, math.Min(width, height)*0.47

	nucleus := -1
	if len(graph.Centres) > 0 {
		nucleus = graph.Centres[0]
		pos[nucleus] = maleculePoint{cx, cy}
	}
	placed := map[int]bool{}
	if nucleus >= 0 {
		placed[nucleus] = true
	}
	// Ring one: what the nucleus depends on, plus the other behaviours strong
	// enough to be centres in their own right.
	var ring1 []int
	add := func(dst *[]int, i int) {
		if !placed[i] {
			placed[i] = true
			*dst = append(*dst, i)
		}
	}
	if nucleus >= 0 {
		for _, j := range graph.Atoms[nucleus].Uses {
			add(&ring1, j)
		}
	}
	for _, c := range graph.Centres {
		add(&ring1, c)
	}
	// Ring two: their dependencies first, then whatever else is worth showing.
	var ring2 []int
	for _, p := range ring1 {
		for _, j := range graph.Atoms[p].Uses {
			if len(ring2) >= maleculeRing2 {
				break
			}
			add(&ring2, j)
		}
	}
	rest := make([]int, 0, len(graph.Atoms))
	for i := range graph.Atoms {
		if !placed[i] && critFromString(graph.Atoms[i].Crit) >= 2 {
			rest = append(rest, i)
		}
	}
	slices.SortStableFunc(rest, func(a, b int) int {
		return cmp.Compare(critFromString(graph.Atoms[b].Crit), critFromString(graph.Atoms[a].Crit))
	})
	for _, i := range rest {
		if len(ring2) >= maleculeRing2 {
			break
		}
		add(&ring2, i)
	}
	hidden := len(graph.Atoms) - len(placed)

	// Sort both rings by category, so kin are neighbours on the ring.
	byCat := func(ids []int) {
		slices.SortStableFunc(ids, func(a, b int) int {
			x, y := &graph.Atoms[a], &graph.Atoms[b]
			return cmp.Or(cmp.Compare(x.Category, y.Category), cmp.Compare(x.Key, y.Key))
		})
	}
	byCat(ring1)
	byCat(ring2)
	place := func(ids []int, r float64) {
		for k, i := range ids {
			a := -math.Pi/2 + float64(k)*2*math.Pi/math.Max(float64(len(ids)), 1)
			pos[i] = maleculePoint{cx + r*math.Cos(a)*aspect, cy + r*math.Sin(a)}
		}
	}
	place(ring1, r1)
	place(ring2, r2)

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %.0f %.0f" class="malecule" role="img" aria-label="malecule">`, width, height)
	// Kinship first, so it sits behind everything.
	for _, t := range graph.Ties {
		p, ok1 := pos[t[0]]
		q, ok2 := pos[t[1]]
		if !ok1 || !ok2 {
			continue
		}
		rr := math.Hypot(q.X-p.X, q.Y-p.Y) * 0.95
		fmt.Fprintf(&b, `<path d="M%.1f,%.1f A%.1f,%.1f 0 0 1 %.1f,%.1f" fill="none" stroke="#8A6080"`+
			` stroke-width="0.75" stroke-opacity="0.5" stroke-dasharray="1.5 2.1"/>`,
			p.X, p.Y, rr, rr, q.X, q.Y)
	}
	for i := range graph.Atoms {
		p, ok := pos[i]
		if !ok {
			continue
		}
		for _, j := range graph.Atoms[i].Uses {
			q, ok := pos[j]
			if !ok {
				continue
			}
			stroke := 1.0
			if len(graph.Atoms[j].UsedBy) > 1 {
				stroke = 1.4 // a behaviour two rules need is load-bearing; say so
			}
			fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s"`+
				` stroke-width="%.1f" stroke-opacity="0.75" stroke-linecap="round"/>`,
				p.X, p.Y, q.X, q.Y, critColor(graph.Atoms[i].Crit), stroke)
		}
	}
	for i := range graph.Atoms {
		p, ok := pos[i]
		if !ok {
			continue
		}
		b.WriteString(maleculeAtomSVG(&graph.Atoms[i], p, height, i == nucleus))
	}
	if hidden > 0 {
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="end" font-family="%s" font-size="8" fill="#8A6080">+%d</text>`,
			width-3, height-3, maleculeFont, hidden)
	}
	b.WriteString(`</svg>`)
	return b.String()
}

const maleculeFont = "SF Mono, Menlo, monospace"

// maleculeAtomSVG draws one atom: a lettered vertex when it is a rule or the
// nucleus, a plain dot otherwise, sized by how many matchers stand behind it.
// An atom assembled from a finer grain of itself carries a second ring.
func maleculeAtomSVG(a *maleculeAtom, p maleculePoint, height float64, nucleus bool) string {
	col := critColor(a.Crit)
	title := html.EscapeString(a.Key)
	if a.IsRule || nucleus {
		r := math.Min(5.4, height*0.088)
		if nucleus {
			r = math.Min(8.4, height*0.135)
		}
		var b strings.Builder
		if a.Internal > 0 {
			fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="%.1f" fill="none" stroke="%s"`+
				` stroke-width="0.7" stroke-opacity="0.5"/>`, p.X, p.Y, r+1.8, col)
		}
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="%.1f" fill="#ffffff" stroke="%s" stroke-width="%.1f"/>`,
			p.X, p.Y, r, col, math.Max(1, r/4.8))
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="middle" font-family="%s" font-size="%.1f"`+
			` font-weight="600" fill="%s"><title>%s</title>%s</text>`,
			p.X, p.Y+r*0.38, maleculeFont, r*1.12, col, title, html.EscapeString(a.Symbol))
		return b.String()
	}
	r := 2.2 + math.Min(1.5, math.Log2(math.Max(float64(a.Members), 1)))
	return fmt.Sprintf(`<circle cx="%.1f" cy="%.1f" r="%.1f" fill=%q><title>%s</title></circle>`,
		p.X, p.Y, r, col, title)
}
