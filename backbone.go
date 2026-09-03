package main

// The backbone is the sample page's drawing of its compound: the trait
// categories along a zigzag chain in tier order, each carrying one stub per
// subcategory beneath it, tipped in the worst severity found there. It is the
// same tree BuildMalecule lays out in three dimensions, drawn flat, server-side,
// so the page needs no script to show it.

import (
	"fmt"
	"html"
	"html/template"
	"math"
	"strings"
)

// backboneAtom is one category on the chain, with the subcategories that hang
// off it. Tier is the formula's tier symbol (O, H, Md, K, Th).
type backboneAtom struct {
	Tier   string
	Symbol string
	Name   string
	Stubs  []backboneStub
}

// backboneStub is one subcategory beneath a category: its path below the tier
// and the strongest severity found on it.
type backboneStub struct {
	Path     string
	Severity Severity
}

// tierSymbol maps a trait id's first segment to its formula tier. Ids outside
// the four tiers (cleave's package facts, for instance) do not appear in the
// formula and so do not appear on the backbone either.
func tierSymbol(seg string) string {
	switch seg {
	case "objectives":
		return "O"
	case "micro-behaviors":
		return "H"
	case "metadata":
		return "Md"
	case "well-known":
		return "K"
	case "third-party", "third_party":
		return "Th"
	default:
		return ""
	}
}

// backboneAtoms folds findings into categories and subcategories, keeping only
// notable and stronger, in tier order and then first-seen order so the chain
// is stable across renders.
func backboneAtoms(findings []FindingForFormula) []backboneAtom {
	tierOrder := map[string]int{"O": 0, "H": 1, "Md": 2, "K": 3, "Th": 4}
	var atoms []backboneAtom
	index := make(map[string]int)
	for _, f := range findings {
		if f.Severity < SeverityNotable {
			continue
		}
		id, _, _ := strings.Cut(f.ID, "::")
		parts := strings.Split(id, "/")
		if len(parts) < 2 {
			continue
		}
		tier := tierSymbol(parts[0])
		if tier == "" {
			continue
		}
		el, ok := categoryToElement(parts[1])
		if !ok {
			continue
		}
		key := tier + "/" + parts[1]
		i, seen := index[key]
		if !seen {
			i = len(atoms)
			index[key] = i
			atoms = append(atoms, backboneAtom{Tier: tier, Symbol: el.Symbol, Name: parts[1]})
		}
		stub := parts[1]
		if len(parts) > 2 {
			stub = strings.Join(parts[1:min(len(parts), 4)], "/")
		}
		a := &atoms[i]
		found := false
		for j := range a.Stubs {
			if a.Stubs[j].Path == stub {
				found = true
				if f.Severity > a.Stubs[j].Severity {
					a.Stubs[j].Severity = f.Severity
				}
				break
			}
		}
		if !found {
			a.Stubs = append(a.Stubs, backboneStub{Path: stub, Severity: f.Severity})
		}
	}
	// Stable sort by tier; insertion order within a tier.
	for i := 1; i < len(atoms); i++ {
		for j := i; j > 0 && tierOrder[atoms[j].Tier] < tierOrder[atoms[j-1].Tier]; j-- {
			atoms[j], atoms[j-1] = atoms[j-1], atoms[j]
		}
	}
	return atoms
}

// backboneFont is the label face; the page's mono stack, so the drawing
// matches the formula beneath it.
const backboneFont = "SF Mono, Menlo, monospace"

// backboneSVG draws the chain. Coordinates live in a 224×150 box that scales
// to its container. Returns "" when there is nothing to draw so the template
// can drop the card.
func backboneSVG(findings []FindingForFormula) template.HTML {
	atoms := backboneAtoms(findings)
	if len(atoms) == 0 {
		return ""
	}
	const width, height = 224.0, 150.0
	tierColor := map[string]string{"O": "#4A2040", "H": "#CC0077", "Md": "#8A6080", "K": "#4A2040", "Th": "#4A2080"}
	n := len(atoms)
	x0, dx := 16.0, 0.0
	if n > 1 {
		dx = (width - 32) / float64(n-1)
	} else {
		x0 = width / 2
	}
	pos := make([][2]float64, n)
	for i := range atoms {
		y := 78.0
		if i%2 == 1 {
			y = 60
		}
		pos[i] = [2]float64{x0 + float64(i)*dx, y}
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" class="backbone" role="img" aria-label="compound backbone">`, int(width), int(height))
	for i := 0; i+1 < n; i++ {
		fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#4A2040" stroke-width="1.6"></line>`,
			pos[i][0], pos[i][1], pos[i+1][0], pos[i+1][1])
	}
	for i, a := range atoms {
		x, y := pos[i][0], pos[i][1]
		up := i%2 == 1
		k := len(a.Stubs)
		for j, s := range a.Stubs {
			base := math.Pi / 2
			if up {
				base = -math.Pi / 2
			}
			ang := base + (float64(j)-float64(k-1)/2)*0.5
			sx, sy := x+22*math.Cos(ang), y+22*math.Sin(ang)
			fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#4A2040" stroke-width="1.2"></line>`, x, y, sx, sy)
			fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="3" fill="%s"><title>%s</title></circle>`,
				sx, sy, s.Severity.Color(), html.EscapeString(s.Path))
		}
		fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" text-anchor="middle" font-family="%s" font-size="10" font-weight="600" fill="%s"`+
			` stroke="#fdf5fc" stroke-width="4" paint-order="stroke" stroke-linejoin="round"><title>%s</title>%s</text>`,
			x, y+3.6, backboneFont, tierColor[a.Tier], html.EscapeString(a.Name), html.EscapeString(a.Symbol))
		if i == 0 || atoms[i-1].Tier != a.Tier {
			ty := 128.0
			if up {
				ty = 22
			}
			fmt.Fprintf(&b, `<text x="%.1f" y="%.0f" text-anchor="middle" font-family="%s" font-size="8" font-weight="600" fill="%s">%s</text>`,
				x, ty, backboneFont, tierColor[a.Tier], a.Tier)
		}
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec // every dynamic value passes through html.EscapeString or a fixed palette
}
