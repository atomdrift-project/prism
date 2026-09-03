package main

// The malecule drawing. A trait id is two things joined by "::": the directory
// names the behaviour, the leaf names one way to search for it. Two rules that
// depend on different matchers of one behaviour depend on the same thing, so
// the atom is the directory — truncated, because the deepest segments split
// hairs no reader is asking about.
//
// Two kinds of line, kept apart on purpose. A bond is a dependency: some rule
// required this behaviour, drawn solid in the requiring rule's severity. A tie
// is kinship: two behaviours sit under one category, drawn thin, grey and
// dashed. Confusing the two would be the worst thing this picture could do.

import (
	"cmp"
	"slices"
	"strings"
)

// maleculeDepth is how much of a trait's directory names the atom. Three keeps
// "objectives/anti-static/obfuscation" whole while folding its sixteen matchers
// into one atom; four splits hairs the index row has no room for.
const maleculeDepth = 3

// maleculeRing2 caps the outer ring. Past this the drawing stops being read and
// starts being decoration, so the remainder is counted instead.
const maleculeRing2 = 12

// maleculeAtom is one behaviour: every finding whose directory truncates here.
type maleculeAtom struct {
	Key      string // the truncated directory, e.g. "objectives/anti-static/obfuscation"
	Category string // its first two segments, the level kinship is judged at
	Symbol   string
	Crit     string
	Uses     []int
	UsedBy   []int
	conf     float64
	Members  int // matchers behind this atom
	Internal int // dependencies between its own members, invisible at this depth
	IsRule   bool
}

// maleculeGraph is a file's behaviours and the two relations between them.
type maleculeGraph struct {
	Atoms []maleculeAtom
	Ties  [][2]int // kinship: same category, drawn dashed
	// Centres are the atoms worth drawing first, strongest severity first.
	// Ranking by severity rather than by position in the dependency graph is
	// deliberate: collapsing can leave a hostile behaviour with every
	// dependency internal and a parent above it, and it still has to be seen.
	Centres []int
}

func maleculeKey(id string) string {
	dir, _, _ := strings.Cut(id, "::")
	parts := strings.Split(dir, "/")
	return strings.Join(parts[:min(len(parts), maleculeDepth)], "/")
}

func categorySymbol(key string) string {
	parts := strings.Split(key, "/")
	for _, part := range slices.Backward(parts) {
		if el, ok := categoryToElement(part); ok {
			return el.Symbol
		}
	}
	last := parts[len(parts)-1]
	if len(last) > 2 {
		last = last[:2]
	}
	return strings.ToUpper(last[:1]) + last[1:]
}

// buildMaleculeGraph folds a file's findings into behaviours and reads the two
// relations off them. Findings below baseline are dropped: they are matcher
// fragments, and drawing them buries the ones that carry the verdict.
func buildMaleculeGraph(file *cleaveFile) maleculeGraph {
	var graph maleculeGraph
	index := make(map[string]int, len(file.Findings))
	for i := range file.Findings {
		f := &file.Findings[i]
		if f.Crit < 2 {
			continue
		}
		key := maleculeKey(f.ID)
		at, ok := index[key]
		if !ok {
			at = len(graph.Atoms)
			index[key] = at
			cat := key
			if parts := strings.Split(key, "/"); len(parts) > 2 {
				cat = strings.Join(parts[:2], "/")
			}
			graph.Atoms = append(graph.Atoms, maleculeAtom{Key: key, Category: cat, Symbol: categorySymbol(key), Crit: critIntToString(f.Crit)})
		}
		a := &graph.Atoms[at]
		a.Members++
		if f.Crit > critFromString(a.Crit) {
			a.Crit = critIntToString(f.Crit)
		}
		a.conf = max(a.conf, f.Conf)
		if len(f.Uses) > 0 {
			a.IsRule = true
		}
	}
	// Dependencies. An edge inside one atom is internal at this depth: the
	// behaviour is assembled from a finer grain of itself, which earns a ring
	// rather than a bond going nowhere.
	seen := make(map[[2]int]bool)
	for i := range file.Findings {
		f := &file.Findings[i]
		if f.Crit < 2 {
			continue
		}
		from, ok := index[maleculeKey(f.ID)]
		if !ok {
			continue
		}
		for _, j := range f.Uses {
			if j < 0 || j >= len(file.Findings) {
				continue // a stale index names a finding this report does not carry
			}
			to, ok := index[maleculeKey(file.Findings[j].ID)]
			if !ok {
				continue
			}
			if to == from {
				graph.Atoms[from].Internal++
				continue
			}
			if seen[[2]int{from, to}] {
				continue
			}
			seen[[2]int{from, to}] = true
			graph.Atoms[from].Uses = append(graph.Atoms[from].Uses, to)
			graph.Atoms[to].UsedBy = append(graph.Atoms[to].UsedBy, from)
		}
	}
	byCat := make(map[string][]int, len(graph.Atoms))
	for i := range graph.Atoms {
		byCat[graph.Atoms[i].Category] = append(byCat[graph.Atoms[i].Category], i)
	}
	cats := make([]string, 0, len(byCat))
	for c := range byCat {
		cats = append(cats, c)
	}
	slices.Sort(cats)
	for _, c := range cats {
		ids := byCat[c]
		for a := range ids {
			for b := a + 1; b < len(ids); b++ {
				graph.Ties = append(graph.Ties, [2]int{ids[a], ids[b]})
			}
		}
	}
	for i := range graph.Atoms {
		if graph.Atoms[i].IsRule || critFromString(graph.Atoms[i].Crit) >= minNotableCrit {
			graph.Centres = append(graph.Centres, i)
		}
	}
	slices.SortStableFunc(graph.Centres, func(x, y int) int {
		a, b := &graph.Atoms[x], &graph.Atoms[y]
		return cmp.Or(
			cmp.Compare(critFromString(b.Crit), critFromString(a.Crit)),
			cmp.Compare(b.conf, a.conf),
			cmp.Compare(a.Key, b.Key),
		)
	})
	return graph
}

func critFromString(s string) int {
	switch s {
	case "hostile":
		return 5
	case "suspicious":
		return 4
	case "notable":
		return 3
	case "baseline":
		return 2
	default:
		return 1
	}
}

// maleculeFromFormula builds the drawing a feed row can afford. Hopper's feed
// carries a formula string and the sample's few strongest trait ids, not its
// findings, so the row has categories and severities but no dependencies: the
// same atoms, drawn without bonds. That is the honest picture of what the feed
// knows, and it is the same shape the sample page shows for a scan that
// recorded no relations at all.
//
// Giving the list real bonds means teaching hopper to carry the graph; until
// then a reader who wants the structure opens the sample.
func maleculeFromFormula(formula string, traits []feedTrait) maleculeGraph {
	var graph maleculeGraph
	// Severity per category, from the row's top traits — the only per-atom
	// severity the feed projection carries.
	sev := make(map[string]string, len(traits))
	for _, t := range traits {
		dir, _, _ := strings.Cut(t.Full, "::")
		for seg := range strings.SplitSeq(dir, "/") {
			if el, ok := categoryToElement(seg); ok {
				if critFromString(t.Crit) > critFromString(sev[el.Symbol]) {
					sev[el.Symbol] = t.Crit
				}
			}
		}
	}
	for _, group := range parseFormulaGroups(formula) {
		counts := map[string]int{}
		order := []string{}
		for _, sym := range group.Members {
			if counts[sym] == 0 {
				order = append(order, sym)
			}
			counts[sym]++
		}
		for _, sym := range order {
			crit := sev[sym]
			if crit == "" {
				crit = "notable"
			}
			cat := elementCategory(sym)
			graph.Atoms = append(graph.Atoms, maleculeAtom{
				Key: cat, Category: cat, Symbol: sym, Crit: crit, Members: counts[sym],
			})
		}
	}
	byCat := map[string][]int{}
	for i := range graph.Atoms {
		byCat[graph.Atoms[i].Category] = append(byCat[graph.Atoms[i].Category], i)
	}
	for i := range graph.Atoms {
		graph.Centres = append(graph.Centres, i)
	}
	slices.SortStableFunc(graph.Centres, func(a, b int) int {
		return cmp.Compare(critFromString(graph.Atoms[b].Crit), critFromString(graph.Atoms[a].Crit))
	})
	return graph
}

// elementCategory names the category an element symbol stands for, for the
// hover text on a feed row's atom. Unknown symbols name themselves.
func elementCategory(symbol string) string {
	for category, el := range categoryElements {
		if el.Symbol == symbol {
			return category
		}
	}
	return symbol
}
