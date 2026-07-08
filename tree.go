package main

import (
	"net/url"
	"sort"
)

// maxTreeChildrenExpanded bounds how many direct children a node lists inline
// before the remainder fold into a "+N more" tail. A directory with thousands
// of siblings must not emit thousands of rows into the page.
const maxTreeChildrenExpanded = 200

// collapseChildrenAbove folds a node shut by default once it has more than this
// many direct children, so a wide directory stays scannable while a passthrough
// node (one child that itself holds thousands) stays open. A fetched subtree
// always arrives folded regardless of width.
const collapseChildrenAbove = 24

// treeNode is one row in the containment/provenance tree, built from the flat
// files[] array via the pid edge. It is a pure display object: everything a
// template needs to draw the row and recurse into children, and nothing the
// analysis itself owns.
type treeNode struct {
	Name        string      // basename shown in the row
	Path        string      // full inner path, for the row's title tooltip
	FileType    string      // e.g. "shell", "gz"
	SHA256      string      // links the row to the member's own page
	Rel         string      // edge to parent: "fetched"/"registry"/"unpacked"/""
	Via         string      // full source locator, for rel=="fetched"
	ViaHost     string      // host of Via — the compact "fetched from …" label
	Role        string      // "sidecar" for a metadata node, else ""
	Crit        string      // severity CSS class: hostile/suspicious/notable/…
	SizeHuman   string      // formatted size
	Children    []*treeNode // direct children, severity-then-name ordered
	ID          int
	Descendants int  // total nodes beneath this one (accurate before Hidden)
	Hidden      int  // direct children beyond the render cap, summarized as a tail
	critN       int  // severity rank, for ordering only
	Collapsed   bool // fold shut by default (a large or fetched subtree)
}

// buildFileTree assembles the pid-linked forest from a report's flat files. A
// file with no resolvable parent is a root; every other file hangs under the
// node its pid names. Siblings are ordered severity-first then by name, so the
// riskiest members surface. The traversal carries a visited set, so a pid cycle
// or a diamond in an attacker-crafted envelope terminates instead of looping.
// Returns the roots — usually one, the sample itself.
func buildFileTree(files []cleaveFile) []*treeNode {
	byID := make(map[int]*treeNode, len(files))
	for i := range files {
		f := &files[i]
		crit := maxCritInFile(f)
		byID[f.ID] = &treeNode{
			Name:      extractBasename(f.Path),
			Path:      displayPath(f.Path),
			FileType:  f.FileType,
			SHA256:    f.SHA256,
			Rel:       f.Rel,
			Via:       f.Via,
			ViaHost:   hostOfURL(f.Via),
			Role:      f.Role,
			Crit:      critIntToString(crit),
			SizeHuman: formatBytes(f.Size),
			ID:        f.ID,
			critN:     crit,
		}
	}

	var roots []*treeNode
	for i := range files {
		f := &files[i]
		node := byID[f.ID]
		if f.Parent != nil && *f.Parent != f.ID {
			if parent, ok := byID[*f.Parent]; ok {
				parent.Children = append(parent.Children, node)
				continue
			}
		}
		roots = append(roots, node)
	}

	visited := make(map[int]bool, len(files))
	for _, r := range roots {
		finalizeNode(r, visited)
		r.Collapsed = false // the top of the tree always opens
	}
	sortNodes(roots)
	return roots
}

// finalizeNode counts descendants, orders and caps children, and decides the
// default collapse state, depth-first. The shared visited set makes it
// cycle-safe: a node already folded into the tree is not re-walked.
func finalizeNode(n *treeNode, visited map[int]bool) int {
	if visited[n.ID] {
		n.Children = nil // a cycle re-entered this node; stop here
		return 0
	}
	visited[n.ID] = true

	total := 0
	for _, c := range n.Children {
		total += 1 + finalizeNode(c, visited)
	}
	n.Descendants = total
	sortNodes(n.Children)
	if len(n.Children) > maxTreeChildrenExpanded {
		n.Hidden = len(n.Children) - maxTreeChildrenExpanded
		n.Children = n.Children[:maxTreeChildrenExpanded]
	}
	// A fetched dependency, or a node wide with direct children, arrives folded
	// so it does not bury the sample it rode in with. Roots are re-opened by the
	// caller — the top of the tree always shows.
	n.Collapsed = n.Rel == "fetched" || len(n.Children) > collapseChildrenAbove
	return total
}

// sortNodes orders siblings severity-first, then by name, so the riskiest
// members float to the top of each level while staying stable within a tier.
func sortNodes(ns []*treeNode) {
	sort.SliceStable(ns, func(a, b int) bool {
		if ns[a].critN != ns[b].critN {
			return ns[a].critN > ns[b].critN
		}
		return ns[a].Name < ns[b].Name
	})
}

// hostOfURL returns the host of a source locator for the compact "fetched from
// …" chip, or the raw string when it doesn't parse as a URL (e.g. a bare PURL).
func hostOfURL(raw string) string {
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}
