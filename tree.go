package main

import (
	"cmp"
	"net/url"
	"slices"
	"strconv"
	"strings"
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
// files[] array via the pid edge and then folded into directories by path. It is
// a pure display object: everything a template needs to draw the row and recurse
// into children, and nothing the analysis itself owns.
type treeNode struct {
	Name        string      // basename (file) or directory segment(s)
	Path        string      // full inner path, for the row's title tooltip
	FileType    string      // e.g. "shell", "gz"
	SHA256      string      // links the row to the member's own page (files only)
	Rel         string      // edge to parent: "fetched"/"registry"/"unpacked"/""
	Via         string      // full source locator, for rel=="fetched"
	ViaHost     string      // host of Via — the compact "fetched from …" label
	Role        string      // "sidecar" for a metadata node, else ""
	Crit        string      // severity CSS class: hostile/suspicious/notable/…
	SizeHuman   string      // formatted size (files only)
	Count       string      // commafied file count beneath (containers/dirs)
	Children    []*treeNode // direct children, severity-then-name ordered
	ID          int
	Descendants int  // file count beneath this node (accurate before Hidden)
	Hidden      int  // direct children beyond the render cap, summarized as a tail
	critN       int  // severity rank, for ordering only
	IsDir       bool // a synthesized directory node — no sha, no findings
	Collapsed   bool // fold shut by default (a large or fetched subtree)
}

// reportHasPid reports whether any file carries a parent edge — the signal that
// a payload is new enough to have a containment tree. Older payloads predate
// `pid` and decode with every Parent nil, so the whole tree build (and the
// Structure tab) is skipped for them rather than assembling a flat forest the
// tab would hide anyway.
func reportHasPid(files []cleaveFile) bool {
	for i := range files {
		if files[i].Parent != nil {
			return true
		}
	}
	return false
}

// buildFileTree assembles the containment tree from a report's flat files: the
// pid edge nests each member under its container, then each container's members
// fold into a directory tree keyed on their paths. A file with no resolvable
// parent is a root. Siblings order severity-first then by name. The finalize
// pass carries a per-node visited set, so a pid cycle in an attacker-crafted
// envelope terminates instead of looping. Returns the roots — usually one.
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

	visited := make(map[*treeNode]bool, len(files))
	for _, r := range roots {
		nestByDir(r)      // fold flat members into a directory tree
		mergeDirChains(r) // collapse single-child dir chains (a/b/c)
		finalizeNode(r, visited)
		r.Collapsed = false // the top of the tree always opens
	}
	sortNodes(roots)
	return roots
}

// nestByDir folds a node's flat pid-children into a directory tree keyed on their
// relative paths, so an archive browses like a filesystem instead of a flat
// member dump. Recurses first, so a nested archive's own members nest too.
func nestByDir(n *treeNode) {
	for _, c := range n.Children {
		nestByDir(c)
	}
	if len(n.Children) > 0 {
		n.Children = groupByDir(n.Children)
	}
}

// groupByDir builds directory nesting from a flat list of file nodes: files
// sharing a leading path segment fold under a synthesized directory node,
// recursively. A file with no directory prefix stays at the top level.
func groupByDir(children []*treeNode) []*treeNode {
	type entry struct {
		node *treeNode
		segs []string // directory segments remaining above this file
	}
	var build func([]entry) []*treeNode
	build = func(es []entry) []*treeNode {
		var files []*treeNode
		var order []string
		byDir := map[string][]entry{}
		for _, e := range es {
			if len(e.segs) == 0 {
				files = append(files, e.node)
				continue
			}
			seg := e.segs[0]
			if _, ok := byDir[seg]; !ok {
				order = append(order, seg)
			}
			byDir[seg] = append(byDir[seg], entry{segs: e.segs[1:], node: e.node})
		}
		out := files
		for _, seg := range order {
			out = append(out, &treeNode{Name: seg, IsDir: true, Children: build(byDir[seg])})
		}
		return out
	}

	entries := make([]entry, 0, len(children))
	for _, c := range children {
		entries = append(entries, entry{segs: splitDirs(c.Path), node: c})
	}
	return build(entries)
}

// splitDirs returns the directory segments of a relative path — everything above
// the basename. "a/b/c.py" → ["a","b"]; "c.py" → nil.
func splitDirs(path string) []string {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return nil
	}
	return strings.Split(path[:i], "/")
}

// mergeDirChains collapses a single-child directory chain into one row (a/b/c),
// so a deep path with no branching doesn't cost a click per empty level.
func mergeDirChains(n *treeNode) {
	for _, c := range n.Children {
		mergeDirChains(c)
	}
	for n.IsDir && len(n.Children) == 1 && n.Children[0].IsDir {
		only := n.Children[0]
		n.Name += "/" + only.Name
		n.Children = only.Children
	}
}

// finalizeNode counts files, inherits severity into directory nodes, orders and
// caps children, and sets the default collapse state, depth-first. The shared
// visited set is keyed by node pointer — synthesized dir nodes have no id — so
// it stays cycle-safe against a pid cycle in a crafted envelope.
func finalizeNode(n *treeNode, visited map[*treeNode]bool) int {
	if visited[n] {
		n.Children = nil // a cycle re-entered this node; stop here
		return 0
	}
	visited[n] = true

	files := 0
	for _, c := range n.Children {
		below := finalizeNode(c, visited)
		if c.IsDir {
			files += below
		} else {
			files += 1 + below
		}
		if n.IsDir && c.critN > n.critN {
			n.critN = c.critN // a directory takes its worst child's severity
		}
	}
	n.Descendants = files
	n.Count = commafy(files)
	if n.IsDir {
		n.Crit = critIntToString(n.critN)
	}
	sortNodes(n.Children)
	if len(n.Children) > maxTreeChildrenExpanded {
		n.Hidden = len(n.Children) - maxTreeChildrenExpanded
		n.Children = n.Children[:maxTreeChildrenExpanded]
	}
	// A fetched dependency, or a node wide with direct children, arrives folded so
	// it does not bury the sample it rode in with. Roots re-open in the caller.
	n.Collapsed = n.Rel == "fetched" || len(n.Children) > collapseChildrenAbove
	return files
}

// sortNodes orders siblings severity-first, then by name, so the riskiest members
// float to the top of each level while staying stable within a tier.
func sortNodes(ns []*treeNode) {
	slices.SortStableFunc(ns, func(a, b *treeNode) int {
		return cmp.Or(cmp.Compare(b.critN, a.critN), cmp.Compare(a.Name, b.Name))
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

// commafy formats a count with thousands separators: 10198 → "10,198".
func commafy(n int) string {
	s := strconv.Itoa(n)
	if n < 1000 {
		return s
	}
	var b strings.Builder
	if pre := len(s) % 3; pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := len(s) % 3; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}
