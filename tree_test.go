package main

import (
	"bytes"
	"strings"
	"testing"
)

// findChild returns the first child of n whose Name matches, or nil.
func findChild(n *treeNode, name string) *treeNode {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// buildFileTree must reconstruct the pid forest, place a fetched dependency
// under the file that declared it (not the archive root), and fold that fetched
// subtree shut by default — the opencv4-llvm shape that motivated the tree.
func TestBuildFileTreeProvenance(t *testing.T) {
	files := []cleaveFile{
		{ID: 0, Path: "opencv4-llvm-4.13.0-2.src.tar.gz", FileType: "gz"},
		{ID: 1, Path: "…src.tar.gz!!opencv4-llvm/PKGBUILD", FileType: "shell", Parent: new(0)},
		{
			ID: 2, Path: "4.13.0", FileType: "gz", Parent: new(1), Rel: "fetched",
			Via: "https://github.com/opencv/opencv/archive/4.13.0.tar.gz",
		},
		{ID: 3, Path: "4.13.0!!opencv-4.13.0/modules/a.py", FileType: "python", Parent: new(2)},
		{
			ID: 4, Path: "opencv4-llvm@4.13.0-2.registry.json", FileType: "registry",
			Parent: new(0), Rel: "registry", Role: "sidecar",
		},
	}

	roots := buildFileTree(files)
	if len(roots) != 1 {
		t.Fatalf("want 1 root, got %d", len(roots))
	}
	root := roots[0]
	if root.Name != "opencv4-llvm-4.13.0-2.src.tar.gz" {
		t.Fatalf("root name = %q", root.Name)
	}
	if root.Descendants != 4 {
		t.Fatalf("root descendants = %d, want 4", root.Descendants)
	}

	// Members fold under the opencv4-llvm/ package directory.
	pkgDir := findChild(root, "opencv4-llvm")
	if pkgDir == nil || !pkgDir.IsDir {
		t.Fatalf("members should nest under the opencv4-llvm/ dir; root children = %+v", root.Children)
	}
	pkgbuild := findChild(pkgDir, "PKGBUILD")
	if pkgbuild == nil {
		t.Fatal("PKGBUILD not found under opencv4-llvm/")
	}
	// The fetched tarball hangs under the PKGBUILD that declared it, not the root.
	if findChild(root, "4.13.0") != nil {
		t.Fatal("4.13.0 should not be a direct child of the archive")
	}
	fetched := findChild(pkgbuild, "4.13.0")
	if fetched == nil {
		t.Fatal("4.13.0 not found under PKGBUILD")
	}
	if fetched.Rel != "fetched" || fetched.ViaHost != "github.com" {
		t.Fatalf("fetched edge = rel:%q host:%q", fetched.Rel, fetched.ViaHost)
	}
	if !fetched.Collapsed && fetched.Rel == "fetched" {
		// fetched subtrees fold by default even when small
		t.Fatal("fetched subtree should default to collapsed")
	}

	reg := findChild(root, "opencv4-llvm@4.13.0-2.registry.json")
	if reg == nil || reg.Role != "sidecar" || reg.Rel != "registry" {
		t.Fatalf("registry sidecar not placed correctly: %+v", reg)
	}
}

// A pid cycle (or self-parent) in a crafted envelope must not loop or panic;
// the tree build simply terminates.
func TestBuildFileTreeCycleSafe(t *testing.T) {
	files := []cleaveFile{
		{ID: 0, Path: "root", Parent: new(0)}, // self-parent → treated as root
		{ID: 1, Path: "a", Parent: new(2)},    // 1 ↔ 2 cycle
		{ID: 2, Path: "b", Parent: new(1)},
	}
	roots := buildFileTree(files) // must return without hanging
	if len(roots) == 0 {
		t.Fatal("self-parented node should still surface as a root")
	}
}

// The recursive treeNode template must render a fetched node's provenance chip
// and linked source host, recurse into a registry-sidecar child, and link each
// row to the member's page — a render check the parse-only test can't catch.
func TestTreeNodeRenders(t *testing.T) {
	tmpl := resultTemplateForTest(t)
	node := &treeNode{
		Name: "4.13.0", SHA256: "1d40ca01", FileType: "gz",
		Rel: "fetched", Via: "https://github.com/opencv/opencv/archive/4.13.0.tar.gz",
		ViaHost: "github.com", Crit: "suspicious", SizeHuman: "95 MB",
		Descendants: 10198, Count: "10,198",
		Children: []*treeNode{
			{Name: "package.json", SHA256: "abc", FileType: "package.json", Role: "sidecar", Crit: "notable"},
		},
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "treeNode", node); err != nil {
		t.Fatalf("treeNode render: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`class="tchip fetch"`,
		`href="https://github.com/opencv/opencv/archive/4.13.0.tar.gz"`,
		"github.com",
		"10,198 files",
		`class="tchip reg"`, // the sidecar child recursed into
		`href="/file/1d40ca01"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("treeNode output missing %q\n---\n%s", want, out)
		}
	}
}

// Older payloads predate pid: every file decodes with Parent==nil, so
// reportHasPid is false and buildFileTree yields a flat forest with no nesting —
// the Structure tab stays hidden and no build work is wasted.
func TestNoPidDegradesGracefully(t *testing.T) {
	files := []cleaveFile{
		{ID: 0, Path: "a.zip", FileType: "zip"},
		{ID: 1, Path: "a.zip!!x.py", FileType: "python"}, // no Parent
		{ID: 2, Path: "a.zip!!y.sh", FileType: "shell"},  // no Parent
	}
	if reportHasPid(files) {
		t.Fatal("reportHasPid should be false for pid-less payloads")
	}
	roots := buildFileTree(files)
	if len(roots) != len(files) {
		t.Fatalf("pid-less data should yield %d flat roots, got %d", len(files), len(roots))
	}
	for _, r := range roots {
		if len(r.Children) != 0 {
			t.Errorf("pid-less root %q unexpectedly has children", r.Name)
		}
	}
}

// buildFileTree folds a container's flat members into a directory tree, merges
// single-child chains (src/a), and lifts each directory's severity to its worst
// file so a folder holding a hostile file shows a hostile dot.
func TestBuildFileTreeNestsDirectories(t *testing.T) {
	files := []cleaveFile{
		{ID: 0, Path: "pkg.zip", FileType: "zip"},
		{ID: 1, Path: "pkg.zip!!src/a/util.py", FileType: "python", Parent: new(0)},
		{
			ID: 2, Path: "pkg.zip!!src/a/evil.py", FileType: "python", Parent: new(0),
			Findings: []finding{{ID: "x", Crit: 5}},
		}, // hostile
		{ID: 3, Path: "pkg.zip!!README.md", FileType: "markdown", Parent: new(0)},
	}
	root := buildFileTree(files)[0]

	if findChild(root, "README.md") == nil {
		t.Fatal("README.md should stay a direct child of the archive")
	}
	srcA := findChild(root, "src/a")
	if srcA == nil || !srcA.IsDir {
		t.Fatalf("src/a should be one merged directory node; root children = %+v", root.Children)
	}
	if srcA.Crit != "hostile" {
		t.Errorf("src/a severity = %q, want hostile (inherited from evil.py)", srcA.Crit)
	}
	if srcA.Descendants != 2 {
		t.Errorf("src/a file count = %d, want 2", srcA.Descendants)
	}
	if findChild(srcA, "evil.py") == nil || findChild(srcA, "util.py") == nil {
		t.Errorf("src/a should hold evil.py and util.py; got %+v", srcA.Children)
	}
}

func TestCommafy(t *testing.T) {
	for _, c := range []struct {
		in   int
		want string
	}{{0, "0"}, {42, "42"}, {999, "999"}, {1000, "1,000"}, {10198, "10,198"}, {1234567, "1,234,567"}} {
		if got := commafy(c.in); got != c.want {
			t.Errorf("commafy(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}
