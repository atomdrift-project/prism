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

	pkgbuild := findChild(root, "PKGBUILD")
	if pkgbuild == nil {
		t.Fatal("PKGBUILD not a direct child of the archive")
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
		Descendants: 10198,
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
		"10198 files",
		`class="tchip reg"`, // the sidecar child recursed into
		`href="/file/1d40ca01"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("treeNode output missing %q\n---\n%s", want, out)
		}
	}
}
