package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// findMatches locates an aggregated trait by its display ID (dirPath form)
// across all category groups and returns its match rows.
func findMatches(t *testing.T, cats []CategoryGroup, id string) []FindingMatch {
	t.Helper()
	for _, g := range cats {
		for _, f := range g.Findings {
			if f.ID == id {
				return f.Matches
			}
		}
	}
	t.Fatalf("trait %q not found in %+v", id, cats)
	return nil
}

// TestContextProvidesEvidence locks in the v8 path: a finding's `spans` index
// into the file's `ctx` bytes, and the evidence column renders the matched
// content the same way the Content tab does. A binary (hex) window yields a
// hex+ascii dump, a 0x-formatted offset, and no syntax-highlight tokens.
func TestContextProvidesEvidence(t *testing.T) {
	files := []cleaveFile{{
		Path:     "stub.bin",
		FileType: "elf", // binary type → hex view
		Depth:    0,
		Findings: []finding{
			{
				ID: "objectives/execution/interpreter/eval::dynamic", Crit: 3, Conf: 0.9, Desc: "dynamic eval",
				Spans: [][2]int64{{0x6b, 4}},
			},
		},
		Ctx: []contextWindow{{
			Offset: 0x6b,
			Data:   []byte{0xea, 0xfb, 0x32, 0xd5},
		}},
	}}

	got := buildStructuredFindings(files)
	if len(got) != 1 {
		t.Fatalf("expected findings for one file, got %d", len(got))
	}
	m := findMatches(t, got[0].Categories, "execution/interpreter")
	if len(m) != 1 {
		t.Fatalf("expected one match from ctx, got %d: %+v", len(m), m)
	}
	if m[0].Evidence != "ea fb 32 d5  ..2." {
		t.Errorf("evidence = %q, want the hex dump of the ctx bytes", m[0].Evidence)
	}
	if m[0].Location != "0x6b" {
		t.Errorf("location = %q, want hex offset 0x6b (107)", m[0].Location)
	}
	if m[0].Tokens != nil {
		t.Errorf("hex evidence should not be syntax-highlighted, got %d tokens", len(m[0].Tokens))
	}
}

// TestArchiveContextEvidence confirms the archive aggregation path reads ctx
// from inner files and attributes rows to the inner file's name.
func TestArchiveContextEvidence(t *testing.T) {
	containerSHA := strings.Repeat("a", 64)
	innerSHA := strings.Repeat("b", 64)
	files := []cleaveFile{
		{Path: "bundle.zip", SHA256: containerSHA, Depth: 0},
		{
			Path: "bundle.zip!!pkg/index.js", SHA256: innerSHA, FileType: "javascript", Depth: 1,
			Findings: []finding{{
				ID: "objectives/execution/interpreter/eval::call", Crit: 3, Conf: 0.9, Desc: "eval",
				Spans: [][2]int64{{40, 7}},
			}},
			Ctx: []contextWindow{{
				Offset: 40,
				Addr:   ptrInt64(40),
				Data:   []byte("eval(s)"),
			}},
		},
	}

	cats, _, _ := aggregateArchiveCategories(files)
	m := findMatches(t, cats, "execution/interpreter")
	if len(m) != 1 {
		t.Fatalf("expected one ctx match, got %d: %+v", len(m), m)
	}
	if m[0].Filename != "index.js" {
		t.Errorf("filename = %q, want index.js", m[0].Filename)
	}
	if m[0].Evidence != "eval(s)" || m[0].Location != "40" {
		t.Errorf("got evidence=%q location=%q, want eval(s)/40", m[0].Evidence, m[0].Location)
	}
}

// TestArchiveFromAttribution is the v8 archive shape: every member trait is
// rolled up onto the container (depth 0) with a `from` listing the member it
// fired on. The Traits tab must attribute each rollup to its member file (path +
// line/offset) rather than showing a bare offset with no filename.
func TestArchiveFromAttribution(t *testing.T) {
	containerSHA := strings.Repeat("a", 64)
	mdSHA := strings.Repeat("b", 64)
	jsSHA := strings.Repeat("c", 64)
	files := []cleaveFile{
		{
			Path: "src.tar.gz", SHA256: containerSHA, FileType: "tar.gz", Depth: 0,
			Findings: []finding{
				{
					ID: "metadata/file/profile/language::lang-arabic-urdu", Crit: 1, Conf: 0.9,
					Desc: "Arabic script detection (Arabic/Urdu)",
					From: []compactSource{{File: 1}}, Spans: [][2]int64{{19, 10}},
				},
				{
					ID: "objectives/execution/interpreter/eval/invoke::shell-eval", Crit: 3, Conf: 0.9,
					Desc: "Dynamic code evaluation",
					From: []compactSource{{File: 2, Line: ptrInt64(4)}}, Spans: [][2]int64{{60, 9}},
				},
			},
			// Container ctx is only a header sample; it must not become evidence.
			Ctx: []contextWindow{{Offset: 0, Data: []byte{0x1f, 0x8b, 0x08, 0x00}}},
		},
		{Path: "src.tar.gz!!tests/unicode/input.md", SHA256: mdSHA, FileType: "markdown", Depth: 1, ID: 1},
		{Path: "src.tar.gz!!editors/installer.js", SHA256: jsSHA, FileType: "javascript", Depth: 1, ID: 2},
	}

	cats, _, _ := aggregateArchiveCategories(files)

	ar := findMatches(t, cats, "file/profile")
	if len(ar) != 1 || ar[0].Filename != "input.md" {
		t.Fatalf("Arabic trait should attribute to input.md, got %+v", ar)
	}
	se := findMatches(t, cats, "execution/interpreter/eval")
	if len(se) != 1 || se[0].Filename != "installer.js" || se[0].Location != "4" {
		t.Fatalf("shell-eval should attribute to installer.js:4, got %+v", se)
	}
	// The container's header sample must never leak in as evidence.
	for _, c := range cats {
		for _, f := range c.Findings {
			for _, mm := range f.Matches {
				if mm.Filename == "src.tar.gz" {
					t.Errorf("container attributed as a source: %+v", mm)
				}
			}
		}
	}
}

func TestMarkContainers(t *testing.T) {
	pid := func(i int) *int { return &i }
	files := []cleaveFile{
		{ID: 0, FileType: "tar.gz"},                     // archive by type; parent of 1,2,3
		{ID: 1, FileType: "javascript", Parent: pid(0)}, // leaf member
		{ID: 2, FileType: "customfmt", Parent: pid(0)},  // unusual type, container only via child 5
		{ID: 3, FileType: "asar", Parent: pid(0)},       // archive by type; parent of 4
		{ID: 4, FileType: "php", Parent: pid(3)},        // leaf member
		{ID: 5, FileType: "text", Parent: pid(2)},       // makes 2 a structural container
	}
	markContainers(files)
	want := map[int]bool{0: true, 1: false, 2: true, 3: true, 4: false, 5: false}
	for i := range files {
		if got := files[i].Container; got != want[files[i].ID] {
			t.Errorf("id %d (%s): Container=%v want %v", files[i].ID, files[i].FileType, got, want[files[i].ID])
		}
	}
}

// A payload decoded or carved out of a file's readable bytes does not make the
// file a container: its bytes are still the evidence. Only `!!` members that
// are not `embedded:` do, as in cleave's archive_container_paths.
func TestCarvedPath(t *testing.T) {
	for path, want := range map[string]bool{
		"x.zip!!agent.go!!##base64@4296":      true, // as hopper serves cleave's `##` leaf
		"agent.go##base64@0x10c7":             true, // as cleave names it
		"x.zip!!dir/agent.go##base64-obf@0x1": true,
		"setup.exe!!embedded:elf@0x10":        true,
		"plain.js":                            false,
		"x.zip!!a.js":                         false,
		"x.zip!!a##b.tgz!!c.js":               false, // a member of an archive whose name holds ##
		"ci.yml!!/jobs/test/steps/2/run":      false, // a `!!` member, as cleave counts it
	} {
		if got := carvedPath(path); got != want {
			t.Errorf("carvedPath(%q) = %v, want %v", path, got, want)
		}
	}
	pid := func(i int) *int { return &i }
	files := []cleaveFile{
		{ID: 0, FileType: "zip", Path: "x.zip"},
		{ID: 1, FileType: "go", Path: "x.zip!!agent.go", Parent: pid(0)},
		{ID: 2, FileType: "shell", Path: "x.zip!!agent.go!!##base64@4296", Parent: pid(1)},
	}
	markContainers(files)
	if !files[0].Container || files[1].Container {
		t.Errorf("Container = %v, %v; want the zip only", files[0].Container, files[1].Container)
	}
}

// The regions a reader sees first are where the malware is. This Go module
// hides an SSH-key and systemd backdoor in base64 strings in agent.go, whose
// decoded payloads once marked it a container, so the page showed Markdown
// headings and imports instead (2026-11-23).
func TestMalwareRegionsLead(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "solana-vigil-0.1.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	res := storedResult{RawLitmus: string(raw), Classification: "hostile"}
	data := prepareResultData("solana-vigil-0.1.0.zip", strings.Repeat("a", 64), &res)
	var shown []string
	for _, v := range data.FileViews {
		for _, w := range v.Windows {
			shown = append(shown, v.Filename+": "+w.Title)
		}
	}
	if len(shown) < 4 {
		t.Fatalf("regions = %q, want at least four", shown)
	}
	for _, s := range shown[:4] {
		if !strings.HasPrefix(s, "agent.go: ") {
			t.Errorf("first four regions = %q, want all from agent.go", shown[:4])
			break
		}
	}
	if !slices.Contains(shown, "agent.go: Encoded shell appends SSH login keys") {
		t.Errorf("regions = %q, want the SSH key append", shown)
	}
}

// Among otherwise equal regions, one headed by a telling branch of the
// taxonomy comes first, and a region is titled by its telling note over one
// that merely sorts first. Neither outranks severity.
func TestTellingTraitsBreakTies(t *testing.T) {
	note := func(id string, crit int) ctxNoteRef { return ctxNoteRef{ID: id, Crit: crit, Atomic: true} }
	headings := labeledWindow{Notes: []ctxNoteRef{note("metadata/lang/source/syntax/markup/markdown::headings", 3)}, Crit: 3}
	exec := labeledWindow{Notes: []ctxNoteRef{
		note("metadata/import/go/os::os", 3),
		note("micro-behaviors/process/create::exec-command", 3),
	}, Crit: 3}
	hostile := labeledWindow{Notes: []ctxNoteRef{note("metadata/lang/natural/vocabulary::token", 4)}, Crit: 4}

	if got := exec.headNote(nil).ID; got != "micro-behaviors/process/create::exec-command" {
		t.Errorf("exec region titled %q, want its process note", got)
	}
	if windowScore(&exec, nil, nil) <= windowScore(&headings, nil, nil) {
		t.Error("a process region does not outrank a Markdown one of equal severity")
	}
	if windowScore(&hostile, nil, nil) <= windowScore(&exec, nil, nil) {
		t.Error("the taxonomy lift outranked a higher severity")
	}
	if traitIsTelling("metadata/encoded-payload/base64") {
		t.Error("metadata is not a telling branch")
	}
}

func TestContainerBytesNotWindowed(t *testing.T) {
	// A native trait (no From) whose span lands in a file's own ctx window.
	newFile := func(ft string, container bool) *cleaveFile {
		return &cleaveFile{
			FileType: ft, Container: container,
			Findings: []finding{{
				ID:   "metadata/package/quality/empty::npm-has-licenses-array",
				Crit: 3, Conf: 0.9, Desc: "licenses array",
				Spans: [][2]int64{{2, 4}},
			}},
			Ctx: []contextWindow{{Offset: 0, Data: []byte("packed-member-garbage")}},
		}
	}
	if lw := labeledWindows(newFile("javascript", false)); len(lw) == 0 {
		t.Error("non-container should window its native trait")
	}
	if lw := labeledWindows(newFile("gz", true)); len(lw) != 0 {
		t.Errorf("compressed container must not window its packed bytes, got %d windows", len(lw))
	}
	// A binary-content container (e.g. an ELF installer with an appended
	// archive) still has a real own-byte view, so its own code keeps windowing.
	if lw := labeledWindows(newFile("elf", true)); len(lw) == 0 {
		t.Error("binary-content container should still window its own code")
	}
}
