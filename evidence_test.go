package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFoldContext keeps two plain rows around each match, folds longer plain
// runs, and leaves runs too short to be worth a marker alone.
func TestFoldContext(t *testing.T) {
	rows := make([]contextRow, 20)
	for i := range rows {
		rows[i].Loc = string(rune('a' + i))
	}
	rows[3].Crit = "hostile"
	rows[15].Crit = "notable"
	for i := 4; i <= 9; i++ { // the hostile span runs on for six rows; its tail folds like context
		rows[i].Crit, rows[i].Cont = "hostile", true
	}
	got := foldContext(contextBlock{Rows: rows})
	var locs []string
	for _, r := range got.Rows {
		if r.Gap > 0 {
			locs = append(locs, "gap"+string(rune('0'+r.Gap)))
			continue
		}
		locs = append(locs, r.Loc)
	}
	want := "a b c d e f gap7 n o p q r s t"
	if joined := joinStrings(locs); joined != want {
		t.Errorf("folded rows = %q, want %q", joined, want)
	}
	if short := foldContext(contextBlock{Rows: rows[:4]}); len(short.Rows) != 4 {
		t.Errorf("short block must pass through, got %d rows", len(short.Rows))
	}
	if r := windowRange(contextBlock{Rows: []contextRow{{Loc: "22:19"}, {Loc: "49"}}}); r != "lines 22–49" {
		t.Errorf("windowRange = %q, want the column dropped", r)
	}
}

func joinStrings(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += " "
		}
		out += x
	}
	return out
}

// TestBadgesAndFindingsWithoutSpans covers a sample whose findings carry no
// byte spans — an LNK inside a zip, where cleave reports the verdict's reasons
// but no line to light. The badges must still name them, and the evidence must
// fall back to the findings themselves rather than an empty page.
func TestBadgesAndFindingsWithoutSpans(t *testing.T) {
	files := []cleaveFile{
		{ID: 0, Path: "sample.zip", FileType: "zip", Findings: []finding{
			{ID: "objectives/execution/lnk/proxy::command-c-argument", Desc: "LNK target proxies a command", Crit: 4, Conf: 0.9},
			{ID: "metadata/file/profile/identity::hex-hash-zip-basename", Desc: "Archive named for its own hash", Crit: 3, Conf: 0.8},
		}},
		{ID: 1, Path: "sample.zip!!DOC.lnk", FileType: "lnk", Depth: 2, Findings: []finding{
			{ID: "objectives/anti-static/obfuscation/string/anomaly::lnk-cmd-delayed-sub", Desc: "Delayed substitution hides the command", Crit: 4, Conf: 0.95},
			{ID: "objectives/execution/lnk/proxy::command-c-argument", Desc: "LNK target proxies a command", Crit: 4, Conf: 0.9},
			{ID: "micro-behaviors/process/create/shortcut::lnk-cmd-target", Desc: "Shortcut targets cmd.exe", Crit: 3, Conf: 0.9},
		}},
	}
	badges := resultBadges(nil, files)
	if len(badges) != 2 {
		t.Fatalf("badges = %+v, want the two suspicious findings", badges)
	}
	if badges[0].Desc != "Delayed substitution hides the command" || badges[0].Crit != "suspicious" {
		t.Errorf("strongest badge = %+v, want the highest-confidence suspicious finding", badges[0])
	}
	rows, hidden := fallbackFindings(nil, files)
	if hidden != 0 || len(rows) != 4 {
		t.Fatalf("rows = %+v (hidden %d), want the four distinct notable-and-up findings", rows, hidden)
	}
	if rows[0].Crit != "suspicious" || rows[len(rows)-1].Crit != "notable" {
		t.Errorf("rows must run strongest first, got %+v", rows)
	}
	if rows[0].File == "" {
		t.Error("a finding must name the member file that reported it")
	}
	if got, _ := fallbackFindings([]fileView{{}}, files); got != nil {
		t.Errorf("regions exist, so the fallback list must stay empty; got %+v", got)
	}
}

// TestRegionsAreDistinct guards the reader against the same sentence repeated
// down the page: a composite fires wherever any of its legs match, so titling
// each region by the strongest note gave one Go binary five identical headings.
// Every region in a file must name a different behaviour.
func TestRegionsAreDistinct(t *testing.T) {
	for _, name := range []string{"paysafe-kyc-1.0.2.json", "lnk-in-zip.json"} {
		raw, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		res := storedResult{RawLitmus: string(raw), Classification: "hostile"}
		data := prepareResultData(name, strings.Repeat("a", 64), &res)
		for _, v := range data.FileViews {
			seen := make(map[string]bool)
			for _, w := range v.Windows {
				if w.Title == "" {
					continue
				}
				if seen[w.Title] {
					t.Errorf("%s: %s repeats the region title %q", name, v.Path, w.Title)
				}
				seen[w.Title] = true
			}
		}
	}
}
