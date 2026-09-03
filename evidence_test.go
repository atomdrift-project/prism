package main

import "testing"

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
