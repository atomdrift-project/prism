package main

import (
	"html/template"
	"strings"
	"testing"
	"time"
)

// Shared 64-hex SHAs for tests that render feed rows (also used by the atom
// and dependency-chip tests).
const (
	testSHAHero = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testSHABare = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testSHARow  = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// falloutTestNow is a fixed UTC reference; rows are placed relative to it.
var falloutTestNow = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

// templateFuncsForTest mirrors the FuncMap main() registers, so template
// tests catch syntax errors that would otherwise crash the server at startup.
func templateFuncsForTest() template.FuncMap {
	return template.FuncMap{
		"isPublic":         func() bool { return false },
		"buildCommit":      func() string { return "abcdef0123456789" },
		"buildCommitShort": func() string { return "abcde" },
		"mul":              func(a, b float64) float64 { return a * b },
		"formulaQuery":     func(s string) string { return s },
		"deref": func(p *int) int {
			if p == nil {
				return 0
			}
			return *p
		},
		"ecoColor":  func(string) string { return "slate" },
		"chromaCSS": func() template.CSS { return "" },
		"commaInt":  commaInt,
	}
}

// uploadTemplateForTest parses the frontpage template the way main() does;
// shared by the dependency-chip tests.
func uploadTemplateForTest(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("upload.html").Funcs(templateFuncsForTest()).
		ParseFS(templatesFS, "templates/base.html", "templates/upload.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return tmpl
}

func hostileRow(sha, eco, fileType, formula, pkg string, age time.Duration) feedRow {
	return feedRow{
		SHA256:         sha,
		Filename:       pkg + ".tgz",
		Package:        pkg,
		Classification: "hostile",
		Ecosystem:      eco,
		FileType:       fileType,
		Formula:        formula,
		AnalyzedAt:     falloutTestNow.Add(-age),
	}
}

func shaN(n byte) string { return strings.Repeat(string([]byte{'a' + n%16}), 64) }

func TestBuildFalloutViewWaves(t *testing.T) {
	var rows []feedRow
	// A same-day npm wave: one formula, one file type, four members. The
	// exemplar must be the top-downloaded member.
	for i := range 4 {
		r := hostileRow(shaN(byte(i)), "npm", "javascript", "O3(CCa2)", "squat-"+string(rune('a'+i)), 2*time.Hour)
		if i == 2 {
			r.Downloads = 9000
		}
		rows = append(rows, r)
	}
	// Two singles (a rare-sector catch and an older one on another day),
	// then two rows that must be excluded: outside the window, and outside
	// the verdict.
	rows = append(rows,
		hostileRow(testSHABare, "aur", "shell", "H2(ExPe)", "librewolf-fix-bin", 3*time.Hour),
		hostileRow(testSHARow, "pypi", "python", "O2(CaEu)", "requests-toolkit", 30*time.Hour),
		hostileRow(shaN(10), "npm", "javascript", "O1(C)", "old-catch", 8*24*time.Hour),
		func() feedRow {
			r := hostileRow(shaN(11), "npm", "javascript", "O1(C)", "benign-row", time.Hour)
			r.Classification = "benign"
			return r
		}(),
	)

	view := buildFalloutView(rows, []string{"npm", "aur", "pypi", "rubygems"}, falloutTestNow, "")
	if view.WeeklyCount != 6 {
		t.Errorf("WeeklyCount = %d, want 6 (wave of 4 + 2 singles)", view.WeeklyCount)
	}
	if len(view.Days) != 2 {
		t.Fatalf("days = %d, want 2", len(view.Days))
	}
	today := view.Days[0]
	if today.Label != "TODAY" {
		t.Errorf("first band label = %q, want TODAY", today.Label)
	}
	if len(today.Rows) != 2 {
		t.Fatalf("today rows = %d, want 2 (wave + aur single)", len(today.Rows))
	}
	wave := today.Rows[0]
	if !wave.IsWave() || wave.WaveSize != 4 || wave.Siblings != 3 {
		t.Errorf("first row must be the wave of 4, got IsWave=%v size=%d", wave.IsWave(), wave.WaveSize)
	}
	if wave.Package != "squat-c" {
		t.Errorf("wave exemplar = %q, want the top-downloaded squat-c", wave.Package)
	}
	if single := today.Rows[1]; single.Ecosystem != "aur" || single.IsWave() {
		t.Errorf("second row must be the aur single, got %q (wave=%v)", single.Ecosystem, single.IsWave())
	}
	if view.Days[1].Label != "YESTERDAY" {
		t.Errorf("second band label = %q, want YESTERDAY", view.Days[1].Label)
	}

	// The sector strip: damage-descending, then the quiet watched sector.
	if len(view.Sectors) != 4 {
		t.Fatalf("sectors = %d, want 4", len(view.Sectors))
	}
	if view.Sectors[0].Ecosystem != "npm" || view.Sectors[0].Count != 4 {
		t.Errorf("first sector = %+v, want npm ×4", view.Sectors[0])
	}
	last := view.Sectors[3]
	if last.Ecosystem != "rubygems" || !last.Quiet {
		t.Errorf("last sector = %+v, want quiet rubygems", last)
	}
}

func TestBuildFalloutViewEcosystemFilter(t *testing.T) {
	rows := []feedRow{
		hostileRow(testSHAHero, "npm", "javascript", "O1(C)", "one", time.Hour),
		hostileRow(testSHABare, "pypi", "python", "O2(CaEu)", "two", 2*time.Hour),
	}
	view := buildFalloutView(rows, nil, falloutTestNow, "pypi")
	if view.WeeklyCount != 2 {
		t.Errorf("WeeklyCount = %d, want 2 — the filter narrows the log, not the totals", view.WeeklyCount)
	}
	if len(view.Days) != 1 || len(view.Days[0].Rows) != 1 || view.Days[0].Rows[0].Ecosystem != "pypi" {
		t.Fatalf("filtered log = %+v, want exactly the pypi row", view.Days)
	}
	// The strip keeps both sectors so the chips stay navigable.
	if len(view.Sectors) != 2 {
		t.Errorf("sectors = %d, want 2 (strip is never filtered)", len(view.Sectors))
	}
}

func TestBuildFalloutViewWindowLabel(t *testing.T) {
	// Rows spanning the full window: the snapshot reaches the window's edge,
	// so the label stays "this week".
	full := []feedRow{
		hostileRow(testSHAHero, "npm", "javascript", "O1(C)", "new", time.Hour),
		hostileRow(testSHABare, "npm", "javascript", "O2(CC)", "old", 6*24*time.Hour),
	}
	if got := buildFalloutView(full, nil, falloutTestNow, "").WindowLabel; got != "this week" {
		t.Errorf("full-window label = %q, want this week", got)
	}
	// A full feedLimit snapshot entirely inside the window: the snapshot ran
	// out of depth first, and the label must claim only the days it covers.
	truncated := make([]feedRow, 0, feedLimit)
	for i := range feedLimit {
		truncated = append(truncated, hostileRow(shaN(byte(i)), "npm", "javascript", "O1(C)", "pkg", time.Duration(i)*time.Minute))
	}
	want := "since " + falloutTestNow.Add(-time.Duration(feedLimit-1)*time.Minute).Format("Jan 2")
	if got := buildFalloutView(truncated, nil, falloutTestNow, "").WindowLabel; got != want {
		t.Errorf("truncated label = %q, want %q", got, want)
	}
}

func TestFalloutSectorsQuietCap(t *testing.T) {
	week := []feedRow{hostileRow(testSHAHero, "npm", "javascript", "O1(C)", "one", time.Hour)}
	watched := []string{"npm"}
	for i := range falloutQuietMax + 4 {
		watched = append(watched, "quiet-"+string(rune('a'+i)))
	}
	sectors, overflow := falloutSectors(week, week, watched, "")
	if overflow != 4 {
		t.Errorf("overflow = %d, want 4", overflow)
	}
	if len(sectors) != 1+falloutQuietMax {
		t.Errorf("sectors = %d, want %d (1 damage + capped quiet)", len(sectors), 1+falloutQuietMax)
	}
	// An actively-filtered quiet sector beyond the cap keeps its chip.
	sectors, overflow = falloutSectors(week, week, watched, watched[len(watched)-1])
	if overflow != 3 {
		t.Errorf("overflow with active tail sector = %d, want 3", overflow)
	}
	if !sectors[len(sectors)-1].Active {
		t.Error("the filtered quiet sector must survive the cap")
	}
}

func TestSplitWavesSectorQuota(t *testing.T) {
	// Six distinct npm formulas (no wave) must trim to the per-sector quota.
	var rows []feedRow
	for i := range 6 {
		rows = append(rows, hostileRow(shaN(byte(i)), "npm", "javascript", "O1(C"+string(rune('0'+i))+")", "pkg", time.Hour))
	}
	rows = append(rows, hostileRow(testSHABare, "crates", "rust", "H2(ExPe)", "rare", time.Hour))
	eco := map[string]int{"npm": 6, "crates": 1}
	formula := map[string]int{}
	for _, r := range rows {
		formula[r.Formula]++
	}
	waves, singles := splitWaves(rows, eco, formula, len(rows))
	if len(waves) != 0 {
		t.Fatalf("waves = %d, want 0 (all formulas distinct)", len(waves))
	}
	npm, crates := 0, 0
	for _, s := range singles {
		switch s.Ecosystem {
		case "npm":
			npm++
		case "crates":
			crates++
		}
	}
	if npm != falloutSinglesPerSector {
		t.Errorf("npm singles = %d, want the quota %d", npm, falloutSinglesPerSector)
	}
	if crates != 1 {
		t.Errorf("crates singles = %d, want 1 — rare sectors always fit", crates)
	}
}

func TestDecorateFalloutRowsRibbons(t *testing.T) {
	blast := hostileRow(testSHAHero, "chrome", "crx", "O4(AlCCa2)", "pdf-tool", time.Hour)
	blast.Downloads = 128000
	blast.Corroborated = true
	first := hostileRow(testSHABare, "aur", "shell", "H2(ExPe)", "librewolf", 2*time.Hour)
	rows := []falloutRow{{feedRow: blast}, {feedRow: first}}
	decorateFalloutRows(rows, falloutTestNow)
	if rows[0].Ribbon != "biggest blast radius" {
		t.Errorf("blast ribbon = %q", rows[0].Ribbon)
	}
	if rows[1].Ribbon != "first seen anywhere" {
		t.Errorf("first-seen ribbon = %q", rows[1].Ribbon)
	}
	if rows[0].HeatClass != "heat-2" || rows[1].HeatClass != "heat-2" {
		t.Errorf("decay classes = %q/%q, want heat-2 under six hours", rows[0].HeatClass, rows[1].HeatClass)
	}
}

func TestParseFormulaGroups(t *testing.T) {
	groups := parseFormulaGroups("O3(CCa2)H2")
	if len(groups) != 2 {
		t.Fatalf("groups = %+v, want 2", groups)
	}
	if groups[0].Lead != "O" || strings.Join(groups[0].Members, ",") != "C,Ca,Ca" {
		t.Errorf("composite group = %+v, want O(C,Ca,Ca)", groups[0])
	}
	if groups[1].Lead != "" || strings.Join(groups[1].Members, ",") != "H,H" {
		t.Errorf("standalone group = %+v, want (H,H)", groups[1])
	}
	// Subscripted digits (the display form) parse identically, and huge
	// member counts cap instead of minting undrawable atoms.
	if got := parseFormulaGroups("H₂(Cm₆₅Db₃₉)"); len(got) != 1 || len(got[0].Members) != 2*molRingMax {
		t.Errorf("subscripted groups = %+v, want one group with capped members", got)
	}
	if got := parseFormulaGroups(""); got != nil {
		t.Errorf("empty formula groups = %+v, want nil", got)
	}
}

func TestSkeletalSVGRingPriority(t *testing.T) {
	// A real-shaped formula leads with provenance (K) and metadata groups;
	// the ring must still come from the objectives group, where the hostile
	// structure lives.
	traits := []feedTrait{
		{ID: "exec", Full: "objectives/execution/hta", Crit: "hostile"},
	}
	svg := string(skeletalSVG("K3(Am3Li15)O2(XeEr)Md12(Bi12Pa16)", traits))
	if !strings.Contains(svg, ">Xe</text>") {
		t.Errorf("objectives members must draw (and Xe label via the execution trait), got %q", svg)
	}
	if strings.Contains(svg, ">Li</text>") || strings.Contains(svg, ">Pa</text>") {
		t.Errorf("metadata/provenance members must not outrank objectives, got %q", svg)
	}
}

func TestSkeletalSVG(t *testing.T) {
	traits := []feedTrait{
		{ID: "cred.wallet-keys", Full: "objectives/credential-access/wallet-keys", Crit: "hostile"},
	}
	svg := string(skeletalSVG("O3(CCa2)", traits))
	if !strings.Contains(svg, "<svg") || !strings.Contains(svg, "</svg>") {
		t.Fatalf("not an svg: %q", svg)
	}
	// The credential-access trait colors the Ca atoms hostile.
	if !strings.Contains(svg, `class="e-h"`) || !strings.Contains(svg, ">Ca</text>") {
		t.Errorf("expected hostile Ca labels, got %q", svg)
	}
	// Untouched symbols stay bare vertices — no C label without a c2 trait.
	if strings.Contains(svg, ">C</text>") {
		t.Errorf("C must stay an unlabeled vertex, got %q", svg)
	}
	// Determinism: the same inputs draw the same bytes.
	if again := string(skeletalSVG("O3(CCa2)", traits)); again != svg {
		t.Error("thumbnail must be deterministic")
	}
	// A hostile symbol embedded in a formula never escapes into markup.
	if hostile := string(skeletalSVG(`O1(<b>)`, nil)); strings.Contains(hostile, "<b>") {
		t.Errorf("unescaped markup in %q", hostile)
	}
}

func TestFalloutTemplateRenders(t *testing.T) {
	tmpl, err := template.New("fallout.html").Funcs(templateFuncsForTest()).
		ParseFS(templatesFS, "templates/base.html", "templates/fallout.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	wave := hostileRow(testSHAHero, "npm", "javascript", "O3(CCa2)", "solana-web3-utils", 2*time.Hour)
	wave.TimeAgo = "2h ago"
	rows := []falloutRow{{
		feedRow:   wave,
		WaveSize:  23,
		Siblings:  22,
		HeatClass: "heat-2",
		MolSVG:    skeletalSVG(wave.Formula, nil),
		Ribbon:    "biggest blast radius",
	}}
	data := falloutPageData{
		HasHopper:   true,
		WeeklyCount: 47,
		WindowLabel: "this week",
		MeterSegs:   []bool{true, true, false, false, false, false},
		Sectors: []falloutSector{
			{Ecosystem: "npm", Color: "red", Count: 24},
			{Ecosystem: "rubygems", Color: "yellow", Quiet: true, LastCatch: "Jul 26"},
		},
		Days: []falloutDay{{Label: "TODAY", Sub: "Mon Aug 4 · 24 catches · 1 wave · 0 singles", Rows: rows}},
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	html := sb.String()
	for _, want := range []string{
		"🌊",
		"and 22 siblings",
		"/file/" + testSHAHero,
		"SECTOR SURVEY",
		"biggest blast radius",
		"/fallout?ecosystem=npm",
		"quiet — nothing hostile this week; last catch Jul 26",
		"heat-2",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered fallout page missing %q", want)
		}
	}
}
