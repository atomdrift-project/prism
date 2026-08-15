package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
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

// hostileRow builds a row that clears the fallout gate (falloutQualifies): a
// hostile verdict with an LLM summary and a hostile LLM grade. Tests that
// probe the gate itself override Why/LLMGrade.
func hostileRow(sha, eco, fileType, formula, pkg string, age time.Duration) feedRow {
	return feedRow{
		SHA256:         sha,
		Filename:       pkg + ".tgz",
		Package:        pkg,
		Classification: "hostile",
		Ecosystem:      eco,
		FileType:       fileType,
		Formula:        formula,
		Why:            "exfiltrates credentials on install",
		LLMGrade:       "hostile",
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

	view := buildFalloutView(rows, falloutTestNow, "")
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

	// The sector strip: damage-descending, zero-count sectors get no chip.
	if len(view.Sectors) != 3 {
		t.Fatalf("sectors = %d, want 3 (no zero-count chips)", len(view.Sectors))
	}
	if view.Sectors[0].Ecosystem != "npm" || view.Sectors[0].Count != 4 {
		t.Errorf("first sector = %+v, want npm ×4", view.Sectors[0])
	}
}

func TestBuildFalloutViewEcosystemFilter(t *testing.T) {
	rows := []feedRow{
		hostileRow(testSHAHero, "npm", "javascript", "O1(C)", "one", time.Hour),
		hostileRow(testSHABare, "pypi", "python", "O2(CaEu)", "two", 2*time.Hour),
	}
	view := buildFalloutView(rows, falloutTestNow, "pypi")
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

// TestBuildFalloutViewQualifies pins the gate: a hostile catch reaches the log
// only when the LLM ran, left a summary, and graded the sample hostile itself
// — a blended-hostile verdict the LLM downgraded (or never scored) stays off.
func TestBuildFalloutViewQualifies(t *testing.T) {
	tune := func(pkg, why, grade string) feedRow {
		r := hostileRow(shaN(byte(len(pkg))), "npm", "javascript", "O1(C)", pkg, time.Hour)
		r.Why, r.LLMGrade = why, grade
		return r
	}
	rows := []feedRow{
		tune("no-summary", "", "hostile"),               // graded hostile but no LLM summary
		tune("llm-downgraded", "summary", "suspicious"), // LLM disagrees with the blend
		tune("no-llm-pass", "summary", ""),              // no LLM verdict at all
		tune("llm-hostile", "summary", "hostile"),       // LLM agrees — qualifies
	}
	view := buildFalloutView(rows, falloutTestNow, "")
	if view.WeeklyCount != 1 {
		t.Fatalf("WeeklyCount = %d, want 1 (llm-hostile only)", view.WeeklyCount)
	}
	kept := map[string]bool{}
	for _, day := range view.Days {
		for _, row := range day.Rows {
			kept[row.Package] = true
		}
	}
	for _, pkg := range []string{"no-summary", "llm-downgraded", "no-llm-pass"} {
		if kept[pkg] {
			t.Errorf("%q should have been gated out of the log", pkg)
		}
	}
	if !kept["llm-hostile"] {
		t.Error("llm-hostile should have qualified for the log")
	}
}

func TestBuildFalloutViewWindowLabel(t *testing.T) {
	// Rows spanning the full window: the snapshot reaches the window's edge,
	// so the label stays "this week".
	full := []feedRow{
		hostileRow(testSHAHero, "npm", "javascript", "O1(C)", "new", time.Hour),
		hostileRow(testSHABare, "npm", "javascript", "O2(CC)", "old", 6*24*time.Hour),
	}
	if got := buildFalloutView(full, falloutTestNow, "").WindowLabel; got != "this week" {
		t.Errorf("full-window label = %q, want this week", got)
	}
	// A full feedLimit snapshot entirely inside the window: the snapshot ran
	// out of depth first, and the label must claim only the days it covers.
	truncated := make([]feedRow, 0, feedLimit)
	for i := range feedLimit {
		truncated = append(truncated, hostileRow(shaN(byte(i)), "npm", "javascript", "O1(C)", "pkg", time.Duration(i)*time.Minute))
	}
	want := "since " + falloutTestNow.Add(-time.Duration(feedLimit-1)*time.Minute).Format("Jan 2")
	if got := buildFalloutView(truncated, falloutTestNow, "").WindowLabel; got != want {
		t.Errorf("truncated label = %q, want %q", got, want)
	}
}

// TestBuildFalloutViewViewerZone pins the reader's-calendar rule at the hour
// it used to break: 21:51 in New York is already the next day in UTC, so a
// UTC-grouped log titled the reader's own Friday "YESTERDAY" and split its
// evening off into a second band.
func TestBuildFalloutViewViewerZone(t *testing.T) {
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("no zone database: %v", err)
	}
	utcNow := time.Date(2026, 8, 15, 1, 51, 0, 0, time.UTC) // Fri 21:51 in New York
	rows := []feedRow{
		// Fri 18:00 in New York; Friday in both zones.
		hostileRow(testSHAHero, "npm", "javascript", "O1(C)", "afternoon", 3*time.Hour+51*time.Minute),
		// Fri 20:30 in New York, but already Saturday in UTC.
		hostileRow(testSHABare, "pypi", "python", "O2(CaEu)", "evening", time.Hour+21*time.Minute),
	}
	for i := range rows {
		rows[i].AnalyzedAt = utcNow.Add(rows[i].AnalyzedAt.Sub(falloutTestNow))
	}

	view := buildFalloutView(rows, utcNow.In(ny), "")
	if len(view.Days) != 1 {
		t.Fatalf("bands = %d, want 1: both catches happened on the reader's Friday", len(view.Days))
	}
	band := view.Days[0]
	if band.Label != "TODAY" {
		t.Errorf("band label = %q, want TODAY: it is still Friday in New York", band.Label)
	}
	if !strings.HasPrefix(band.Sub, "Fri Aug 14 ") {
		t.Errorf("band subtitle = %q, want it to lead with Fri Aug 14", band.Sub)
	}
	if len(band.Rows) != 2 {
		t.Errorf("band rows = %d, want 2 (the 20:30 catch belongs to the reader's Friday)", len(band.Rows))
	}

	// The same instant read in UTC is what the reader was complaining about.
	if utc := buildFalloutView(rows, utcNow, ""); len(utc.Days) != 2 || utc.Days[1].Label != "YESTERDAY" {
		t.Errorf("UTC view = %d bands (second %q), want 2 with YESTERDAY — the behavior this fix replaces",
			len(utc.Days), utc.Days[len(utc.Days)-1].Label)
	}
}

func TestViewerLocation(t *testing.T) {
	tests := []struct {
		name   string
		cookie string // "" means no cookie at all
		want   string
	}{
		{"no cookie", "", "UTC"},
		{"iana zone", "America/New_York", "America/New_York"},
		{"utc", "UTC", "UTC"},
		{"underscored and signed", "Etc/GMT+5", "Etc/GMT+5"},
		{"empty value", "=", "UTC"},
		{"server zone refused", "Local", "UTC"},
		{"unknown zone", "Mars/Olympus_Mons", "UTC"},
		{"traversal", "../../etc/passwd", "UTC"},
		{"overlong", strings.Repeat("A", maxTZNameLen+1), "UTC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/fallout", http.NoBody)
			if tt.cookie != "" {
				r.Header.Set("Cookie", tzCookieName+"="+strings.TrimPrefix(tt.cookie, "="))
			}
			if got := viewerLocation(r).String(); got != tt.want {
				t.Errorf("viewerLocation(%q) = %q, want %q", tt.cookie, got, tt.want)
			}
		})
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

func TestNormalizeFalloutIdentity(t *testing.T) {
	// Threat-feed import: sha as the package name, readable filename behind
	// it — the filename must lead.
	bazaar := feedRow{SHA256: testSHAHero, Package: testSHAHero, Version: "x1", Filename: "invoice_scan.exe"}
	normalizeFalloutIdentity(&bazaar)
	if got := bazaar.Headline(); got != "invoice_scan.exe" {
		t.Errorf("bazaar headline = %q, want the filename", got)
	}
	// Wholly anonymous: sha everywhere shortens to the sha prefix.
	anon := feedRow{SHA256: testSHABare, Package: testSHABare, Filename: testSHABare + ".elf"}
	normalizeFalloutIdentity(&anon)
	if got := anon.Headline(); got != shortSHA(testSHABare)+"…" {
		t.Errorf("anonymous headline = %q, want %q", got, shortSHA(testSHABare)+"…")
	}
	// A named row is untouched.
	named := feedRow{SHA256: testSHARow, RegistryTitle: "Volume Max", Package: "abcdef", Version: "1.2"}
	normalizeFalloutIdentity(&named)
	if got := named.Headline(); got != "Volume Max 1.2" {
		t.Errorf("named headline = %q, want unchanged", got)
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
		Nonce:       "test-script-nonce",
		HasHopper:   true,
		WeeklyCount: 47,
		WindowLabel: "this week",
		MeterSegs:   []bool{true, true, false, false, false, false},
		Sectors: []falloutSector{
			{Ecosystem: "npm", Color: "red", Count: 24},
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
		"heat-2",
		// The time-zone probe: nonced so CSP admits it, and naming the cookie
		// viewerLocation reads back.
		`<script nonce="test-script-nonce">`,
		"resolvedOptions().timeZone",
		"'" + tzCookieName + "=' + zone",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("rendered fallout page missing %q", want)
		}
	}
}
