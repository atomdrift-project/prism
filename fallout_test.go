package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
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
// Tuesday, so the week it belongs to (Mon Aug 3) is already two days old and a
// row a day or two back still lands inside it.
var falloutTestNow = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

// falloutTestView renders the week containing now, unfiltered, from a snapshot
// that reached the whole window — what the handler does for a plain /fallout.
func falloutTestView(rows []feedRow, now time.Time, eco string) falloutView {
	return buildFalloutView(rows, false, now, falloutWeekOf(now, now), eco, falloutAny)
}

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
		"ecoColor":     func(string) string { return "slate" },
		"chromaCSS":    func() template.CSS { return "" },
		"commaInt":     commaInt,
		"formulaTiers": formulaTiers,
		"tierName":     tierName,
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

	view := falloutTestView(rows, falloutTestNow, "")
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
	view := falloutTestView(rows, falloutTestNow, "pypi")
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

func TestFalloutVerificationFilter(t *testing.T) {
	uncorroborated := hostileRow(testSHAHero, "npm", "javascript", "O1(C)", "fresh", time.Hour)
	corroborated := hostileRow(testSHABare, "pypi", "python", "O2(CaEu)", "known", 2*time.Hour)
	corroborated.Corroborated = true
	rows := []feedRow{uncorroborated, corroborated}

	if got := falloutRowsInWindow(rows, falloutWeekOf(falloutTestNow, falloutTestNow), falloutAny); len(got) != 2 {
		t.Fatalf("all rows = %d, want 2", len(got))
	}
	if got := falloutRowsInWindow(rows, falloutWeekOf(falloutTestNow, falloutTestNow), falloutUncorroborated); len(got) != 1 || got[0].SHA256 != testSHAHero {
		t.Fatalf("uncorroborated rows = %+v, want only the fresh catch", got)
	}
	if got := falloutRowsInWindow(rows, falloutWeekOf(falloutTestNow, falloutTestNow), falloutCorroborated); len(got) != 1 || got[0].SHA256 != testSHABare {
		t.Fatalf("corroborated rows = %+v, want only the known catch", got)
	}

	for _, value := range []string{"", "0", "1"} {
		if _, err := parseFalloutVerification(value); err != nil {
			t.Errorf("verified=%q: unexpected error: %v", value, err)
		}
	}
	if _, err := parseFalloutVerification("maybe"); err == nil {
		t.Error("invalid verified value was accepted")
	}
}

func TestFalloutJSONRowsKeepFullPURL(t *testing.T) {
	row := hostileRow(testSHAHero, "npm", "javascript", "O1(C)", "@scope/pkg", time.Hour)
	row.PURLBase = "pkg:npm/%40scope/pkg"
	row.Version = "1.2.3"
	got := falloutJSONRows([]feedRow{row})
	if len(got) != 1 {
		t.Fatalf("got %d JSON rows, want 1", len(got))
	}
	if got[0].SHA256 != testSHAHero {
		t.Errorf("sha256 = %q, want %q", got[0].SHA256, testSHAHero)
	}
	if got[0].PURL != "pkg:npm/@scope/pkg@1.2.3" {
		t.Errorf("purl = %q, want full display PURL", got[0].PURL)
	}
	if got[0].Corroborated {
		t.Error("uncorroborated row marked corroborated")
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
	view := falloutTestView(rows, falloutTestNow, "")
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
	rows := []feedRow{
		hostileRow(testSHAHero, "npm", "javascript", "O1(C)", "new", time.Hour),
		hostileRow(testSHABare, "npm", "javascript", "O2(CC)", "older", 30*time.Hour),
	}
	// The week in progress is named, not dated: it has not finished happening.
	if got := falloutTestView(rows, falloutTestNow, "").WindowLabel; got != "this week" {
		t.Errorf("current-week label = %q, want this week", got)
	}
	// A closed week is dated, inclusive of both ends, so the label says
	// exactly which seven days the page covers.
	last := falloutWeekOf(falloutTestNow.AddDate(0, 0, -7), falloutTestNow)
	archived := []feedRow{hostileRow(testSHAHero, "npm", "javascript", "O1(C)", "old", 8*24*time.Hour)}
	view := buildFalloutView(archived, false, falloutTestNow, last, "", falloutAny)
	if want := "Jul 27 – Aug 2"; view.WindowLabel != want {
		t.Errorf("archive label = %q, want %q", view.WindowLabel, want)
	}
	if view.WeeklyCount != 1 {
		t.Errorf("archive count = %d, want the one catch that week", view.WeeklyCount)
	}
	// A snapshot that gave up before the far edge of the window must not
	// claim the whole week — it names the oldest day it actually reached.
	trunc := buildFalloutView(rows, true, falloutTestNow, falloutWeekOf(falloutTestNow, falloutTestNow), "", falloutAny)
	if want := "since " + falloutTestNow.Add(-30*time.Hour).Format("Jan 2"); trunc.WindowLabel != want {
		t.Errorf("truncated label = %q, want %q", trunc.WindowLabel, want)
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

	view := falloutTestView(rows, utcNow.In(ny), "")
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
	if utc := falloutTestView(rows, utcNow, ""); len(utc.Days) != 2 || utc.Days[1].Label != "YESTERDAY" {
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
		Ribbon:    "biggest blast radius",
	}}
	rows[0].MaleculeSVG = template.HTML(maleculeSVG(maleculeFromFormula(wave.Formula, []feedTrait{
		{ID: "cred/browser-cookies", Full: "objectives/credential-access/browser::cookies", Crit: "hostile"},
	}), 132, 62))
	data := falloutPageData{
		Nonce:         "test-script-nonce",
		HasHopper:     true,
		CurrentWeek:   true,
		WeeklyCount:   47,
		WindowLabel:   "this week",
		MeterSegs:     []bool{true, true, false, false, false, false},
		AllSectorsURL: "/fallout",
		OlderURL:      "/fallout?week=2026-07-27",
		CurrentURL:    "/fallout",
		Sectors: []falloutSector{
			{Ecosystem: "npm", Color: "red", Count: 24, URL: "/fallout?ecosystem=npm"},
		},
		Days: []falloutDay{{Label: "TODAY", Sub: "Mon Aug 4 · 24 catches · 1 wave · 0 singles", ID: "day-2026-08-04", Date: "Tue 4 Aug", Count: 24, Rows: rows}},
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	html := sb.String()
	if out := os.Getenv("PRISM_RENDER_OUT"); out != "" {
		if err := os.WriteFile(out, []byte(html), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{
		"and <b>22</b> siblings",
		"/file/" + testSHAHero,
		"/fallout?ecosystem=npm",
		// The malecule. A feed row knows categories and severities but not the
		// dependency graph, so its atoms carry no bonds and, being one per
		// category, no kinship ties either.
		`<title>credential-access</title>`,
		`class="malecule"`,
		// The rail: the day anchor.
		`href="#day-2026-08-04"`,
		// The week nav: a link back through the archive, and no forward link
		// on the week in progress.
		`href="/fallout?week=2026-07-27" rel="prev"`,
		`aria-disabled="true" title="This is the week in progress"`,
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

// TestFalloutWeekOf pins the calendar the archive is cut on: weeks start
// Monday, a week knows whether it is the one in progress, and the links it
// offers never point into the future or past the archive floor.
func TestFalloutWeekOf(t *testing.T) {
	// falloutTestNow is Tue Aug 4 2026; its week began Mon Aug 3.
	now := falloutTestNow
	for _, tt := range []struct {
		name  string
		day   time.Time
		start string
	}{
		{"tuesday", now, "2026-08-03"},
		{"the monday itself", time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC), "2026-08-03"},
		{"sunday closes the week", time.Date(2026, 8, 9, 23, 59, 59, 0, time.UTC), "2026-08-03"},
		{"the next monday opens a new one", time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC), "2026-08-10"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := falloutWeekOf(tt.day, now).Date; got != tt.start {
				t.Errorf("week of %s = %s, want %s", tt.day.Format(time.RFC3339), got, tt.start)
			}
		})
	}

	current := falloutWeekOf(now, now)
	if !current.Current || current.Next != "" {
		t.Errorf("current week: Current=%v Next=%q, want true and no forward link", current.Current, current.Next)
	}
	if current.Prev != "2026-07-27" {
		t.Errorf("current week Prev = %q, want 2026-07-27", current.Prev)
	}
	if !current.End.Equal(current.Start.AddDate(0, 0, 7)) {
		t.Errorf("week [%v, %v) is not seven days", current.Start, current.End)
	}

	// The oldest week the archive reaches still has a forward link and no
	// backward one — the floor is where the older link stops being offered.
	floor := falloutWeekOf(now.AddDate(0, 0, -7*falloutArchiveWeeks), now)
	if floor.Prev != "" {
		t.Errorf("archive floor Prev = %q, want no older link", floor.Prev)
	}
	if floor.Next == "" || floor.Current {
		t.Errorf("archive floor: Next=%q Current=%v, want a forward link and not current", floor.Next, floor.Current)
	}
}

// TestParseFalloutWeek covers what a ?week= value may be. The out-of-range
// cases are the ones that matter to more than the reader: each rejected value
// is a week snapshot that never gets built or cached.
func TestParseFalloutWeek(t *testing.T) {
	now := falloutTestNow
	for _, tt := range []struct {
		name, raw, want string
		wantErr         bool
	}{
		{name: "empty is the week in progress", raw: "", want: "2026-08-03"},
		{name: "a monday", raw: "2026-07-27", want: "2026-07-27"},
		{name: "a mid-week date resolves to its week", raw: "2026-07-30", want: "2026-07-27"},
		{name: "whitespace", raw: "  2026-07-27  ", want: "2026-07-27"},
		{name: "not a date", raw: "last-week", wantErr: true},
		{name: "not a date at all", raw: "../../etc/passwd", wantErr: true},
		{name: "next week", raw: "2026-08-10", wantErr: true},
		{name: "older than the archive", raw: "2020-01-06", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			week, err := parseFalloutWeek(tt.raw, now)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("week=%q resolved to %s, want an error", tt.raw, week.Date)
				}
				return
			}
			if err != nil {
				t.Fatalf("week=%q: %v", tt.raw, err)
			}
			if week.Date != tt.want {
				t.Errorf("week=%q resolved to %s, want %s", tt.raw, week.Date, tt.want)
			}
		})
	}

	// The week in progress is reachable by its own date as well as by the
	// bare URL, and both know they are current — otherwise the dated form
	// would render a "newer" link to nowhere.
	dated, err := parseFalloutWeek("2026-08-03", now)
	if err != nil || !dated.Current {
		t.Errorf("dated current week: Current=%v err=%v, want current", dated.Current, err)
	}
	if dated.param() != "" {
		t.Errorf("current week param = %q, want the bare /fallout", dated.param())
	}
}

// TestFalloutWeekSnapshotArgs pins the property that keeps one snapshot
// serving every reader: the fetched window depends only on the week's date,
// and it contains that week as any zone on earth cuts it.
func TestFalloutWeekSnapshotArgs(t *testing.T) {
	now := falloutTestNow
	args := falloutWeekOf(now, now).snapshotArgs()
	if args.criticality != "hostile" {
		t.Errorf("criticality = %q, want hostile", args.criticality)
	}
	for _, zone := range []string{"Pacific/Kiritimati", "America/New_York", "Pacific/Midway", "UTC"} {
		loc, err := time.LoadLocation(zone)
		if err != nil {
			t.Skipf("no zone database: %v", err)
		}
		reader := falloutWeekOf(now.In(loc), now.In(loc))
		if reader.Date != "2026-08-03" {
			// Kiritimati is far enough ahead that "now" can be a different
			// week there; that is a different week's snapshot, not a gap.
			continue
		}
		if reader.Start.Before(args.since) || reader.End.After(args.until) {
			t.Errorf("%s week [%v, %v) escapes the fetched window [%v, %v)",
				zone, reader.Start, reader.End, args.since, args.until)
		}
		if got := falloutWeekOf(now.In(loc), now.In(loc)).snapshotArgs(); got != args {
			t.Errorf("%s: snapshot args differ from UTC's — the cache key is not zone-independent", zone)
		}
	}
}

func TestFalloutURL(t *testing.T) {
	for _, tt := range []struct {
		name, week, eco, verified, want string
	}{
		{name: "the log's front door", want: "/fallout"},
		{name: "a week", week: "2026-07-27", want: "/fallout?week=2026-07-27"},
		{name: "a sector", eco: "npm", want: "/fallout?ecosystem=npm"},
		{
			name: "filters ride along with the week", week: "2026-07-27", eco: "npm", verified: "1",
			want: "/fallout?ecosystem=npm&verified=1&week=2026-07-27",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := falloutURL(tt.week, tt.eco, tt.verified); got != tt.want {
				t.Errorf("falloutURL(%q, %q, %q) = %q, want %q", tt.week, tt.eco, tt.verified, got, tt.want)
			}
		})
	}
}

// TestBuildFalloutViewArchiveWeek renders a closed week: only its own catches,
// under weekday bands rather than TODAY, and the sector strip counting the
// week it names rather than the one in progress.
func TestBuildFalloutViewArchiveWeek(t *testing.T) {
	now := falloutTestNow
	last := falloutWeekOf(now.AddDate(0, 0, -7), now)
	rows := []feedRow{
		hostileRow(testSHAHero, "npm", "javascript", "O1(C)", "this-week", time.Hour),
		hostileRow(testSHABare, "pypi", "python", "O2(CaEu)", "last-week", 8*24*time.Hour),
		hostileRow(testSHARow, "npm", "javascript", "O3(CC)", "long-ago", 30*24*time.Hour),
	}

	view := buildFalloutView(rows, false, now, last, "", falloutAny)
	if view.WeeklyCount != 1 {
		t.Fatalf("archive week count = %d, want only last week's catch", view.WeeklyCount)
	}
	if len(view.Days) != 1 {
		t.Fatalf("bands = %d, want 1", len(view.Days))
	}
	if got := view.Days[0].Label; got != "MONDAY" {
		t.Errorf("archive band label = %q, want the weekday — TODAY belongs to the live week", got)
	}
	if len(view.Sectors) != 1 || view.Sectors[0].Ecosystem != "pypi" {
		t.Errorf("archive sectors = %+v, want pypi alone", view.Sectors)
	}
	// The meter reads the newest day the week actually holds, so an archive
	// week still lights it instead of reading empty.
	lit := 0
	for _, on := range view.MeterSegs {
		if on {
			lit++
		}
	}
	if lit == 0 {
		t.Error("archive meter is dark: it should read the week's own last day")
	}
}

// TestFalloutWeekBoundaryIsHalfOpen: a catch at the stroke of Monday belongs
// to the week that is starting, and to exactly one week.
func TestFalloutWeekBoundaryIsHalfOpen(t *testing.T) {
	now := falloutTestNow
	current := falloutWeekOf(now, now)
	previous := falloutWeekOf(now.AddDate(0, 0, -7), now)

	row := hostileRow(testSHAHero, "npm", "javascript", "O1(C)", "midnight", 0)
	row.AnalyzedAt = current.Start
	rows := []feedRow{row}

	if got := falloutRowsInWindow(rows, current, falloutAny); len(got) != 1 {
		t.Errorf("midnight catch in the week it opens = %d rows, want 1", len(got))
	}
	if got := falloutRowsInWindow(rows, previous, falloutAny); len(got) != 0 {
		t.Errorf("midnight catch in the week it closes = %d rows, want 0", len(got))
	}
}

// TestHandleFalloutWeekParam drives the handler itself: the week reaches the
// page, its filters ride the nav and the strip links, and an unusable ?week=
// falls back to the week in progress rather than erroring — the same
// forgiveness the other filters get.
func TestHandleFalloutWeekParam(t *testing.T) {
	saved := falloutTemplate
	t.Cleanup(func() { falloutTemplate = saved })
	tmpl, err := template.New("fallout.html").Funcs(templateFuncsForTest()).
		ParseFS(templatesFS, "templates/base.html", "templates/fallout.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	falloutTemplate = tmpl

	// Without hopper the page renders its empty state, which is all this test
	// needs: the week plumbing runs before any query.
	get := func(target string) string {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, target, http.NoBody)
		r.AddCookie(&http.Cookie{Name: tzCookieName, Value: "UTC"})
		handleFallout(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", target, w.Code)
		}
		return w.Body.String()
	}

	week := falloutWeekOf(time.Now().UTC(), time.Now().UTC())
	older := week.Prev
	if older == "" {
		t.Fatal("the current week should always offer an older week")
	}

	live := get("/fallout")
	if !strings.Contains(live, "this week") {
		t.Error("the bare log should be titled this week")
	}
	if !strings.Contains(live, `href="/fallout?week=`+older+`"`) {
		t.Errorf("the bare log has no link back to %s:\n%s", older, live)
	}

	// An archive week, with a verification filter that must survive every
	// link the page draws.
	archive := get("/fallout?week=" + older + "&verified=1")
	if strings.Contains(archive, ">this week<") {
		t.Error("an archive week must not be titled this week")
	}
	before := falloutWeekOf(week.Start.AddDate(0, 0, -14), week.Start)
	for _, want := range []string{
		// The older step keeps the filter and walks one more week back.
		"verified=1&amp;week=" + before.Date,
		`href="/fallout?verified=1"`, // the way back to the live week
	} {
		if !strings.Contains(archive, want) {
			t.Errorf("archive page missing %q:\n%s", want, archive)
		}
	}

	// Unusable weeks: neither may reach the template as anything but the
	// week in progress.
	for _, bad := range []string{"?week=tomorrow", "?week=2000-01-03", "?week=" + time.Now().AddDate(0, 0, 30).Format(falloutWeekLayout)} {
		if page := get("/fallout" + bad); !strings.Contains(page, "this week") {
			t.Errorf("GET /fallout%s did not fall back to the week in progress", bad)
		}
	}
}

// TestFormulaTiers pins the tile rendering of a formula: tiers in formula
// order, atoms folded back to a count, and names resolved for the tiles.
func TestFormulaTiers(t *testing.T) {
	tiers := formulaTiers("O₄(AlEu₂CaDy)H₅(CmCrDb₅Os₄Po)Md(Pa)")
	if len(tiers) != 3 || tiers[0].Tier != "O" || tiers[1].Tier != "H" || tiers[2].Tier != "Md" {
		t.Fatalf("tiers = %+v, want O, H, Md", tiers)
	}
	if got := tiers[0].Atoms; len(got) != 4 || got[1].Symbol != "Eu" || got[1].Count != 2 || got[1].Name != "exfiltration" {
		t.Errorf("objective atoms = %+v, want Al, Eu₂ (exfiltration), Ca, Dy", got)
	}
	if got := tiers[1].Atoms[2]; got.Symbol != "Db" || got.Count != 5 {
		t.Errorf("behaviour Db = %+v, want count 5", got)
	}
	if got := formulaTiers("O1(C)H2"); len(got) != 2 || got[1].Tier != "" || got[1].Atoms[0].Count != 2 {
		t.Errorf("standalone atoms = %+v, want a tierless row with H₂", got)
	}
	if got := formulaTiers(""); got != nil {
		t.Errorf("empty formula = %+v, want nil", got)
	}
}
