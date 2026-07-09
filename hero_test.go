package main

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// uploadTemplateForTest parses the feed template with the same funcs
// registered in main(), so tests catch syntax errors that would otherwise
// crash the server at startup.
func uploadTemplateForTest(t *testing.T) *template.Template {
	t.Helper()
	funcs := template.FuncMap{
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
	}
	tmpl, err := template.New("upload.html").Funcs(funcs).ParseFS(templatesFS,
		"templates/base.html", "templates/upload.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return tmpl
}

const (
	testSHAHero = "64e9a4281f4ea68069afad163cdeec148f73499470c0e4dc254e2af668b7ed4f"
	testSHARow  = "2b6e308fe459a47906991d90be8184126839baca8fb8b7f32deef4e1c036af66"
	testSHABare = "54fd2bd51e3cdea2b09da11d96ae7e87fbc7ada093a7818f2b1be5d95fa6fb19"
)

func TestUploadTemplateRendersHeroAndLedger(t *testing.T) {
	tmpl := uploadTemplateForTest(t)
	hero := &feedHero{
		feedRow: feedRow{
			SHA256:         testSHAHero,
			Filename:       "ext.crx",
			Package:        "kpeiokhfmoigdhgmiippgkbnilhmmoim",
			Version:        "5.2.1",
			Classification: "hostile",
			Ecosystem:      "chrome",
			EcosystemURL:   "/chrome/",
			Formula:        "O2(AsXe)",
			FileType:       "crx",
			Why:            "posts every visited URL to a hardcoded endpoint",
			Conf:           93,
			Corroborated:   true,
			AnalyzedDate:   "10h ago",
		},
		Reasons: "rare catch for chrome",
	}
	data := feedPageData{
		HasHopper:    true,
		SelectedCrit: "hostile",
		Hero:         hero,
		Rows: []feedRow{
			{
				SHA256:         testSHARow,
				Filename:       "nomad_pydantic-0.0.0.tar.gz",
				Package:        "nomad-pydantic",
				Version:        "0.0.0",
				Classification: "hostile",
				Ecosystem:      "python",
				Why:            "downloads a second stage from a CDN",
				Conf:           97,
				AnalyzedDate:   "11h ago",
			},
			// A bare sample (no package, no rationale) degrades to the
			// filename + sha form with no pkg spec or rationale line.
			{
				SHA256:         testSHABare,
				Filename:       testSHABare + ".elf",
				Classification: "hostile",
				Ecosystem:      "linux",
				AnalyzedDate:   "13h ago",
			},
		},
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"HOT PARTICLE",
		"rare catch for chrome",
		testSHAHero, // full hero sha in the side rail
		testSHARow,  // full row sha on the ledger line
		"kpeiokhfmoigdhgmiippgkbnilhmmoim@5.2.1",
		"nomad-pydantic@0.0.0",
		"✓ corroborated",
		"93% confidence",
		"97%",
		"View full analysis",
		`value="any"`, // the explicit Any option
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered feed missing %q", want)
		}
	}
	if strings.Contains(got, testSHABare+"@") {
		t.Error("bare sample must not render a pkg spec")
	}
}

func TestUploadTemplateEmptyFeed(t *testing.T) {
	tmpl := uploadTemplateForTest(t)
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, feedPageData{HasHopper: true, SelectedCrit: "hostile"}); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(buf.String(), "No matching records.") {
		t.Error("empty feed must render the empty state")
	}
	if strings.Contains(buf.String(), "HOT PARTICLE") {
		t.Error("nil hero must omit the Hot Particle section")
	}
}

// TestRenderFeedCriticalityDefault covers the new default: a bare frontpage
// URL is the hostile view, and criticality=any is the explicit opt-out.
func TestRenderFeedCriticalityDefault(t *testing.T) {
	if uploadTemplate == nil {
		uploadTemplate = uploadTemplateForTest(t)
	}
	cases := []struct {
		url  string
		want string
	}{
		{"/", `value="hostile" selected`},
		{"/?criticality=any", `value="any" selected`},
		{"/?criticality=benign", `value="benign" selected`},
		{"/?criticality=bogus", `value="any" selected`}, // junk degrades to the unfiltered view
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, tc.url, http.NoBody)
		w := httptest.NewRecorder()
		renderFeed(w, r, "")
		if !strings.Contains(w.Body.String(), tc.want) {
			t.Errorf("GET %s: missing %q in rendered dropdown", tc.url, tc.want)
		}
	}
}

func TestFeedRowTitleAndPkgSpec(t *testing.T) {
	cases := []struct {
		name    string
		row     feedRow
		title   string
		pkgSpec string
	}{
		{"attributed", feedRow{Package: "lodash", Version: "4.17.21", Filename: "lodash-4.17.21.tgz"}, "lodash", "lodash@4.17.21"},
		{"no version", feedRow{Package: "lodash", Filename: "lodash.tgz"}, "lodash", "lodash"},
		{"unattributed", feedRow{Filename: "sample.elf"}, "sample.elf", ""},
	}
	for _, tc := range cases {
		if got := tc.row.Title(); got != tc.title {
			t.Errorf("%s: Title() = %q, want %q", tc.name, got, tc.title)
		}
		if got := tc.row.PkgSpec(); got != tc.pkgSpec {
			t.Errorf("%s: PkgSpec() = %q, want %q", tc.name, got, tc.pkgSpec)
		}
	}
}

func TestLLMWhy(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		why  string
		conf int
	}{
		{"absent", "", "", 0},
		{"invalid", "{nope", "", 0},
		{"failed pass", `{"error":"model timeout"}`, "", 0},
		{"present", `{"interpretation":"steals env vars","conf":0.93}`, "steals env vars", 93},
		{"rounds", `{"interpretation":"x","conf":0.855}`, "x", 86},
	}
	for _, tc := range cases {
		why, conf := llmWhy([]byte(tc.raw))
		if why != tc.why || conf != tc.conf {
			t.Errorf("%s: llmWhy = (%q, %d), want (%q, %d)", tc.name, why, conf, tc.why, tc.conf)
		}
	}
}

// heroTestRow builds a fully-eligible hostile row `age` before now; tests
// mutate fields to probe individual gates and score terms.
func heroTestRow(sha, eco, formula string, age time.Duration, now time.Time) feedRow {
	return feedRow{
		SHA256:         sha,
		Filename:       sha + ".bin",
		Package:        "pkg-" + sha,
		Version:        "1.0.0",
		Classification: "hostile",
		Ecosystem:      eco,
		Formula:        formula,
		Why:            "does bad things",
		Conf:           90,
		AnalyzedAt:     now.Add(-age),
	}
}

func TestChooseHeroGatesAndScore(t *testing.T) {
	now := time.Now()
	if got := chooseHero(nil, now, ""); got != nil {
		t.Fatalf("empty pool: got %+v, want nil", got)
	}

	// A wave of common-ecosystem catches sharing one formula vs one
	// rare-ecosystem catch with a novel formula: the rare one is the hot
	// particle, and at 1-in-25 its ecosystem clears the tooltip's "rare"
	// share threshold too.
	rows := make([]feedRow, 0, 25)
	for i := range 24 {
		rows = append(rows, heroTestRow(fmt.Sprintf("a%d", i), "npm", "F1", time.Duration(2+i)*time.Minute, now))
	}
	rows = append(rows, heroTestRow("rare", "chrome", "F2", 8*time.Hour, now))
	hero := chooseHero(rows, now, "")
	if hero == nil || hero.SHA256 != "rare" {
		t.Fatalf("expected the rare-ecosystem catch, got %+v", hero)
	}
	if !strings.Contains(hero.Reasons, "rare catch for chrome") ||
		!strings.Contains(hero.Reasons, "novel trait composition") ||
		!strings.Contains(hero.Reasons, "first seen here") {
		t.Errorf("reasons = %q, want all three score components", hero.Reasons)
	}

	// Gates: each defect disqualifies an otherwise-winning candidate.
	for _, mutate := range []func(*feedRow){
		func(r *feedRow) { r.Classification = "suspicious" },
		func(r *feedRow) { r.Conf = heroMinConf - 1 },
		func(r *feedRow) { r.Why = "" },
		func(r *feedRow) { r.Package = "" },
		func(r *feedRow) { r.AnalyzedAt = now.Add(-heroWindowWide - time.Hour) },
	} {
		gated := append([]feedRow(nil), rows...)
		mutate(&gated[len(gated)-1])
		if hero := chooseHero(gated, now, ""); hero == nil || hero.SHA256 == "rare" {
			t.Errorf("gate failed to disqualify: got %+v", hero)
		}
	}

	// An uncorroborated catch outscores an otherwise-identical corroborated one.
	pair := []feedRow{
		heroTestRow("fed", "npm", "F1", 2*time.Hour, now),
		heroTestRow("ours", "npm", "F1", 3*time.Hour, now),
	}
	pair[0].Corroborated = true
	if hero := chooseHero(pair, now, ""); hero == nil || hero.SHA256 != "ours" {
		t.Errorf("first-seen bonus: got %+v, want ours", hero)
	}

	// Equal scores tie-break on confidence.
	pair = []feedRow{
		heroTestRow("lo", "npm", "F1", 2*time.Hour, now),
		heroTestRow("hi", "npm", "F1", 3*time.Hour, now),
	}
	pair[1].Conf = 99
	if hero := chooseHero(pair, now, ""); hero == nil || hero.SHA256 != "hi" {
		t.Errorf("confidence tie-break: got %+v, want hi", hero)
	}
}

func TestChooseHeroWindowWidensOnQuietDays(t *testing.T) {
	now := time.Now()
	stale := []feedRow{heroTestRow("old", "npm", "F1", heroWindow+2*time.Hour, now)}
	hero := chooseHero(stale, now, "")
	if hero == nil || hero.SHA256 != "old" {
		t.Fatalf("quiet day must widen to %v, got %+v", heroWindowWide, hero)
	}
	ancient := []feedRow{heroTestRow("ancient", "npm", "F1", heroWindowWide+time.Hour, now)}
	if hero := chooseHero(ancient, now, ""); hero != nil {
		t.Errorf("nothing within %v must yield no hero, got %+v", heroWindowWide, hero)
	}
}

func TestChooseHeroPinOverridesScore(t *testing.T) {
	now := time.Now()
	rows := []feedRow{
		heroTestRow("winner", "chrome", "F2", 2*time.Hour, now),
		heroTestRow("pinned", "npm", "F1", 30*time.Hour, now),
	}
	// The pin wins even over an otherwise-winning candidate, and even for a
	// row outside the scoring window.
	hero := chooseHero(rows, now, "pinned")
	if hero == nil || hero.SHA256 != "pinned" {
		t.Fatalf("pin override: got %+v, want pinned", hero)
	}
	if hero.Reasons != "operator pick of the day" {
		t.Errorf("pin reasons = %q", hero.Reasons)
	}
	// A pin pointing at a sample not in the pool falls back to scoring.
	if hero := chooseHero(rows, now, "absent"); hero == nil || hero.SHA256 != "winner" {
		t.Errorf("dangling pin must fall back to scoring, got %+v", hero)
	}
}
