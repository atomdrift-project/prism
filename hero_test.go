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
			RegistryTitle:  "Volume Max — Ultimate Sound Booster",
			Desc:           "Boost your volume up to 600%.",
			Users:          "412,033",
			Downloads:      412033,
			Classification: "hostile",
			Ecosystem:      "chrome",
			EcosystemURL:   "/chrome/",
			Formula:        "O2(AsXe)",
			FileType:       "crx",
			Why:            "posts every visited URL to a hardcoded endpoint",
			Conf:           93,
			TopTraits: []feedTrait{
				{ID: "net.beacon-hardcoded-c2", Full: "objectives/net/beacon-hardcoded-c2", Crit: "hostile"},
			},
			Corroborated: true,
			AnalyzedDate: "10h ago",
		},
		Reasons: "rare catch for chrome",
	}
	data := feedPageData{
		HasHopper:    true,
		SelectedCrit: "hostile",
		Hero:         hero,
		Rows: []feedRow{
			// An LLM rationale and trait chips render together — the chips
			// are evidence, not a fallback.
			{
				SHA256:         testSHARow,
				Filename:       "nomad_pydantic-0.0.0.tar.gz",
				Package:        "nomad-pydantic",
				Version:        "0.0.0",
				Classification: "hostile",
				Ecosystem:      "python",
				Why:            "downloads a second stage from a CDN",
				Conf:           97,
				TopTraits: []feedTrait{
					{ID: "exec.install-hook", Full: "objectives/exec/install-hook", Crit: "hostile"},
				},
				AnalyzedDate: "11h ago",
			},
			// A bare sample (no package, no LLM rationale) degrades to the
			// filename + sha form; its rationale line is the trait chips.
			{
				SHA256:         testSHABare,
				Filename:       testSHABare + ".elf",
				Classification: "hostile",
				Ecosystem:      "linux",
				TopTraits: []feedTrait{
					{ID: "persist.systemd-unit", Full: "objectives/persist/systemd-unit", Crit: "hostile"},
					{ID: "obf.xor-stage", Full: "micro-behaviors/obf/xor-stage", Crit: "suspicious"},
				},
				AnalyzedDate: "13h ago",
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
		testSHAHero, // full hero sha, inline on the hash line
		testSHARow,  // full row sha on the ledger line
		"Volume Max — Ultimate Sound Booster 5.2.1", // hero headline: title + version
		// the extension id appears once, as the muted sub-id — never as a
		// repeated name@version coordinate
		`>kpeiokhfmoigdhgmiippgkbnilhmmoim</span>`,
		"Boost your volume up to 600%.", // registry description
		"412,033",                       // install count
		"nomad-pydantic 0.0.0",          // row headline: name + version, no duplicate pkg line
		`class="feedmark"`,              // the bare ✓ corroboration mark
		"93% confidence",
		"97%",
		// hero evidence chip renders alongside the LLM interpretation
		`>net.beacon-hardcoded-c2</span>`,
		// ...and so does the LLM-bearing row's chip
		`>exec.install-hook</span>`,
		"installs exposed", // reach sits in the coordinate stack under the formula
		"View full analysis",
		`value="any"`,         // the explicit Any option
		`property="og:title"`, // social-preview tags
		`href="/feed.atom"`,   // Atom autodiscovery + pill
		// The LLM-less row's rationale line is its trait chips, dot-colored
		// by criticality, with the full trait path on hover.
		`<span class="why-chip crit-hostile" title="objectives/persist/systemd-unit">persist.systemd-unit</span>`,
		`crit-suspicious`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered feed missing %q", want)
		}
	}
	if strings.Contains(got, "nomad-pydantic@0.0.0") {
		t.Error("row identity must not repeat the package as name@version")
	}
	if strings.Contains(got, "kpeiokhfmoigdhgmiippgkbnilhmmoim@5.2.1") {
		t.Error("compact hero must not render the name@version coordinate")
	}
	if strings.Contains(got, ">threat feeds<") {
		t.Error("compact hero must not render the threat-feeds rail row")
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

func TestFeedRowIdentity(t *testing.T) {
	marketplace := feedRow{
		Package: "kpeiokhfmoigdhgmiippgkbnilhmmoim", Version: "5.2.1",
		RegistryTitle: "Volume Max", Filename: "ext.crx",
	}
	cases := []struct {
		name     string
		row      feedRow
		headline string
		subID    string
	}{
		// A marketplace title displaces the package id, which moves to the
		// muted sub-id so the identity line never repeats itself.
		{"marketplace", marketplace, "Volume Max 5.2.1", "kpeiokhfmoigdhgmiippgkbnilhmmoim"},
		{"attributed", feedRow{Package: "lodash", Version: "4.17.21", Filename: "lodash-4.17.21.tgz"}, "lodash 4.17.21", ""},
		{"no version", feedRow{Package: "lodash", Filename: "lodash.tgz"}, "lodash", ""},
		{"unattributed", feedRow{Filename: "sample.elf"}, "sample.elf", ""},
		// A version without package attribution stays off the headline —
		// filenames usually embed their version already.
		{"filename fallback", feedRow{Filename: "pkg-0.0.0.tar.gz", Version: "0.0.0"}, "pkg-0.0.0.tar.gz", ""},
	}
	for _, tc := range cases {
		if got := tc.row.Headline(); got != tc.headline {
			t.Errorf("%s: Headline() = %q, want %q", tc.name, got, tc.headline)
		}
		if got := tc.row.SubID(); got != tc.subID {
			t.Errorf("%s: SubID() = %q, want %q", tc.name, got, tc.subID)
		}
	}
}

func TestFormatCount(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, ""},
		{-3, ""},
		{7, "7"},
		{999, "999"},
		{1000, "1,000"},
		{412033, "412,033"},
		{1234567890, "1,234,567,890"},
	}
	for _, tc := range cases {
		if got := formatCount(tc.n); got != tc.want {
			t.Errorf("formatCount(%d) = %q, want %q", tc.n, got, tc.want)
		}
	}
}

func TestTruncDesc(t *testing.T) {
	if got := truncDesc("  short  "); got != "short" {
		t.Errorf("truncDesc trims, got %q", got)
	}
	long := strings.Repeat("é", 200)
	got := truncDesc(long)
	if runes := []rune(got); len(runes) != 140 || !strings.HasSuffix(got, "…") {
		t.Errorf("truncDesc cap: %d runes, suffix %q", len(runes), got[len(got)-3:])
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

	// Reach: a broad install base outscores an otherwise-identical catch.
	pair = []feedRow{
		heroTestRow("small", "npm", "F1", 2*time.Hour, now),
		heroTestRow("broad", "npm", "F1", 3*time.Hour, now),
	}
	pair[1].Downloads = 412033
	hero = chooseHero(pair, now, "")
	if hero == nil || hero.SHA256 != "broad" {
		t.Errorf("reach term: got %+v, want broad", hero)
	}
	if !strings.Contains(hero.Reasons, "412,033 installs exposed") {
		t.Errorf("reach reason missing: %q", hero.Reasons)
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
