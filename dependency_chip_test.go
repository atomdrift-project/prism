package main

import (
	"strings"
	"testing"
)

// depTestSHA is a syntactically valid content sha for the fetched dependency.
const depTestSHA = "4c930ba4e609cdf4576d6c859bf7022a1f0a801578965e4e135625acb9bb5d50"

// A fetch/dependency-verdict trait carrying scan's structured dep identity
// renders as a specific chip: the text names the inherited verdict and the
// package it comes from, the tooltip keeps the full locator, and the chip
// links to the dependency's own record.
func TestParseTopTraitsDependencyPURL(t *testing.T) {
	raw := `[{"id":"fetch/dependency-verdict","crit":5,"dep":{"locator":"pkg:npm/zaboodle@1.49","sha":"` + depTestSHA + `","type":"javascript"}}]`
	got := parseTopTraits(raw)
	if len(got) != 1 {
		t.Fatalf("chips = %+v, want exactly one", got)
	}
	want := feedTrait{
		ID:   "depends on hostile npm: zaboodle v1.49",
		Full: "fetch/dependency-verdict — pkg:npm/zaboodle@1.49",
		Crit: "hostile",
		Href: "/file/" + depTestSHA,
	}
	if got[0] != want {
		t.Errorf("chip = %+v,\nwant  %+v", got[0], want)
	}
}

// A URL-declared dependency names the fetched payload's sniffed type and the
// compacted URL (host + filename) instead of package coordinates.
func TestParseTopTraitsDependencyURL(t *testing.T) {
	raw := `[{"id":"fetch/dependency-verdict","crit":4,"dep":{"locator":"http://x.y.z/a/b/x.exe","sha":"` + depTestSHA + `","type":"pe"}}]`
	got := parseTopTraits(raw)
	if len(got) != 1 {
		t.Fatalf("chips = %+v, want exactly one", got)
	}
	want := feedTrait{
		ID:   "references suspicious pe: x.y.z/x.exe",
		Full: "fetch/dependency-verdict — http://x.y.z/a/b/x.exe",
		Crit: "suspicious",
		Href: "/file/" + depTestSHA,
	}
	if got[0] != want {
		t.Errorf("chip = %+v,\nwant  %+v", got[0], want)
	}
}

// Rows scanned before scan emitted the dep field — and rows whose dep is
// malformed — keep the generic id chip, exactly as before.
func TestParseTopTraitsDependencyFallbacks(t *testing.T) {
	generic := feedTrait{ID: "fetch/dependency-verdict", Full: "fetch/dependency-verdict", Crit: "hostile"}
	cases := []struct {
		name string
		raw  string
		want feedTrait
	}{
		{"no dep field", `[{"id":"fetch/dependency-verdict","crit":5}]`, generic},
		{"malformed dep", `[{"id":"fetch/dependency-verdict","crit":5,"dep":{"locator":7}}]`, generic},
		{"empty locator", `[{"id":"fetch/dependency-verdict","crit":5,"dep":{"locator":"","sha":"` + depTestSHA + `"}}]`, generic},
		{
			// A bad sha still gets the specific text — it just can't link.
			"invalid sha drops href only",
			`[{"id":"fetch/dependency-verdict","crit":5,"dep":{"locator":"pkg:npm/zaboodle@1.49","sha":"nope","type":"javascript"}}]`,
			feedTrait{ID: "depends on hostile npm: zaboodle v1.49", Full: "fetch/dependency-verdict — pkg:npm/zaboodle@1.49", Crit: "hostile"},
		},
		{
			// An unsniffable type falls back to the neutral word.
			"unknown type",
			`[{"id":"fetch/dependency-verdict","crit":5,"dep":{"locator":"http://x.y.z/blob","sha":"` + depTestSHA + `","type":"unknown"}}]`,
			feedTrait{ID: "depends on hostile dependency: x.y.z/blob", Full: "fetch/dependency-verdict — http://x.y.z/blob", Crit: "hostile", Href: "/file/" + depTestSHA},
		},
	}
	for _, tc := range cases {
		got := parseTopTraits(tc.raw)
		if len(got) != 1 {
			t.Errorf("%s: chips = %+v, want exactly one", tc.name, got)
			continue
		}
		if tc.name == "unknown type" {
			// The URL form reads "references", not "depends on".
			tc.want.ID = "references hostile dependency: x.y.z/blob"
		}
		if got[0] != tc.want {
			t.Errorf("%s: chip = %+v,\nwant  %+v", tc.name, got[0], tc.want)
		}
	}
}

// Two dependency verdicts naming different packages are different evidence —
// both chips survive the dedup that folds ordinary same-rule traits together.
func TestParseTopTraitsDependencyDedup(t *testing.T) {
	dep := func(locator string) string {
		return `{"id":"fetch/dependency-verdict","crit":5,"dep":{"locator":"` + locator + `","sha":"` + depTestSHA + `","type":"javascript"}}`
	}
	got := parseTopTraits(`[` + dep("pkg:npm/zaboodle@1.49") + `,` + dep("pkg:npm/left-pad@9.9") + `,` + dep("pkg:npm/zaboodle@1.49") + `]`)
	if len(got) != 2 {
		t.Fatalf("chips = %+v, want the two distinct dependencies", got)
	}
	if got[0].ID == got[1].ID {
		t.Errorf("distinct dependencies folded together: %+v", got)
	}
}

func TestPurlCoords(t *testing.T) {
	cases := []struct {
		locator            string
		eco, name, version string
		ok                 bool
	}{
		{"pkg:npm/zaboodle@1.49", "npm", "zaboodle", "1.49", true},
		{"pkg:npm/%40types/node@22.0.0", "npm", "@types/node", "22.0.0", true},
		{"pkg:deb/debian/curl@7.88.1", "deb", "debian/curl", "7.88.1", true},
		{"pkg:gem/rails", "gem", "rails", "", true},
		{"pkg:pypi/requests@2.31?arch=any", "pypi", "requests", "2.31", true},
		{"http://x.y.z/x.exe", "", "", "", false},
		{"pkg:npm", "", "", "", false},
		{"pkg:", "", "", "", false},
		{"", "", "", "", false},
	}
	for _, tc := range cases {
		eco, name, version, ok := purlCoords(tc.locator)
		if eco != tc.eco || name != tc.name || version != tc.version || ok != tc.ok {
			t.Errorf("purlCoords(%q) = %q %q %q %v, want %q %q %q %v",
				tc.locator, eco, name, version, ok, tc.eco, tc.name, tc.version, tc.ok)
		}
	}
}

func TestURLCoords(t *testing.T) {
	cases := []struct{ locator, want string }{
		{"http://x.y.z/x.exe", "x.y.z/x.exe"},
		{"https://github.com/tigerbeetle/tigerbeetle/archive/refs/tags/0.17.9/tigerbeetle-0.17.9.tar.gz", "github.com/tigerbeetle-0.17.9.tar.gz"},
		{"http://x.y.z", "x.y.z"},
		{"http://x.y.z/", "x.y.z"},
		{"::not a url::", "::not a url::"},
	}
	for _, tc := range cases {
		if got := urlCoords(tc.locator); got != tc.want {
			t.Errorf("urlCoords(%q) = %q, want %q", tc.locator, got, tc.want)
		}
	}
}

// A pathological locator (attacker-authored manifest string) is capped so it
// can't stretch the chip row or the atom summary; the tooltip keeps it whole.
func TestDependencyChipCapsRunawayLocator(t *testing.T) {
	long := strings.Repeat("a", 300)
	raw := `[{"id":"fetch/dependency-verdict","crit":5,"dep":{"locator":"pkg:npm/` + long + `@1.0","sha":"` + depTestSHA + `","type":"javascript"}}]`
	got := parseTopTraits(raw)
	if len(got) != 1 {
		t.Fatalf("chips = %+v, want exactly one", got)
	}
	if n := len([]rune(got[0].ID)); n > 80 {
		t.Errorf("chip text is %d runes, want <= 80: %q", n, got[0].ID)
	}
	if !strings.HasSuffix(got[0].ID, "…") {
		t.Errorf("capped chip must end in an ellipsis: %q", got[0].ID)
	}
	if !strings.Contains(got[0].Full, long) {
		t.Error("tooltip must keep the full locator")
	}
}

// The feed template renders a dependency chip as a link to the dependency's
// record and an ordinary trait as a plain span, in a ledger row's fallback
// rationale line.
func TestUploadTemplateRendersDependencyChipAsLink(t *testing.T) {
	tmpl := uploadTemplateForTest(t)
	depChip := feedTrait{
		ID:   "depends on hostile npm: zaboodle v1.49",
		Full: "fetch/dependency-verdict — pkg:npm/zaboodle@1.49",
		Crit: "hostile",
		Href: "/file/" + depTestSHA,
	}
	plainChip := feedTrait{ID: "exec.install-hook", Full: "objectives/exec/install-hook", Crit: "hostile"}
	data := feedPageData{
		HasHopper: true,
		Rows: []feedRow{{
			SHA256:         testSHARow,
			Filename:       "other-2.0.0.tgz",
			Classification: "hostile",
			Conf:           92,
			TopTraits:      []feedTrait{depChip, plainChip},
			AnalyzedDate:   "2h ago",
		}},
	}

	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	html := sb.String()

	anchor := `<a class="why-chip crit-hostile" href="/file/` + depTestSHA + `"`
	if n := strings.Count(html, anchor); n != 1 {
		t.Errorf("dependency chip anchor rendered %d times, want 1", n)
	}
	if !strings.Contains(html, "depends on hostile npm: zaboodle v1.49</a>") {
		t.Error("dependency chip text missing or not inside the anchor")
	}
	if !strings.Contains(html, `<span class="why-chip crit-hostile" title="objectives/exec/install-hook">exec.install-hook</span>`) {
		t.Error("ordinary trait must stay a plain span")
	}
}

// Chip text and tooltip are attacker-influenced (locator strings from hostile
// manifests); html/template must escape them wherever they land.
func TestUploadTemplateEscapesHostileChipText(t *testing.T) {
	tmpl := uploadTemplateForTest(t)
	raw := `[{"id":"fetch/dependency-verdict","crit":5,"dep":{"locator":"pkg:npm/<script>alert(1)</script>@1.0","sha":"` + depTestSHA + `","type":"javascript"}}]`
	chips := parseTopTraits(raw)
	if len(chips) != 1 {
		t.Fatalf("chips = %+v, want exactly one", chips)
	}
	data := feedPageData{
		HasHopper: true,
		Rows: []feedRow{{
			SHA256:         testSHARow,
			Filename:       "evil-1.0.0.tgz",
			Classification: "hostile",
			Conf:           92,
			TopTraits:      chips,
			AnalyzedDate:   "2h ago",
		}},
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.Contains(sb.String(), "<script>alert(1)</script>") {
		t.Error("hostile locator reached the page unescaped")
	}
}

// A dependency chip is navigation, not rationale: it is the only link from a
// feed row to the dependency that elevated it. An LLM interpretation replaces
// the ordinary trait chips, and suppressing the dependency chip with them hid
// that link on exactly the rows most likely to need it — a verdict inherited
// from a hostile dependency is what an interpretation tends to write about.
func TestDependencyChipSurvivesAnLLMRationale(t *testing.T) {
	depChip := feedTrait{
		ID:   "depends on hostile npm: zaboodle v1.49",
		Full: "fetch/dependency-verdict — pkg:npm/zaboodle@1.49",
		Crit: "hostile",
		Href: "/file/" + depTestSHA,
	}
	plainChip := feedTrait{ID: "exec.install-hook", Full: "objectives/exec/install-hook", Crit: "hostile"}

	withWhy := feedRow{Why: "Installs a hook that exfiltrates env vars.", TopTraits: []feedTrait{depChip, plainChip}}
	got := withWhy.FallbackTraits()
	if len(got) != 1 || got[0].Href != depChip.Href {
		t.Errorf("with a rationale: chips = %+v, want only the dependency chip", got)
	}

	withoutWhy := feedRow{TopTraits: []feedTrait{depChip, plainChip}}
	if len(withoutWhy.FallbackTraits()) != 2 {
		t.Errorf("without a rationale: chips = %+v, want both headline traits", withoutWhy.FallbackTraits())
	}

	noDeps := feedRow{Why: "Nothing linkable here.", TopTraits: []feedTrait{plainChip}}
	if len(noDeps.FallbackTraits()) != 0 {
		t.Errorf("a rationale with no dependency chips = %+v, want none", noDeps.FallbackTraits())
	}
}

// The chip must actually reach the page alongside the prose, not just survive
// the accessor.
func TestUploadTemplateRendersDependencyChipBesideRationale(t *testing.T) {
	tmpl := uploadTemplateForTest(t)
	data := feedPageData{
		HasHopper: true,
		Rows: []feedRow{{
			SHA256:         testSHARow,
			Filename:       "wrapper-1.0.0.tgz",
			Classification: "hostile",
			Why:            "Pulls a hostile dependency at install time.",
			TopTraits: []feedTrait{{
				ID: "depends on hostile npm: zaboodle v1.49", Crit: "hostile",
				Href: "/file/" + depTestSHA,
			}},
			AnalyzedDate: "2h ago",
		}},
	}
	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	html := sb.String()
	if !strings.Contains(html, "Pulls a hostile dependency at install time.") {
		t.Error("rationale missing")
	}
	if !strings.Contains(html, `href="/file/`+depTestSHA+`"`) {
		t.Error("dependency chip must render beside the rationale, not be replaced by it")
	}
}
