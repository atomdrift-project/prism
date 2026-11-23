package main

import (
	"html/template"
	"strings"
	"testing"

	"github.com/atomdrift-project/hopper"
)

const (
	depSHAHostile    = "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddee"
	depSHASuspicious = "bb11223344556677889900aabbccddeeff00112233445566778899aabbccddee"
	depSHABenign     = "cc11223344556677889900aabbccddeeff00112233445566778899aabbccddee"
)

// ref builds a resolved reference edge from a parent to file id.
func ref(to string, id int) cleaveRef {
	return cleaveRef{To: to, Kind: "dependency", TargetFile: &id}
}

// A fetched child that came back hostile becomes a chip named by the PURL its
// parent declared — not by the registry tarball URL the fetch resolved to.
func TestFlaggedDepsPrefersDeclaredPURL(t *testing.T) {
	files := []cleaveFile{
		{ID: 0, Path: "wrapper.tgz", Classification: "hostile", Refs: []cleaveRef{ref("pkg:npm/zaboodle@1.49", 1)}},
		{
			ID: 1, Parent: new(0), Rel: "fetched", FileType: "javascript",
			Via:    "https://registry.npmjs.org/zaboodle/-/zaboodle-1.49.tgz",
			SHA256: depSHAHostile, Classification: "hostile",
		},
	}

	deps, hidden := flaggedDeps(files, nil)
	if hidden != 0 {
		t.Errorf("hidden = %d, want 0", hidden)
	}
	if len(deps) != 1 {
		t.Fatalf("deps = %+v, want exactly one", deps)
	}
	got := deps[0]
	if got.Label != "npm: zaboodle v1.49" {
		t.Errorf("Label = %q, want %q", got.Label, "npm: zaboodle v1.49")
	}
	if got.Locator != "pkg:npm/zaboodle@1.49" {
		t.Errorf("Locator = %q, want the declared PURL", got.Locator)
	}
	if got.Href != "/"+depSHAHostile {
		t.Errorf("Href = %q, want the dependency's own record", got.Href)
	}
	if got.Kind != "" {
		t.Errorf("Kind = %q, want empty — the ecosystem already names a package", got.Kind)
	}
}

// A bare URL reference has no PURL to fall back on: the chip compacts the URL
// and carries the sniffed type, so "what did it pull" stays legible.
func TestFlaggedDepsURLReference(t *testing.T) {
	files := []cleaveFile{
		{ID: 0, Path: "install.sh", Classification: "suspicious"},
		{
			ID: 1, Parent: new(0), Rel: "fetched", FileType: "pe",
			Via: "https://x.y.z/dl/x.exe", SHA256: depSHAHostile, Classification: "hostile",
		},
	}

	deps, _ := flaggedDeps(files, nil)
	if len(deps) != 1 {
		t.Fatalf("deps = %+v, want exactly one", deps)
	}
	if deps[0].Label != "x.y.z/x.exe" {
		t.Errorf("Label = %q, want %q", deps[0].Label, "x.y.z/x.exe")
	}
	if deps[0].Kind != "pe" {
		t.Errorf("Kind = %q, want %q", deps[0].Kind, "pe")
	}
}

// The panel explains an elevated verdict, so benign dependencies, sidecars,
// unscored files, and ordinary archive members all stay out of it.
func TestFlaggedDepsExcludesEverythingBenign(t *testing.T) {
	files := []cleaveFile{
		{ID: 0, Path: "wrapper.tgz", Classification: "hostile"},
		{ID: 1, Parent: new(0), Rel: "fetched", Via: "https://a.example/a", SHA256: depSHABenign, Classification: "benign"},
		{ID: 2, Parent: new(0), Rel: "fetched", Role: "sidecar", Via: "https://b.example/b", SHA256: depSHAHostile, Classification: "hostile"},
		{ID: 3, Parent: new(0), Rel: "fetched", Via: "https://c.example/c", SHA256: depSHAHostile, Classification: ""},
		{ID: 4, Parent: new(0), Path: "lib/evil.js", SHA256: depSHAHostile, Classification: "hostile"},
	}

	deps, _ := flaggedDeps(files, nil)
	if len(deps) != 0 {
		t.Errorf("deps = %+v, want none — nothing here is a flagged dependency", deps)
	}
}

// Hostile sorts above suspicious, and the same payload reached twice is one
// dependency rather than two chips.
func TestFlaggedDepsOrdersAndDedups(t *testing.T) {
	files := []cleaveFile{
		{ID: 0, Path: "wrapper.tgz", Classification: "hostile"},
		{ID: 1, Parent: new(0), Rel: "fetched", Via: "https://a.example/sus", SHA256: depSHASuspicious, Classification: "suspicious"},
		{ID: 2, Parent: new(0), Rel: "fetched", Via: "https://b.example/bad", SHA256: depSHAHostile, Classification: "hostile"},
		{ID: 3, Parent: new(0), Rel: "fetched", Via: "https://c.example/same", SHA256: depSHAHostile, Classification: "hostile"},
	}

	deps, _ := flaggedDeps(files, nil)
	if len(deps) != 2 {
		t.Fatalf("deps = %+v, want two (the duplicate sha collapses)", deps)
	}
	if deps[0].Crit != "hostile" || deps[1].Crit != "suspicious" {
		t.Errorf("order = %q then %q, want hostile first", deps[0].Crit, deps[1].Crit)
	}
}

// A sample declaring more hostile dependencies than the panel shows must
// report the remainder instead of presenting the cap as the whole set.
func TestFlaggedDepsReportsCappedRemainder(t *testing.T) {
	files := []cleaveFile{{ID: 0, Path: "wrapper.tgz", Classification: "hostile"}}
	for i := 1; i <= maxFlaggedDeps+7; i++ {
		files = append(files, cleaveFile{
			ID: i, Parent: new(0), Rel: "fetched", Classification: "hostile",
			Via: "https://evil.example/" + strings.Repeat("a", i),
		})
	}

	deps, hidden := flaggedDeps(files, nil)
	if len(deps) != maxFlaggedDeps {
		t.Errorf("len(deps) = %d, want the cap %d", len(deps), maxFlaggedDeps)
	}
	if hidden != 7 {
		t.Errorf("hidden = %d, want 7", hidden)
	}
}

// A dependency without a usable sha still names itself; it just has no record
// to link to, so the chip must render as a span rather than a dead link.
func TestFlaggedDepsWithoutSHAHasNoHref(t *testing.T) {
	files := []cleaveFile{
		{ID: 0, Path: "wrapper.tgz", Classification: "hostile"},
		{ID: 1, Parent: new(0), Rel: "fetched", Via: "https://a.example/a", SHA256: "not-a-sha", Classification: "hostile"},
	}

	deps, _ := flaggedDeps(files, nil)
	if len(deps) != 1 {
		t.Fatalf("deps = %+v, want exactly one", deps)
	}
	if deps[0].Href != "" {
		t.Errorf("Href = %q, want empty for an unlinkable dependency", deps[0].Href)
	}
}

func TestResultTemplateRendersFlaggedDepChips(t *testing.T) {
	tmpl := resultTemplateForTest(t)
	data := singleFileData()
	data.FlaggedDeps = []flaggedDep{
		{Label: "npm: zaboodle v1.49", Locator: "pkg:npm/zaboodle@1.49", Crit: "hostile", SHA256: depSHAHostile, Href: "/" + depSHAHostile},
		{Label: "x.y.z/x.exe", Locator: "https://x.y.z/dl/x.exe", Kind: "pe", Crit: "suspicious"},
	}
	data.FlaggedDepsHidden = 3
	data.Badges = []topTrait{{Desc: "spawns child", Crit: "hostile"}}

	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	html := sb.String()

	dep := `<a class="badge hostile" href="/` + depSHAHostile + `" title="pkg:npm/zaboodle@1.49">`
	if !strings.Contains(html, dep+`<span class="crit-dot hostile" aria-hidden="true"></span>Depends on npm: zaboodle v1.49</a>`) {
		t.Error("linkable dependency must render as a chip linking to its own record")
	}
	if !strings.Contains(html, `<span class="badge suspicious" title="https://x.y.z/dl/x.exe">`) {
		t.Error("dependency without a record must stay a plain span")
	}
	if !strings.Contains(html, "+3 more") {
		t.Error("capped remainder must be disclosed")
	}
	// The dependencies lead the findings: first chip, ahead of every trait.
	if d, tr := strings.Index(html, dep), strings.Index(html, "spawns child"); d < 0 || tr < 0 || d > tr {
		t.Errorf("dependency chip at %d, first trait at %d: the dependency must come first", d, tr)
	}
	if strings.Contains(html, "flagged dependenc") {
		t.Error("the separate rail panel is gone; dependencies live in the findings row")
	}
	// An archive's findings are re-rendered once its members load; the
	// dependency must survive that swap.
	var findings strings.Builder
	if err := tmpl.ExecuteTemplate(&findings, "findingsbody", data); err != nil {
		t.Fatalf("findingsbody: %v", err)
	}
	if !strings.Contains(findings.String(), dep) {
		t.Error("findingsbody dropped the dependency chip")
	}
}

// Locators are attacker-authored manifest strings; they must never reach the
// page unescaped, in the chip text or the tooltip.
func TestResultTemplateEscapesHostileLocator(t *testing.T) {
	tmpl := resultTemplateForTest(t)
	data := singleFileData()
	data.FlaggedDeps = []flaggedDep{{
		Label:   `<script>alert(1)</script>`,
		Locator: `pkg:npm/<script>alert(1)</script>@1.0`,
		Crit:    "hostile",
	}}

	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.Contains(sb.String(), "<script>alert(1)</script>") {
		t.Error("hostile locator reached the page unescaped")
	}
}

// A verdict hopper's lookup raised through references atomscan never fetched
// (go.mod requirements whose own records are hostile) must name them: the
// panel is the only place the page explains a dependency-raised verdict.
func TestFlaggedDepsNamesLookupRaisers(t *testing.T) {
	sha := depSHAHostile
	files := []cleaveFile{{ID: 0, Path: "v5.6.0", Classification: "benign"}}
	raisers := []hopper.LookupRaiser{
		{Kind: "dependency", Name: "pkg:golang/github.com/saferwall/pe", Version: "v1.6.5", SHA256: &sha, FiresAt: new(0), Why: hopper.RaisedDetected},
		{Kind: "dependency", Name: "pkg:golang/actionlint.kjanat.dev", Version: "v1.17.0", FiresAt: new(0), Why: hopper.RaisedDetected},
		{Kind: "member", Name: "pkg:golang/inner", SHA256: &sha, FiresAt: new(0)},
		{Kind: "url_fetch", Name: "https://x.y.z/dl/x.exe", Version: "1", FiresAt: nil},
		{Kind: "dependency", Name: "pkg:npm/clean", Version: "1.0.0", FiresAt: new(-1)},
	}

	deps, hidden := flaggedDeps(files, raisers)
	if hidden != 0 {
		t.Errorf("hidden = %d, want 0", hidden)
	}
	got := make(map[string]flaggedDep, len(deps))
	for _, d := range deps {
		got[d.Label] = d
	}
	if len(deps) != 3 {
		t.Fatalf("deps = %+v, want the two go modules and the URL", deps)
	}
	pe, ok := got["golang: github.com/saferwall/pe v1.6.5"]
	if !ok {
		t.Fatalf("saferwall/pe chip missing: %+v", deps)
	}
	if pe.Crit != "hostile" || pe.Href != "/"+sha || pe.Locator != "pkg:golang/github.com/saferwall/pe@v1.6.5" {
		t.Errorf("pe chip = %+v", pe)
	}
	if al := got["golang: actionlint.kjanat.dev v1.17.0"]; al.Href != "" || al.Crit != "hostile" {
		t.Errorf("actionlint chip = %+v, want hostile with no link (no sha)", al)
	}
	if u := got["x.y.z/x.exe"]; u.Locator != "https://x.y.z/dl/x.exe" || u.Crit != "hostile" {
		t.Errorf("url chip = %+v, want the bare URL, hostile for a level-less raise", u)
	}
}

// A dependency atomscan fetched and hopper's lookup also raised is one chip.
func TestFlaggedDepsDedupsFetchedAndRaised(t *testing.T) {
	sha := depSHAHostile
	files := []cleaveFile{
		{ID: 0, Path: "wrapper.tgz", Refs: []cleaveRef{ref("pkg:npm/zaboodle@1.49", 1)}},
		{ID: 1, Parent: new(0), Rel: "fetched", SHA256: sha, Classification: "hostile"},
	}
	raisers := []hopper.LookupRaiser{{Kind: "dependency", Name: "pkg:npm/zaboodle", Version: "1.49", SHA256: &sha, FiresAt: new(0)}}
	if deps, _ := flaggedDeps(files, raisers); len(deps) != 1 {
		t.Errorf("deps = %+v, want one chip", deps)
	}
}

// Member evidence inlined from the members cache is evidence: the page must
// not also claim none was recorded.
func TestResultTemplateInlinedMembersSuppressNoEvidenceNote(t *testing.T) {
	tmpl := resultTemplateForTest(t)
	data := singleFileData()
	data.FileViews = nil
	data.DeferredMembers = false
	data.MembersHTML = template.HTML(`<div id="file-x">member evidence</div>`)

	var sb strings.Builder
	if err := tmpl.Execute(&sb, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if strings.Contains(sb.String(), "No evidence locations were recorded") {
		t.Error("inlined member evidence rendered beside the no-evidence note")
	}
}

// The members cache holds rendered findings HTML, so a new build must never
// serve an older build's markup: a template change shows on deploy, not a day
// later.
func TestMembersKeyBelongsToTheBuild(t *testing.T) {
	saved := buildCommit
	t.Cleanup(func() { buildCommit = saved })
	buildCommit = "a543222"
	before := membersKey(depSHAHostile)
	buildCommit = "2b7066e"
	if after := membersKey(depSHAHostile); after == before {
		t.Errorf("membersKey = %q for both builds; an old build's HTML would be served", after)
	}
}
