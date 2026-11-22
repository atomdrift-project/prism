package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func parseForTest(t *testing.T, name string) *template.Template {
	t.Helper()
	tmpl, err := template.New(name).Funcs(templateFuncsForTest()).
		ParseFS(templatesFS, "templates/base.html", "templates/"+name)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return tmpl
}

func TestRegistryURL(t *testing.T) {
	for _, tt := range []struct{ base, version, want string }{
		{"pkg:pypi/cryptography", "48.0.0", "https://pypi.org/project/cryptography/48.0.0"},
		{"pkg:pypi/cryptography", "", "https://pypi.org/project/cryptography"},
		{"pkg:npm/%40scope/pkg", "1.2.3", "https://www.npmjs.com/package/@scope/pkg/v/1.2.3"},
		{"pkg:golang/github.com/user/repo", "v1.0.0", "https://pkg.go.dev/github.com/user/repo@v1.0.0"},
		{"pkg:gem/rails", "7.1.0", "https://rubygems.org/gems/rails/versions/7.1.0"},
		// A qualifier names some other registry than the default one.
		{"pkg:npm/lodash?repository_url=https://example.test", "1.0.0", ""},
		{"pkg:chrome/abcdefgh", "1.0", ""},
		{"not-a-purl", "", ""},
	} {
		if got := registryURL(tt.base, tt.version); got != tt.want {
			t.Errorf("registryURL(%q, %q) = %q, want %q", tt.base, tt.version, got, tt.want)
		}
	}
}

func TestPURLPageURL(t *testing.T) {
	for _, tt := range []struct{ base, version, want string }{
		{"pkg:npm/lodash", "", "/npm/lodash"},
		{"pkg:npm/lodash", "4.17.21", "/npm/lodash@4.17.21"},
		{"pkg:npm/%40scope/pkg", "1.0.0", "/npm/@scope/pkg@1.0.0"},
		// The version goes before the qualifiers, and a qualified coordinate
		// cannot ride in a path.
		{
			"pkg:vscode-extension/pub/name?repository_url=https://open-vsx.org", "1.2.3",
			"/?purl=pkg%3Avscode-extension%2Fpub%2Fname%401.2.3%3Frepository_url%3Dhttps%3A%2F%2Fopen-vsx.org",
		},
	} {
		if got := purlPageURL(tt.base, tt.version); got != tt.want {
			t.Errorf("purlPageURL(%q, %q) = %q, want %q", tt.base, tt.version, got, tt.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	// Each is older than the next.
	order := []string{"2.9", "2.9.1", "2.10", "3.1", "3.4.5", "37.0.1", "48.0.0", "48.0.1", "50.0.2"}
	for i := range order[:len(order)-1] {
		a, b := order[i], order[i+1]
		if compareVersions(a, b) >= 0 || compareVersions(b, a) <= 0 {
			t.Errorf("want %s older than %s", a, b)
		}
	}
	for _, same := range [][2]string{{"1.0", "1.0"}, {"1.01", "1.1"}} {
		if c := compareVersions(same[0], same[1]); c != 0 {
			t.Errorf("compareVersions(%q, %q) = %d, want 0", same[0], same[1], c)
		}
	}
}

func TestNewPackageView(t *testing.T) {
	file := func(version, class string) feedRow {
		return feedRow{Version: version, Classification: class}
	}
	var all []feedRow
	// Twelve releases, so the one asked for falls off the newest ten.
	for _, v := range []string{"1.0", "2.0", "3.0", "4.0", "5.0", "6.0", "7.0", "8.0", "9.0", "10.0", "11.0", "12.0"} {
		all = append(all, file(v, "benign"))
	}
	all = append(all, file("1.0", "hostile"))
	shown := []feedRow{all[0], all[len(all)-1]}
	shown[0].Users = "1,234"

	v := newPackageView("pkg:pypi/thing", "1.0", all, shown)
	if v.PURL != "pkg:pypi/thing@1.0" || v.JSON != purlAPI+"pkg:pypi/thing@1.0" {
		t.Errorf("PURL = %q, JSON = %q", v.PURL, v.JSON)
	}
	if v.Files != "2, 1 hostile" || v.Downloads != "1,234" {
		t.Errorf("Files = %q, Downloads = %q", v.Files, v.Downloads)
	}
	if v.RegistryLabel != "pypi.org/project/thing" {
		t.Errorf("RegistryLabel = %q", v.RegistryLabel)
	}
	labels := make([]string, 0, len(v.Versions))
	for _, p := range v.Versions {
		labels = append(labels, p.Label)
	}
	if got, want := strings.Join(labels, " "), "All 12.0 11.0 10.0 9.0 8.0 7.0 6.0 5.0 4.0 3.0 1.0"; got != want {
		t.Errorf("versions = %q, want %q", got, want)
	}
	last := v.Versions[len(v.Versions)-1]
	if !last.Active || last.Count != 2 || last.URL != "/pypi/thing@1.0" {
		t.Errorf("selected pill = %+v", last)
	}

	// One release is nothing to filter by, and no rows is nothing to count.
	lone := newPackageView("pkg:pypi/thing", "", all[:1], nil)
	if len(lone.Versions) != 0 || lone.Files != "" || lone.Downloads != "" {
		t.Errorf("lone package = %+v", lone)
	}
	if clean := newPackageView("pkg:pypi/thing", "", all[:2], all[:2]); clean.Files != "2, none hostile" {
		t.Errorf("clean Files = %q", clean.Files)
	}
}

func TestFeedRowName(t *testing.T) {
	for _, tt := range []struct {
		name string
		row  feedRow
		want string
	}{
		{"package and version", feedRow{Package: "lodash", Version: "4.17.21", Filename: "lodash-4.17.21.tgz"}, "lodash 4.17.21"},
		{"the page's label wins", feedRow{Label: "lodash-4.17.21.tgz", Package: "lodash", Version: "4.17.21"}, "lodash-4.17.21.tgz"},
		{"a hash is not a name", feedRow{Filename: testSHARow, SHA256: testSHARow}, ""},
		{"nor is nothing", feedRow{SHA256: testSHARow}, ""},
	} {
		if got := tt.row.Name(); got != tt.want {
			t.Errorf("%s: Name() = %q, want %q", tt.name, got, tt.want)
		}
	}
	if got := (feedRow{}).Badge(); got != "" {
		t.Errorf("a row with no ecosystem has badge %q, want none", got)
	}
	if got := (feedRow{Tag: "1.0", Ecosystem: "python"}).Badge(); got != "1.0" {
		t.Errorf("Badge() = %q, want the page's tag", got)
	}
}

// A delta under a day, a date after: nobody subtracts timestamps in their head.
func TestFeedDate(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		age  time.Duration
		want string
	}{
		{48 * time.Minute, "48m ago"},
		{2 * time.Hour, "2h ago"},
		{23*time.Hour + 59*time.Minute, "23h ago"},
		{72 * time.Hour, now.Add(-72 * time.Hour).Local().Format("Jan 2")}, //nolint:gosmopolitan // mirrors feedDate
	} {
		if got := feedDate(now.Add(-tt.age), now); got != tt.want {
			t.Errorf("feedDate(%s ago) = %q, want %q", tt.age, got, tt.want)
		}
	}
}

// The list row, as every list page draws it.
func TestListRow(t *testing.T) {
	tmpl := uploadTemplateForTest(t)
	render := func(row feedRow) string {
		t.Helper()
		var sb strings.Builder
		if err := tmpl.Execute(&sb, feedPageData{HasHopper: true, Rows: []feedRow{row}}); err != nil {
			t.Fatalf("execute: %v", err)
		}
		html := sb.String()
		return html[strings.Index(html, `<li class="row">`):strings.Index(html, `</li>`)]
	}

	named := render(feedRow{
		SHA256: testSHARow, Package: "evil", Version: "1.0.0", Classification: "hostile",
		Why: "steals tokens", Corroborated: true, AnalyzedDate: "2h ago",
	})
	// The sighting mark follows the name, not the hash.
	name := strings.Index(named, `>evil 1.0.0</a>`)
	mark := strings.Index(named, `aria-label="Sighted elsewhere"`)
	hash := strings.Index(named, `<span class="file-sha"`)
	if name < 0 || mark < name || hash < mark {
		t.Errorf("want name, then sighting mark, then hash:\n%s", named)
	}
	for _, want := range []string{`<span class="why">steals tokens</span>`, `>2h ago</span>`} {
		if !strings.Contains(named, want) {
			t.Errorf("row missing %q:\n%s", want, named)
		}
	}
	// Malware and Fallout are all hostile; saying so on every row is noise.
	if strings.Contains(named, `class="verdict`) {
		t.Errorf("a row that was not asked for its verdict shows one:\n%s", named)
	}

	nameless := render(feedRow{SHA256: testSHARow, Filename: testSHARow, Classification: "hostile", Corroborated: true})
	if !strings.Contains(nameless, `<a class="file-link hash" href="/file/`+testSHARow+`">`) || strings.Contains(nameless, "row-name") {
		t.Errorf("a nameless row must link its hash and print no name line:\n%s", nameless)
	}

	// With no rationale and no traits, the row still says what the thing is.
	bare := render(feedRow{SHA256: testSHARow, Package: "left-pad", Classification: "benign", Desc: "String left pad", ShowVerdict: true})
	for _, want := range []string{`<span class="verdict benign">benign</span>`, "String left pad"} {
		if !strings.Contains(bare, want) {
			t.Errorf("row missing %q:\n%s", want, bare)
		}
	}
}

func TestPackagePageRenders(t *testing.T) {
	uploadTemplate = uploadTemplateForTest(t)
	t.Cleanup(func() { uploadTemplate = nil })
	rr := httptest.NewRecorder()
	newMux().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/pypi/cryptography@48.0.0", http.NoBody))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`<dd class="mono">pkg:pypi/cryptography@48.0.0</dd>`,
		`href="https://pypi.org/project/cryptography/48.0.0"`,
		`href="` + purlAPI + `pkg:pypi/cryptography@48.0.0"`,
		"No database.", // nothing is connected in this test
	} {
		if !strings.Contains(body, want) {
			t.Errorf("package page missing %q", want)
		}
	}
}

// A PURL typed into the box reaches the server in ?q= when no script rewrote
// it; it must still land on the package, not run as a filename search.
func TestPURLInSearchBoxIsAPackage(t *testing.T) {
	uploadTemplate = uploadTemplateForTest(t)
	t.Cleanup(func() { uploadTemplate = nil })
	rr := httptest.NewRecorder()
	newMux().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/stream?q=pkg:npm/lodash", http.NoBody))
	if body := rr.Body.String(); !strings.Contains(body, `aria-label="Provenance"`) {
		t.Error("?q=pkg:npm/lodash did not render the package page")
	}
}

func TestMalwarePage(t *testing.T) {
	uploadTemplate = uploadTemplateForTest(t)
	t.Cleanup(func() { uploadTemplate = nil })
	rr := httptest.NewRecorder()
	newMux().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/malware", http.NoBody))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"<h1>Malware</h1>",
		`<a href="/malware" aria-current="page">Malware</a>`,
		`id="search-input" value=""`, // one fixed question: the box stays empty
	} {
		if !strings.Contains(body, want) {
			t.Errorf("malware page missing %q", want)
		}
	}
	// The verdict filter belongs to the index; here there is nothing to pick.
	if strings.Contains(body, `id="criticality"`) {
		t.Error("malware page offers a verdict filter")
	}
}

func TestStaticPages(t *testing.T) {
	homeTemplate = parseForTest(t, "home.html")
	apiTemplate = parseForTest(t, "api.html")
	contributingTemplate = parseForTest(t, "contributing.html")
	savedDonate := donateURL
	t.Cleanup(func() {
		homeTemplate, apiTemplate, contributingTemplate, donateURL = nil, nil, nil, savedDonate
	})
	mux := newMux()
	get := func(path string) string {
		t.Helper()
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, http.NoBody))
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, rr.Code)
		}
		return rr.Body.String()
	}

	home := get("/")
	for _, want := range []string{
		"Look up any file by hash, or package by PURL",
		`<form method="GET" action="/stream" class="search-form" id="search-form"`,
	} {
		if !strings.Contains(home, want) {
			t.Errorf("home missing %q", want)
		}
	}
	// One box per page: the home page has its own, so the header has none.
	if n := strings.Count(home, `id="search-input"`); n != 1 {
		t.Errorf("home has %d search boxes, want 1", n)
	}

	api := get("/api")
	for _, want := range []string{
		sha256API + "{sha256}",
		purlAPI + "{purl}",
		`data-url="` + purlAPI + `pkg:npm/node-ipc@9.2.3"`,
		"/static/js/api.js",
		`<a href="/api" aria-current="page">API</a>`,
	} {
		if !strings.Contains(api, want) {
			t.Errorf("api page missing %q", want)
		}
	}

	// No link, no row: the page never points nowhere.
	donateURL = ""
	if page := get("/contributing"); strings.Contains(page, "<h2>Money</h2>") || !strings.Contains(page, "<h2>Support</h2>") {
		t.Error("contributing without links: want Support and no Money card")
	}
	donateURL = "https://example.test/donate"
	if page := get("/contributing"); !strings.Contains(page, `href="https://example.test/donate"`) {
		t.Error("contributing does not show the donation link it was given")
	}
}

// "/" has been the stream's home and the fallout log's; their links still
// arrive there with queries only those pages can answer.
func TestHomeForwardsOldQueries(t *testing.T) {
	mux := newMux()
	for path, want := range map[string]string{
		"/?q=lodash":                 "/stream?q=lodash",
		"/?criticality=hostile":      "/stream?criticality=hostile",
		"/?week=2026-07-27":          "/fallout?week=2026-07-27",
		"/?ecosystem=npm&verified=1": "/fallout?ecosystem=npm&verified=1",
	} {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, http.NoBody))
		if got := rr.Header().Get("Location"); rr.Code != http.StatusMovedPermanently || got != want {
			t.Errorf("GET %s = %d to %q, want 301 to %q", path, rr.Code, got, want)
		}
	}
}

// The API page's Run buttons call the API from the browser, so the policy
// has to let them — and nothing else.
func TestCSPAllowsTheAPI(t *testing.T) {
	rr := httptest.NewRecorder()
	securityHeaders(http.NotFoundHandler()).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api", http.NoBody))
	csp := rr.Header().Get("Content-Security-Policy")
	if want := "connect-src 'self' https://sha256.is https://purl.is; "; !strings.Contains(csp, want) {
		t.Errorf("CSP = %q, want it to contain %q", csp, want)
	}
}
