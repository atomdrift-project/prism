package main

import (
	"cmp"
	"context"
	"html/template"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// sha256API is the lookup API's front door.
const sha256API = "https://sha256.is/"

// homeRows is how many rows each list on the home page previews.
const homeRows = 5

// versionPills caps a package page's version filter.
const versionPills = 10

// platformPills caps the Malware page's platform filter.
const platformPills = 6

var (
	homeTemplate         *template.Template
	apiTemplate          *template.Template
	contributingTemplate *template.Template

	// donateURL and sponsorURL fill the Contributing page's Money card. Unset,
	// the row is left out rather than pointing nowhere.
	donateURL  string
	sponsorURL string
)

// chrome is what the shared header needs from a request.
type chrome struct {
	// Nav names the current page: "fallout", "malware", "api", "contributing",
	// or "" when the page is none of them.
	Nav string
	// Query fills the search box.
	Query     string
	CSRFToken string
	// FalloutCount is the badge on the Fallout link. Zero hides it.
	FalloutCount  int
	UploadEnabled bool
	// Home drops the header's search box: that page has its own.
	Home bool
	// Refresh makes an upload force a fresh analysis.
	Refresh bool
}

func newChrome(r *http.Request, nav string) chrome {
	return chrome{
		Nav:           nav,
		CSRFToken:     csrfToken(r, "upload"),
		FalloutCount:  weeklyHostileCount(r.Context(), viewerLocation(r)),
		UploadEnabled: uploadEnabled && uploadBackendsAvailable(),
	}
}

// pill is one choice in a list's filter bar.
type pill struct {
	Label  string
	URL    string
	Count  int // shown beside the label; zero shows nothing
	Active bool
}

type homePageData struct {
	Stats       *indexStats
	Nonce       string // script-src nonce
	StyleNonce  string // style-src nonce
	BuildCommit string
	Fallout     []falloutRow
	Malware     []feedRow
	Chrome      chrome
	HasHopper   bool
}

// staticPageData is a page with nothing of its own to look up: API,
// Contributing.
type staticPageData struct {
	Nonce       string // script-src nonce
	StyleNonce  string // style-src nonce
	BuildCommit string
	// Links are the page's outbound addresses, by name.
	Links  map[string]string
	Chrome chrome
}

// handleHome is the front page: the search box, and the newest few rows of
// each list. Either list may come back empty; the page stands without them.
func handleHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Link", fontPreloadLink)
	// The Fallout preview is cut on the reader's week, read from the tz cookie.
	w.Header().Add("Vary", "Cookie")
	data := homePageData{
		Nonce:       nonceFor(r),
		StyleNonce:  styleNonceFor(r),
		BuildCommit: buildCommit,
		Chrome:      newChrome(r, ""),
		HasHopper:   hopperStore.Load() != nil,
	}
	data.Chrome.Home = true
	if s, ok := cachedIndexStats(); ok {
		data.Stats = &s
	}
	if data.HasHopper {
		data.Fallout = latestFallout(r.Context(), time.Now().In(viewerLocation(r)))
		data.Malware = latestMalware(r.Context())
	}
	if err := homeTemplate.Execute(w, data); err != nil {
		logger.Error("template execution failed", "template", "home", "error", err)
	}
}

// latestFallout returns the first homeRows rows of this week's Fallout page,
// in the order that page shows them.
func latestFallout(ctx context.Context, now time.Time) []falloutRow {
	week := falloutWeekOf(now, now)
	args := week.snapshotArgs()
	snapshot, _, err := loadFeedSnapshot(ctx, &args, logger, false)
	if err != nil {
		logger.Warn("home: fallout unavailable", "error", err)
		return nil
	}
	view := buildFalloutView(feedRowsFromSnapshot(snapshot), snapshot.Truncated, now, week, "", falloutAny)
	rows := make([]falloutRow, 0, homeRows)
	for i := range view.Days {
		day := view.Days[i].Rows
		rows = append(rows, day[:min(homeRows-len(rows), len(day))]...)
	}
	return rows
}

// latestMalware returns the newest homeRows hostile samples.
func latestMalware(ctx context.Context) []feedRow {
	snapshot, _, err := loadFeedSnapshot(ctx, &feedQueryArgs{criticality: "hostile"}, logger, false)
	if err != nil {
		logger.Warn("home: malware unavailable", "error", err)
		return nil
	}
	snapshot.Rows = snapshot.Rows[:min(homeRows, len(snapshot.Rows))]
	return feedRowsFromSnapshot(snapshot)
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	renderStatic(w, r, apiTemplate, "api", map[string]string{"SHA256": sha256API})
}

func handleContributing(w http.ResponseWriter, r *http.Request) {
	renderStatic(w, r, contributingTemplate, "contributing", map[string]string{"Donate": donateURL, "Sponsor": sponsorURL})
}

func renderStatic(w http.ResponseWriter, r *http.Request, tmpl *template.Template, nav string, links map[string]string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Link", fontPreloadLink)
	data := staticPageData{
		Nonce:       nonceFor(r),
		StyleNonce:  styleNonceFor(r),
		BuildCommit: buildCommit,
		Links:       links,
		Chrome:      newChrome(r, nav),
	}
	if err := tmpl.Execute(w, data); err != nil {
		logger.Error("template execution failed", "template", nav, "error", err)
	}
}

// load reads one snapshot's rows for the page. A failed read must not take
// the page down — the upload form, filters and footer work without rows — so
// it flags the list and returns nothing instead of serving a 500. A stale
// last-known-good snapshot is flagged the same way and still shown.
func (d *feedPageData) load(ctx context.Context, args *feedQueryArgs, bypass bool) []feedRow {
	snapshot, diag, err := loadFeedSnapshot(ctx, args, logger, bypass)
	if err != nil {
		logger.Warn("failed to load feed rows", "error", err, "ecosystem", args.ecosystem, "purl", args.purlBase)
		d.FeedDegraded = true
		return nil
	}
	d.diags = append(d.diags, diag)
	d.FeedDegraded = d.FeedDegraded || diag.Source == "stale"
	d.Domains, d.Ecosystems = snapshot.Domains, snapshot.Ecosystems
	return feedRowsFromSnapshot(snapshot)
}

// loadPackage fills a package page: the files of the release args names, or
// of every release when it names none, and the strip and version filter
// drawn from all of them. Without a database the page still says what the
// coordinate is and where else to look it up.
func (d *feedPageData) loadPackage(ctx context.Context, args *feedQueryArgs, bypass bool) {
	base, version := args.purlBase, args.purlVersion
	var all []feedRow
	if d.HasHopper {
		every := *args
		every.purlVersion = ""
		all = d.load(ctx, &every, bypass)
		switch {
		case version == "":
			d.Rows = all
		case len(all) < feedLimit:
			d.Rows = slices.DeleteFunc(slices.Clone(all), func(row feedRow) bool { return row.Version != version })
		default:
			// More files than one read holds: ask for the release by name.
			d.Rows = d.load(ctx, args, bypass)
		}
	}
	// The rows share a package, which is the heading; what tells them apart
	// is the file and the release.
	for i := range d.Rows {
		d.Rows[i].Label, d.Rows[i].Tag = d.Rows[i].Filename, d.Rows[i].Version
		d.Rows[i].ShowVerdict = true
	}
	d.Package = newPackageView(base, version, all, d.Rows)
	d.Pills = d.Package.Versions
	if len(d.Rows) == 0 {
		return
	}
	d.Lede = d.Rows[0].Desc
	d.Heading = d.Rows[0].Title()
	if version != "" {
		d.Heading = d.Rows[0].Headline()
	}
}

// platformPillsFor is the Malware page's platform filter: the ecosystems with
// the most hostile samples in the unfiltered snapshot, and the selected one
// whether or not it ranks. A failed read leaves the bar without pills.
func platformPillsFor(ctx context.Context, selected string, feedsOnly bool) []pill {
	snapshot, _, err := loadFeedSnapshot(ctx, &feedQueryArgs{criticality: "hostile", feedsOnly: feedsOnly}, logger, false)
	if err != nil {
		logger.Warn("malware: platform filter unavailable", "error", err)
		return nil
	}
	counts := make(map[string]int, 16)
	for i := range snapshot.Rows {
		if eco := snapshot.Rows[i].Ecosystem; eco != "" {
			counts[eco]++
		}
	}
	ranked := slices.SortedFunc(maps.Keys(counts), func(a, b string) int {
		return cmp.Or(cmp.Compare(counts[b], counts[a]), cmp.Compare(a, b))
	})
	ranked = ranked[:min(platformPills, len(ranked))]
	if selected != "" && !slices.Contains(ranked, selected) {
		ranked = append(ranked, selected)
	}
	link := func(eco string) string {
		q := url.Values{}
		if eco != "" {
			q.Set("ecosystem", eco)
		}
		if feedsOnly {
			q.Set("feeds", "1")
		}
		if len(q) == 0 {
			return "/malware"
		}
		return "/malware?" + q.Encode()
	}
	pills := []pill{{Label: "All", URL: link(""), Active: selected == ""}}
	for _, eco := range ranked {
		pills = append(pills, pill{Label: eco, URL: link(eco), Active: eco == selected})
	}
	return pills
}

// packageView is a package page's provenance strip and version filter.
type packageView struct {
	// PURL is the coordinate as people write it: pkg:pypi/cryptography@48.0.0.
	PURL string
	// Registry is the package's page on its own registry and RegistryLabel
	// the text of that link. Both empty when the registry is not one we know.
	Registry      string
	RegistryLabel string
	// Downloads is the registry's install count, empty when it gave none.
	Downloads string
	// Files counts the rows shown and the hostile ones among them.
	Files    string
	Versions []pill
}

// newPackageView describes the package at base. all holds every file of the
// package, newest first; shown holds the ones on the page, which is all of
// them unless version picks one release.
func newPackageView(base, version string, all, shown []feedRow) *packageView {
	display := purlDisplayString(purlWithVersion(base, version))
	v := &packageView{
		PURL:     display,
		Registry: registryURL(base, version),
	}
	v.RegistryLabel = strings.TrimSuffix(strings.TrimPrefix(registryURL(base, ""), "https://"), "/")
	hostile := 0
	for i := range shown {
		v.Downloads = cmp.Or(v.Downloads, shown[i].Users)
		if shown[i].Classification == "hostile" {
			hostile++
		}
	}
	switch {
	case len(shown) == 0:
	case hostile == 0:
		v.Files = strconv.Itoa(len(shown)) + ", none hostile"
	default:
		v.Files = strconv.Itoa(len(shown)) + ", " + strconv.Itoa(hostile) + " hostile"
	}

	counts := make(map[string]int, versionPills)
	for i := range all {
		if all[i].Version != "" {
			counts[all[i].Version]++
		}
	}
	if len(counts) < 2 {
		return v
	}
	newest := slices.SortedFunc(maps.Keys(counts), func(a, b string) int { return compareVersions(b, a) })
	newest = newest[:min(versionPills, len(newest))]
	if version != "" && counts[version] > 0 && !slices.Contains(newest, version) {
		newest = append(newest, version)
	}
	v.Versions = append(v.Versions, pill{Label: "All", URL: purlPageURL(base, ""), Count: len(all), Active: version == ""})
	for _, ver := range newest {
		v.Versions = append(v.Versions, pill{Label: ver, URL: purlPageURL(base, ver), Count: counts[ver], Active: ver == version})
	}
	return v
}

// compareVersions orders version strings the way people read them: a run of
// digits compares as a number, anything else as text, so 2.10 follows 2.9.
// It is not semver: a pre-release sorts after the release it precedes.
func compareVersions(a, b string) int {
	for a != "" && b != "" {
		na, nb := digitRun(a), digitRun(b)
		if na == 0 || nb == 0 {
			if a[0] != b[0] {
				return cmp.Compare(a[0], b[0])
			}
			a, b = a[1:], b[1:]
			continue
		}
		x, y := strings.TrimLeft(a[:na], "0"), strings.TrimLeft(b[:nb], "0")
		if c := cmp.Or(cmp.Compare(len(x), len(y)), cmp.Compare(x, y)); c != 0 {
			return c
		}
		a, b = a[na:], b[nb:]
	}
	return cmp.Compare(len(a), len(b))
}

// digitRun is the length of the run of decimal digits s starts with.
func digitRun(s string) int {
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	return n
}

// purlWithVersion pins the canonical version-less base to one release. The
// version belongs before any qualifiers: pkg:type/name@version?key=value.
func purlWithVersion(base, version string) string {
	if version == "" {
		return base
	}
	name, qualifiers, qualified := strings.Cut(base, "?")
	if !qualified {
		return name + "@" + version
	}
	return name + "@" + version + "?" + qualifiers
}

// purlPageURL is the package page for base, pinned to version when one is
// given. Like purlIndexURL it falls back to the ?purl= form for a coordinate
// whose qualifiers cannot ride in a path.
func purlPageURL(base, version string) string {
	return purlIndexURL(purlWithVersion(base, version))
}

// registryURL is the package's own page on its registry, or "" for a PURL
// type this table does not know or a coordinate carrying qualifiers, which
// name some other registry than the default.
func registryURL(base, version string) string {
	rest, ok := strings.CutPrefix(purlDisplayString(base), "pkg:")
	if !ok || strings.ContainsAny(rest, "?#") {
		return ""
	}
	typ, name, ok := strings.Cut(rest, "/")
	if !ok || name == "" {
		return ""
	}
	var root, pin string // pin joins the name to a version
	switch typ {
	case "npm":
		root, pin = "https://www.npmjs.com/package/", "/v/"
	case "pypi":
		root, pin = "https://pypi.org/project/", "/"
	case "gem":
		root, pin = "https://rubygems.org/gems/", "/versions/"
	case "cargo":
		root, pin = "https://crates.io/crates/", "/"
	case "golang":
		root, pin = "https://pkg.go.dev/", "@"
	case "nuget":
		root, pin = "https://www.nuget.org/packages/", "/"
	default:
		return ""
	}
	if version == "" {
		return root + name
	}
	return root + name + pin + version
}
