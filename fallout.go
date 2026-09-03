package main

// The Fallout log is the damage feed at /fallout: every hostile catch of one
// calendar week, grouped into day bands, campaigns collapsed into waves.
// /fallout is the week in progress; /fallout?week=2026-08-24 is the week that
// Monday began, back to falloutArchiveWeeks. A dated URL names the same
// catches forever, which is what makes a week citable in a writeup.
//
// The log asks hopper for a period, not for a page of rows: its snapshot is
// the created_at window the week covers, paged in whole (see
// feedSamplesInWindow). Reading the shared feed page instead is what once
// capped the "week" at whatever the newest 500 hostile rows spanned — twelve
// hours, at the 2026 catch rate, under a masthead that still said "this week".
//
// Day bands are calendar days in the reader's own time zone, not UTC: "TODAY"
// has to mean the reader's today, and grouping in UTC titles a New Yorker's
// Friday evening "YESTERDAY" because it is already Saturday in Greenwich. The
// zone arrives in the tz cookie (see viewerLocation) and reaches every band
// through the location carried on the now passed to buildFalloutView.
//
// Within a day, waves lead (largest first) and singles follow by heat. A wave
// is an exact-key campaign: same day band, ecosystem, file type, and malecule
// formula, three members or more. Its row is titled by its best exemplar —
// the top-downloaded member when install counts are known, the hottest
// otherwise — because 23 typosquats of one drainer kit are one event, not 23.

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	// falloutArchiveWeeks is how far back ?week= reaches. It bounds the log's
	// history to something a reader plausibly wants and, more to the point,
	// bounds the set of week snapshots a visitor can ask the cache to hold:
	// each is a week of hostile rows, and without a floor a crawler walking
	// ?week= backwards would mint them forever.
	falloutArchiveWeeks = 12
	// falloutZonePad widens the window prism asks hopper for so one snapshot
	// serves every reader. A week is cut at midnight in the *reader's* zone,
	// which lands anywhere from 12 hours before to 14 hours after midnight UTC
	// on the same date; padding both ends by 14 hours makes the fetched window
	// a superset of every zone's version of that week, so the snapshot — and
	// its cache key — depend only on the week's date, and the reader's own
	// boundaries are applied to the rows in memory.
	falloutZonePad = 14 * time.Hour
	// falloutWeekLayout is how a week is spelled in a URL and a cache key: the
	// date of the Monday it starts on.
	falloutWeekLayout = "2006-01-02"
	// waveMinSize is the smallest campaign worth collapsing: below three
	// members, showing the rows individually reads better than a wave row.
	waveMinSize = 3
	// falloutSinglesPerSector caps how many unwaved rows one ecosystem may
	// place in a single day band — the backstop that keeps a pathological
	// day of distinct npm catches from drowning the rare sectors the log
	// exists to surface. Waves are exempt: they already collapse volume.
	falloutSinglesPerSector = 3
)

// falloutWeek is one page of the log: the calendar week [Start, End) in the
// reader's own zone, and the Monday date that names it in a URL and in the
// cache. Start/End are instants — a reader in Auckland and one in Los Angeles
// asking for the same Date get different instants, which is correct: each sees
// their own week.
type falloutWeek struct {
	Start time.Time
	End   time.Time
	// Date is the Monday, "2006-01-02". It is the same string for every
	// reader, so it addresses one snapshot rather than one per zone.
	Date string
	// Prev/Next are the Dates the older/newer links point at, empty when
	// there is nowhere to go: Prev at the archive floor, Next on the current
	// week. Next is empty rather than a future date so the log never offers a
	// week that cannot have happened yet.
	Prev string
	Next string
	// Current marks the week in progress — the one /fallout shows with no
	// ?week=, still filling, and the only one whose snapshot goes stale.
	Current bool
}

// falloutWeekStart returns the midnight that begins t's calendar week, in t's
// own location. Weeks start on Monday: Go's Weekday counts from Sunday, so the
// shift by 6 rotates Sunday to the end of the week rather than the start of it.
func falloutWeekStart(t time.Time) time.Time {
	y, m, d := t.Date()
	midnight := time.Date(y, m, d, 0, 0, 0, 0, t.Location())
	return midnight.AddDate(0, 0, -((int(midnight.Weekday()) + 6) % 7))
}

// falloutWeekOf builds the week containing t, in t's location. Boundaries move
// by calendar days rather than by 168 hours so a week spanning a DST change is
// still seven midnights.
func falloutWeekOf(t, now time.Time) falloutWeek {
	start := falloutWeekStart(t)
	current := falloutWeekStart(now)
	w := falloutWeek{
		Start:   start,
		End:     start.AddDate(0, 0, 7),
		Date:    start.Format(falloutWeekLayout),
		Current: start.Equal(current),
	}
	if !w.Current {
		w.Next = start.AddDate(0, 0, 7).Format(falloutWeekLayout)
	}
	if prev := start.AddDate(0, 0, -7); !prev.Before(current.AddDate(0, 0, -7*falloutArchiveWeeks)) {
		w.Prev = prev.Format(falloutWeekLayout)
	}
	return w
}

// parseFalloutWeek resolves ?week= to the week it names, read in now's zone.
// Empty selects the week in progress. Any date inside a week resolves to that
// week, so a hand-shortened or mid-week date still lands somewhere real. A
// future week, or one older than the archive reaches, is an error: those are
// the values that would otherwise mint an unbounded set of cache keys.
func parseFalloutWeek(raw string, now time.Time) (falloutWeek, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return falloutWeekOf(now, now), nil
	}
	day, err := time.ParseInLocation(falloutWeekLayout, raw, now.Location())
	if err != nil {
		return falloutWeek{}, errors.New("week must be a date, YYYY-MM-DD")
	}
	week := falloutWeekOf(day, now)
	current := falloutWeekStart(now)
	switch {
	case week.Start.After(current):
		return falloutWeek{}, errors.New("week is in the future")
	case week.Start.Before(current.AddDate(0, 0, -7*falloutArchiveWeeks)):
		return falloutWeek{}, fmt.Errorf("week is older than the log keeps (%d weeks)", falloutArchiveWeeks)
	}
	return week, nil
}

// snapshotArgs is the hopper query behind the week: every hostile catch in the
// window, padded so the one snapshot covers the week as any zone cuts it. The
// padding is why the window is derived from the Date read in UTC rather than
// from Start/End, which are the reader's own instants.
func (w falloutWeek) snapshotArgs() feedQueryArgs {
	day, err := time.ParseInLocation(falloutWeekLayout, w.Date, time.UTC)
	if err != nil {
		// Unreachable: Date is always written by Format with this layout.
		day = w.Start.UTC()
	}
	return feedQueryArgs{
		criticality: "hostile",
		since:       day.Add(-falloutZonePad),
		until:       day.AddDate(0, 0, 7).Add(falloutZonePad),
	}
}

// param is how the week is spelled in a link: empty for the week in progress,
// which lives at the bare /fallout, so the log's front door never carries a
// date that goes stale the moment the week turns over.
func (w falloutWeek) param() string {
	if w.Current {
		return ""
	}
	return w.Date
}

// label names the period the masthead and the survey rule state. The week in
// progress is "this week" — it is still happening, and a date range would read
// as though it had already closed.
func (w falloutWeek) label() string {
	if w.Current {
		return "this week"
	}
	return w.Start.Format("Jan 2") + " – " + w.End.AddDate(0, 0, -1).Format("Jan 2")
}

// falloutURL is the log's canonical link: the current week is bare /fallout,
// every other week carries its date, and the reader's sector and verification
// filters ride along so a link out of the strip or the week nav keeps the view
// they are looking at.
func falloutURL(week, eco, verified string) string {
	q := make(url.Values, 3)
	if week != "" {
		q.Set("week", week)
	}
	if eco != "" {
		q.Set("ecosystem", eco)
	}
	if verified != "" {
		q.Set("verified", verified)
	}
	if len(q) == 0 {
		return "/fallout"
	}
	return "/fallout?" + q.Encode()
}

type falloutVerificationFilter uint8

const (
	falloutAny falloutVerificationFilter = iota
	falloutUncorroborated
	falloutCorroborated
)

// parseFalloutVerification keeps verification as a presentation filter. It
// must not become a feedQueryArgs field: verified=0 and the regular fallout
// page intentionally consume the same hostile snapshot cache entry.
func parseFalloutVerification(raw string) (falloutVerificationFilter, error) {
	switch raw {
	case "":
		return falloutAny, nil
	case "0":
		return falloutUncorroborated, nil
	case "1":
		return falloutCorroborated, nil
	default:
		return falloutAny, errors.New("verified must be 0 or 1")
	}
}

func (f falloutVerificationFilter) matches(corroborated bool) bool {
	switch f {
	case falloutUncorroborated:
		return !corroborated
	case falloutCorroborated:
		return corroborated
	default:
		return true
	}
}

// falloutRow is one line of the log: a single catch, or a wave of them
// represented by its exemplar. The embedded feedRow is the exemplar itself,
// so identity, rationale, and chips render with the ledger's grammar.
//
//nolint:govet // fieldalignment: embedded-first reads better on a struct built a page at a time
type falloutRow struct {
	feedRow

	// HeatClass buckets the row's age for the decay halo: "heat-2" under six
	// hours, "heat-1" under a day, "heat-0" once the particle has cooled.
	HeatClass string
	// Ribbon/RibbonTip carry the row's earned superlative, when it won one
	// ("biggest blast radius", "first seen anywhere"). Computed, never written.
	Ribbon    string
	RibbonTip string
	// WaveSize is the campaign's member count; zero for a single catch.
	// Siblings is WaveSize-1, precomputed because templates can't subtract.
	WaveSize int
	Siblings int
}

// IsWave reports whether the row represents a collapsed campaign. Value
// receiver on purpose: html/template calls it on the non-addressable copies a
// {{range}} yields, which cannot reach a pointer receiver's method set.
//
//nolint:gocritic // see above — a pointer receiver breaks template rendering
func (r falloutRow) IsWave() bool { return r.WaveSize >= waveMinSize }

// falloutDay is one day band of the log.
type falloutDay struct {
	Label string // "TODAY", "YESTERDAY", or an uppercase weekday
	Sub   string // "Mon Aug 4 · 21 catches · 2 waves · 4 singles"
	// ID anchors the band so the rail can jump to it; Date and Count feed
	// the rail's day list without re-parsing Sub.
	ID    string
	Date  string
	Rows  []falloutRow
	Count int
}

// falloutSector is one chip in the ecosystem strip: a sector with damage in
// the window. Sectors with nothing to report get no chip.
type falloutSector struct {
	Ecosystem string
	Color     string
	// URL is where the chip goes: into the sector, or back out of it when it
	// is the active one. Built in Go rather than in the template because it
	// has to carry the week and the verification filter with it.
	URL    string
	Count  int
	Active bool
}

type falloutPageData struct {
	Nonce       string
	StyleNonce  string
	BuildCommit string
	SelectedEco string
	Verified    string
	// WindowLabel mirrors falloutView; MeterSegs are the peak-meter segments
	// (lit = the newest day in view, against the window's busiest day).
	WindowLabel string
	// AllSectorsURL clears the sector filter without leaving the week;
	// OlderURL/NewerURL step the week nav, empty where there is nowhere to
	// go. CurrentWeek is false whenever the reader is looking at the archive,
	// which is what the "back to this week" affordance keys off.
	AllSectorsURL string
	// CiteURL is the dated address of this week, the one that names the same
	// catches forever, shown so a reader can cite it.
	CiteURL      string
	OlderURL     string
	NewerURL     string
	CurrentURL   string
	Sectors      []falloutSector
	Days         []falloutDay
	MeterSegs    []bool
	WeeklyCount  int
	HasHopper    bool
	CurrentWeek  bool
	FeedDegraded bool
	Filtered     bool
}

const falloutMeterSegs = 6

func handleFallout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The day bands differ by the reader's tz cookie, so the page is not one
	// shared document.
	w.Header().Add("Vary", "Cookie")
	eco := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("ecosystem")))
	if !validEcosystem(eco) {
		eco = ""
	}
	verifiedRaw := r.URL.Query().Get("verified")
	verified, verifiedErr := parseFalloutVerification(verifiedRaw)
	if verifiedErr != nil {
		// The HTML page has historically ignored unknown filter values. Keep
		// that forgiving behavior; the JSON endpoint reports a bad parameter.
		verified, verifiedRaw = falloutAny, ""
	}
	now := time.Now().In(viewerLocation(r))
	week, weekErr := parseFalloutWeek(r.URL.Query().Get("week"), now)
	if weekErr != nil {
		// Same forgiveness as the filters above: an unreadable or out-of-range
		// week shows the week in progress rather than an error page.
		week = falloutWeekOf(now, now)
	}
	data := falloutPageData{
		Nonce:       nonceFor(r),
		StyleNonce:  styleNonceFor(r),
		BuildCommit: buildCommit,
		SelectedEco: eco,
		Verified:    verifiedRaw,
		Filtered:    eco != "" || verified != falloutAny,
		HasHopper:   hopperDB.Load() != nil,
		CurrentWeek: week.Current,
		// The period the page names is a property of the URL, not of the
		// query: a degraded or hopper-less page still says which week the
		// reader is looking at. A snapshot that fell short of the window
		// narrows this in buildFalloutView.
		WindowLabel:   week.label(),
		AllSectorsURL: falloutURL(week.param(), "", verifiedRaw),
		CiteURL:       falloutURL(week.Date, "", ""),
		CurrentURL:    falloutURL("", eco, verifiedRaw),
	}
	if week.Prev != "" {
		data.OlderURL = falloutURL(week.Prev, eco, verifiedRaw)
	}
	if week.Next != "" {
		next := week.Next
		if next == falloutWeekStart(now).Format(falloutWeekLayout) {
			next = "" // the week in progress lives at the bare /fallout
		}
		data.NewerURL = falloutURL(next, eco, verifiedRaw)
	}
	var diags []queryDiag
	if data.HasHopper {
		args := week.snapshotArgs()
		snapshot, diag, err := loadFeedSnapshot(
			r.Context(), &args, logger, isHardRefresh(r),
		)
		if err != nil {
			logger.Warn("failed to load fallout rows", "error", err)
			data.FeedDegraded = true
		} else {
			diags = append(diags, diag)
			data.FeedDegraded = diag.Source == "stale"
			view := buildFalloutView(
				feedRowsFromSnapshot(snapshot), snapshot.Truncated, now, week, eco, verified,
			)
			data.Days = view.Days
			data.Sectors = view.Sectors
			data.WeeklyCount = view.WeeklyCount
			data.MeterSegs = view.MeterSegs
			data.WindowLabel = view.WindowLabel
			for i := range data.Sectors {
				chip := &data.Sectors[i]
				target := chip.Ecosystem
				if chip.Active {
					target = ""
				}
				chip.URL = falloutURL(week.param(), target, verifiedRaw)
			}
		}
	}
	if err := falloutTemplate.Execute(w, data); err != nil {
		logger.Error("template execution failed", "template", "fallout", "error", err)
		return
	}
	writeQueryDiags(w, diags)
}

// tzCookieName carries the reader's IANA zone name, written once by the small
// script at the foot of the fallout page. maxTZNameLen bounds it: the longest
// name the database actually carries is "America/Argentina/ComodRivadavia" at
// 32 bytes, so 64 leaves room without letting a cookie grow unbounded.
const (
	tzCookieName = "tz"
	maxTZNameLen = 64
)

// viewerLocation resolves the reader's time zone from the tz cookie, falling
// back to UTC whenever the cookie is missing, malformed, or names a zone this
// binary's database doesn't carry — the log renders in UTC rather than not at
// all. The value is untrusted: LoadLocation rejects traversal on its own, and
// validTZName keeps anything that isn't shaped like a zone name away from it.
func viewerLocation(r *http.Request) *time.Location {
	c, err := r.Cookie(tzCookieName)
	if err != nil || !validTZName(c.Value) {
		return time.UTC
	}
	loc, err := time.LoadLocation(c.Value)
	if err != nil {
		logger.Debug("unknown viewer time zone", "tz", c.Value, "error", err)
		return time.UTC
	}
	return loc
}

// validTZName reports whether s is shaped like an IANA zone name — "UTC",
// "America/New_York", "Etc/GMT+5". "Local" is refused by name: LoadLocation
// would honor it and hand back the server's zone, which is nobody's answer to
// the question this cookie asks.
func validTZName(s string) bool {
	if s == "" || len(s) > maxTZNameLen || s == "Local" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/', r == '_', r == '-', r == '+':
		default:
			return false
		}
	}
	return true
}

// falloutCurrentWeek reads the week in progress out of the cache, in loc's
// zone. It never builds: a miss means the week's snapshot is not warm yet, and
// the callers — the index page's badge and the reliability gauges — must not
// be the ones to pay for a week of hopper queries on the request path. The
// pre-cache loop keeps this entry warm (see feedStaticPrecacheLoop), and the
// first visitor to the log builds it if it isn't.
func falloutCurrentWeek(ctx context.Context, loc *time.Location) (cachedFeedSnapshot, falloutWeek, bool) {
	now := time.Now().In(loc)
	week := falloutWeekOf(now, now)
	if hopperDB.Load() == nil || feedCache == nil {
		return cachedFeedSnapshot{}, week, false
	}
	args := week.snapshotArgs()
	snapshot, found, err := feedCache.Get(ctx, feedCacheKey(&args))
	if err != nil || !found {
		return cachedFeedSnapshot{}, week, false
	}
	return snapshot, week, true
}

// weeklyHostileCount is the number behind the Fallout nav pill's badge on the
// index page: hostile catches in the reader's current week, counted off the
// same snapshot the log itself renders from and gated by the same bar, so the
// badge can never disagree with the page it links to. A cold or failing
// snapshot degrades to zero, which simply hides the badge.
func weeklyHostileCount(ctx context.Context, loc *time.Location) int {
	snapshot, week, ok := falloutCurrentWeek(ctx, loc)
	if !ok {
		return 0
	}
	n := 0
	for i := range snapshot.Rows {
		row := &snapshot.Rows[i]
		if row.Classification == "hostile" &&
			!row.CreatedAt.Before(week.Start) && row.CreatedAt.Before(week.End) &&
			falloutQualifies(row.Why, row.LLMGrade) {
			n++
		}
	}
	return n
}

// falloutQualifies gates a hostile catch into the log. Beyond the hostile
// verdict (which the blend may reach on ML weight alone), the log shows a
// catch only when the LLM interpretation pass ran, agreed the sample looks
// hostile (its own grade), and left a summary to display. The nav badge
// (weeklyHostileCount) applies the same bar so its count never disagrees with
// the log the reader lands on.
func falloutQualifies(why, llmGrade string) bool {
	return why != "" && llmGrade == "hostile"
}

// falloutView is the assembled log: what buildFalloutView hands the handler.
type falloutView struct {
	// WindowLabel names the period the log actually covers: "this week" when
	// the snapshot reaches the full window, "since Aug 1" when catch volume
	// outruns the snapshot's depth before the window's edge — the label must
	// never claim more history than the page shows.
	WindowLabel string
	Days        []falloutDay
	Sectors     []falloutSector
	MeterSegs   []bool
	WeeklyCount int
}

// buildFalloutView assembles the log from the week's snapshot rows: the
// window, the sector strip, and the day bands with waves first. selectedEco,
// when set, narrows the day bands to one sector; the strip always shows every
// sector with damage so the filter chips stay navigable.
//
// now carries the reader's zone, and every calendar date the page states —
// band label, band subtitle, window label, the meter's notion of the newest
// day — is read in that zone, as are the week's own boundaries. Instants (the
// window edges, row ages) are absolute and need no conversion.
//
// truncated is the snapshot's own report that it stopped short of the window
// (see feedSamplesInWindow). It is the only way to tell a quiet Monday from a
// week too big to page in, and without it the label would claim a whole week
// it cannot show.
func buildFalloutView(
	rows []feedRow, truncated bool, now time.Time, week falloutWeek,
	selectedEco string, verified falloutVerificationFilter,
) falloutView {
	loc := now.Location()
	shown := falloutRowsInWindow(rows, week, verified)
	oldest := week.End
	for i := range shown {
		if shown[i].AnalyzedAt.Before(oldest) {
			oldest = shown[i].AnalyzedAt
		}
	}

	view := falloutView{
		WeeklyCount: len(shown),
		WindowLabel: week.label(),
	}
	// A truncated snapshot reached its page cap before the far edge of the
	// window, so the log covers less than the week it names — the label says
	// exactly how much rather than overstating the period.
	if truncated && len(shown) > 0 {
		view.WindowLabel = "since " + oldest.In(loc).Format("Jan 2")
	}
	view.Sectors = falloutSectors(shown, selectedEco)

	// Heat needs distribution counts over the whole weekly pool — not the
	// filtered one — so a wave of common typosquats dilutes its own formula
	// even when the reader is looking at one sector.
	ecoCount := make(map[string]int, 16)
	formulaCount := make(map[string]int, len(shown))
	perDay := make(map[string]int, 8)
	newest := ""
	for i := range shown {
		day := shown[i].AnalyzedAt.In(loc).Format("2006-01-02")
		ecoCount[shown[i].Ecosystem]++
		formulaCount[shown[i].Formula]++
		perDay[day]++
		if day > newest {
			newest = day
		}
	}
	// The meter reads the newest day in view against the week's busiest — for
	// the week in progress that is today, and for an archive week the day it
	// finished on, so one rule covers both.
	view.MeterSegs = falloutMeter(perDay[newest], perDay)

	banded := shown
	if selectedEco != "" {
		banded = slices.DeleteFunc(slices.Clone(shown), func(r feedRow) bool {
			return r.Ecosystem != selectedEco
		})
	}
	view.Days = falloutDays(banded, ecoCount, formulaCount, len(shown), now)
	return view
}

// falloutRowsInWindow is the uncollapsed fallout set: the snapshot's rows
// narrowed to the reader's own week. The snapshot spans a padded window (see
// falloutZonePad), so this is where a shared set of rows becomes one zone's
// week — half-open, [Start, End), so a catch at midnight belongs to the day
// that is starting and to exactly one week. The HTML view groups the result
// into waves and caps singles; JSON keeps every row so a triage client
// receives every exact SHA-256/PURL pair. Both views use the same gates.
func falloutRowsInWindow(rows []feedRow, week falloutWeek, verified falloutVerificationFilter) []feedRow {
	out := make([]feedRow, 0, len(rows))
	for i := range rows {
		row := rows[i]
		if row.Classification == "hostile" &&
			!row.AnalyzedAt.Before(week.Start) && row.AnalyzedAt.Before(week.End) &&
			falloutQualifies(row.Why, row.LLMGrade) && verified.matches(row.Corroborated) {
			out = append(out, row)
		}
	}
	return out
}

// falloutMeter lights today's share of the week's busiest day across the
// masthead's segments — the static Geiger reading behind the weekly count.
func falloutMeter(today int, perDay map[string]int) []bool {
	busiest := 1
	for _, n := range perDay {
		busiest = max(busiest, n)
	}
	lit := 0
	if today > 0 {
		lit = max(1, int(math.Round(float64(falloutMeterSegs)*float64(today)/float64(busiest))))
	}
	segs := make([]bool, falloutMeterSegs)
	for i := range min(lit, falloutMeterSegs) {
		segs[i] = true
	}
	return segs
}

// falloutSectors builds the strip: every sector with damage in the week,
// count-descending. Sectors with nothing to report get no chip.
func falloutSectors(rows []feedRow, selectedEco string) []falloutSector {
	counts := make(map[string]int, 16)
	for i := range rows {
		if rows[i].Ecosystem != "" {
			counts[rows[i].Ecosystem]++
		}
	}
	sectors := make([]falloutSector, 0, len(counts))
	for eco, n := range counts {
		sectors = append(sectors, falloutSector{
			Ecosystem: eco,
			Color:     ecosystemColor(eco),
			Count:     n,
			Active:    eco == selectedEco,
		})
	}
	slices.SortFunc(sectors, func(a, b falloutSector) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), cmp.Compare(a.Ecosystem, b.Ecosystem))
	})
	return sectors
}

// falloutDays groups the shown rows into day bands, newest day first, each
// band waves-first then singles by heat. Bands break at midnight in now's
// zone, so a catch lands in the day the reader saw it happen.
func falloutDays(shown []feedRow, ecoCount, formulaCount map[string]int, poolSize int, now time.Time) []falloutDay {
	loc := now.Location()
	byDay := make(map[string][]feedRow, 8)
	var order []string
	for i := range shown {
		day := shown[i].AnalyzedAt.In(loc).Format("2006-01-02")
		if _, seen := byDay[day]; !seen {
			order = append(order, day)
		}
		byDay[day] = append(byDay[day], shown[i])
	}
	slices.SortFunc(order, func(a, b string) int { return cmp.Compare(b, a) })

	days := make([]falloutDay, 0, len(order))
	for _, day := range order {
		rows := byDay[day]
		waves, singles := splitWaves(rows, ecoCount, formulaCount, poolSize)
		bandRows := make([]falloutRow, 0, len(waves)+len(singles))
		bandRows = append(bandRows, waves...)
		bandRows = append(bandRows, singles...)
		if len(bandRows) == 0 {
			continue
		}
		decorateFalloutRows(bandRows, now)
		date, err := time.ParseInLocation("2006-01-02", day, loc)
		if err != nil {
			continue // impossible: the key came from Format with this layout
		}
		days = append(days, falloutDay{
			Label: falloutDayLabel(date, now),
			Sub: fmt.Sprintf("%s · %s · %d %s · %d %s",
				date.Format("Mon Jan 2"),
				plural(len(rows), "catch", "catches"),
				len(waves), pluralWord(len(waves), "wave", "waves"),
				len(singles), pluralWord(len(singles), "single", "singles")),
			ID:    "day-" + day,
			Date:  date.Format("Mon 2 Jan"),
			Count: len(rows),
			Rows:  bandRows,
		})
	}
	return days
}

// splitWaves partitions one day's rows into collapsed wave rows and heat-
// sorted singles. The wave key is exact — ecosystem, file type, malecule
// formula — because a campaign republishing one kit shares all three; the
// upgrade path, if real campaigns splinter over one-trait variations, is a
// trait-set distance on the same key, not fuzzier string matching here.
func splitWaves(rows []feedRow, ecoCount, formulaCount map[string]int, poolSize int) (waves, singles []falloutRow) {
	groups := make(map[string][]feedRow, len(rows))
	for i := range rows {
		key := rows[i].Ecosystem + "\x00" + rows[i].FileType + "\x00" + rows[i].Formula
		if rows[i].Formula == "" {
			// No formula means nothing to campaign-match on; keep it single.
			key = "single\x00" + rows[i].SHA256
		}
		groups[key] = append(groups[key], rows[i])
	}

	heat := func(r *feedRow) float64 { return falloutHeat(r, ecoCount, formulaCount, poolSize) }
	perSector := make(map[string]int, 8)
	for _, members := range groups {
		if len(members) >= waveMinSize {
			ex := waveExemplar(members, heat)
			waves = append(waves, falloutRow{feedRow: ex, WaveSize: len(members), Siblings: len(members) - 1})
			continue
		}
		for i := range members {
			singles = append(singles, falloutRow{feedRow: members[i]})
		}
	}
	slices.SortFunc(waves, func(a, b falloutRow) int { return cmp.Compare(b.WaveSize, a.WaveSize) })
	slices.SortFunc(singles, func(a, b falloutRow) int {
		return cmp.Or(
			cmp.Compare(heat(&b.feedRow), heat(&a.feedRow)),
			b.AnalyzedAt.Compare(a.AnalyzedAt),
		)
	})
	// The per-sector quota trims the heat-sorted tail, so what survives is
	// each sector's most interesting; rare sectors always fit.
	kept := singles[:0]
	for i := range singles {
		if perSector[singles[i].Ecosystem] >= falloutSinglesPerSector {
			continue
		}
		perSector[singles[i].Ecosystem]++
		kept = append(kept, singles[i])
	}
	return waves, kept
}

// hexWall reports whether a display name is dominated by a long hex run —
// a sha-derived filename that would render as an unreadable wall.
func hexWall(name string) bool {
	run := 0
	for _, c := range name {
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			run++
			if run >= 40 {
				return true
			}
			continue
		}
		run = 0
	}
	return false
}

// falloutHeat is a row's interestingness: ecosystem surprisal plus formula
// novelty (each -log2 of the row's share of the weekly pool), the blast-
// radius term, and a point for an uncorroborated first-seen-here catch.
func falloutHeat(row *feedRow, ecoCount, formulaCount map[string]int, poolSize int) float64 {
	if poolSize == 0 {
		return 0
	}
	total := float64(poolSize)
	score := math.Log2(total / float64(max(ecoCount[row.Ecosystem], 1)))
	score += math.Log2(total / float64(max(formulaCount[row.Formula], 1)))
	score += math.Log10(1 + float64(row.Downloads))
	if !row.Corroborated {
		score++
	}
	return score
}

// waveExemplar picks the member that titles the wave: among members with a
// real identity (a marketplace title or package attribution — a bare
// sha-named file makes an unreadable title), the top-downloaded, heat as the
// tiebreak. Only a wave of wholly anonymous members falls back to the lot.
func waveExemplar(members []feedRow, heat func(*feedRow) float64) feedRow {
	if len(members) == 0 {
		return feedRow{}
	}
	pool := make([]int, 0, len(members))
	for i := range members {
		if members[i].RegistryTitle != "" || members[i].Package != "" {
			pool = append(pool, i)
		}
	}
	if len(pool) == 0 {
		for i := range members {
			pool = append(pool, i)
		}
	}
	best := pool[0]
	for _, i := range pool[1:] {
		switch {
		case members[i].Downloads > members[best].Downloads:
			best = i
		case members[i].Downloads == members[best].Downloads && heat(&members[i]) > heat(&members[best]):
			best = i
		default:
			// members[best] stands.
		}
	}
	return members[best]
}

// normalizeFalloutIdentity rescues rows whose leading identity is a hash:
// threat-feed imports (MalwareBazaar and kin) often carry the sha as the
// package name while the real filename sits behind it. Prefer the readable
// filename; a wholly anonymous row shortens to its sha prefix — the row
// still links to the full record.
func normalizeFalloutIdentity(r *feedRow) {
	if !hexWall(r.Title()) {
		return
	}
	r.RegistryTitle, r.Package, r.Version = "", "", ""
	if r.Filename == "" || hexWall(r.Filename) {
		r.Filename = shortSHA(r.SHA256) + "…"
	}
}

// decorateFalloutRows applies the presentation layer to a finished day band:
// identity cleanup, skeletal thumbnails, decay classes, trimmed chips, and
// the day's ribbons.
func decorateFalloutRows(rows []falloutRow, now time.Time) {
	for i := range rows {
		normalizeFalloutIdentity(&rows[i].feedRow)
		rows[i].HeatClass = decayClass(now.Sub(rows[i].AnalyzedAt))
		if len(rows[i].TopTraits) > 2 {
			rows[i].TopTraits = rows[i].TopTraits[:2]
		}
	}
	// Ribbons go to singles only (waves already stand out) and at most one
	// of each per day — scarcity is what makes them read as awards.
	blast, first := -1, -1
	var blastDownloads int64
	for i := range rows {
		if rows[i].IsWave() {
			continue
		}
		if rows[i].Downloads > blastDownloads {
			blast, blastDownloads = i, rows[i].Downloads
		}
		if !rows[i].Corroborated && first == -1 {
			first = i // rows are heat-sorted, so the first hit is the hottest
		}
	}
	if blast >= 0 {
		rows[blast].Ribbon = "biggest blast radius"
		rows[blast].RibbonTip = "most installs exposed of any catch this day"
	}
	if first >= 0 && first != blast {
		rows[first].Ribbon = "first seen anywhere"
		rows[first].RibbonTip = "no external threat feed has this sample"
	}
}

// decayClass buckets a particle's age for the toxic halo: hot under six
// hours, warm under a day, cooled after.
func decayClass(age time.Duration) string {
	switch {
	case age < 6*time.Hour:
		return "heat-2"
	case age < 24*time.Hour:
		return "heat-1"
	default:
		return "heat-0"
	}
}

// falloutDayLabel names a day band relative to now. Both carry the reader's
// zone, so the comparison is between wall-clock dates the reader recognizes.
func falloutDayLabel(day, now time.Time) string {
	switch day.Format("2006-01-02") {
	case now.Format("2006-01-02"):
		return "TODAY"
	case now.AddDate(0, 0, -1).Format("2006-01-02"):
		return "YESTERDAY"
	default:
		return strings.ToUpper(day.Format("Monday"))
	}
}

func plural(n int, one, many string) string {
	return fmt.Sprintf("%d %s", n, pluralWord(n, one, many))
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// ---------------------------------------------------------------------------
// Skeletal-formula thumbnails
//
// A malecule formula like "O3(CCa2)H2" reads: one composite objective built
// from a c2 atom and two credential-access atoms, plus two micro-behavior
// atoms. The thumbnail draws it in bond-line style: the parenthesized group
// is a ring with its members at the vertices, standalone elements are a
// zigzag chain, and severity-bearing atoms carry their element letter in the
// litmus palette while the rest stay as bare vertices — implicit, like carbon
// in a real skeletal formula.

// molGroup is one parsed unit of a formula: a parenthesized composite (Lead
// carries its identity element — O, H, Md, K, Th) or a run of standalone
// atoms (Lead empty). Members are expanded by their counts.
type molGroup struct {
	Lead    string
	Members []string
}

// parseFormulaGroups splits a formula into its groups. The parser is
// deliberately permissive: element = capital + optional lowercase, optional
// count, parentheses open a composite. Anything unexpected just ends the
// parse — a half-drawn thumbnail beats a 500.
func parseFormulaGroups(formula string) []molGroup {
	formula = desubscriptFormula(formula)
	var groups []molGroup
	inRing := false
	appendAtom := func(sym string, count int) {
		if len(groups) == 0 || (groups[len(groups)-1].Lead != "" && !inRing) {
			groups = append(groups, molGroup{})
		}
		g := &groups[len(groups)-1]
		// Cap the expansion: a Cm₆₅ subscript would otherwise mint 65
		// members nobody can draw.
		for range min(count, molRingMax) {
			g.Members = append(g.Members, sym)
		}
	}
	for i := 0; i < len(formula); {
		c := formula[i]
		switch {
		case c == '(':
			inRing = true
			i++
		case c == ')':
			inRing = false
			i++
		case c >= 'A' && c <= 'Z':
			j := i + 1
			for j < len(formula) && formula[j] >= 'a' && formula[j] <= 'z' {
				j++
			}
			sym := formula[i:j]
			count := 0
			for j < len(formula) && formula[j] >= '0' && formula[j] <= '9' {
				count = count*10 + int(formula[j]-'0')
				j++
			}
			// A lead element immediately before an open paren names the
			// composite; it contributes no member of its own.
			if j < len(formula) && formula[j] == '(' {
				groups = append(groups, molGroup{Lead: sym})
				i = j
				continue
			}
			appendAtom(sym, max(count, 1))
			i = j
		default:
			return groups
		}
	}
	return groups
}

// molRingMax caps how many members one subscript may expand to: a Cm₆₅ would
// otherwise mint 65 tiles nobody can read.
const molRingMax = 5

// tierTiles is one tier of a formula rendered as tiles: the tier symbol (O, H,
// Md, K, Th), its name, and the atoms it holds with their subscripts.
type tierTiles struct {
	Tier  string
	Name  string
	Atoms []tileAtom
}

// tileAtom is one element tile: its symbol, the category it stands for, and
// how many subcategories the formula counted under it.
type tileAtom struct {
	Symbol string
	Name   string
	Count  int
}

// tierName spells out a tier symbol for a title attribute.
func tierName(tier string) string {
	switch tier {
	case "O":
		return "objectives"
	case "H":
		return "behaviours"
	case "Md":
		return "metadata"
	case "K":
		return "well-known"
	case "Th":
		return "third-party"
	default:
		return ""
	}
}

// formulaTiers turns a formula like "O₄(AlEu₂CaDy)H₅(CmCrDb₅Os₄Po)Md(Pa)"
// into tile rows, one per tier, preserving the formula's order. Standalone
// atoms outside any parenthesis become a row with no tier symbol. Counts are
// read from the subscripts; parseFormulaGroups expands them into repeated
// members, so they are folded back here.
func formulaTiers(formula string) []tierTiles {
	var out []tierTiles
	for _, g := range parseFormulaGroups(formula) {
		t := tierTiles{Tier: g.Lead, Name: tierName(g.Lead)}
		idx := make(map[string]int, len(g.Members))
		for _, sym := range g.Members {
			if i, ok := idx[sym]; ok {
				t.Atoms[i].Count++
				continue
			}
			name := sym
			if el, ok := elementBySymbol(sym); ok {
				name = el
			}
			idx[sym] = len(t.Atoms)
			t.Atoms = append(t.Atoms, tileAtom{Symbol: sym, Name: name, Count: 1})
		}
		if len(t.Atoms) > 0 {
			out = append(out, t)
		}
	}
	return out
}

// elementBySymbol maps an element symbol back to the trait category it stands
// for, for tile titles. Symbols the table does not know keep their letters.
func elementBySymbol(sym string) (string, bool) {
	for category, el := range categoryElements {
		if el.Symbol == sym {
			return category, true
		}
	}
	return "", false
}
