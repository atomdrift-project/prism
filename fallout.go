package main

// The Fallout log is the damage feed at /fallout: every hostile catch of the
// rolling week, grouped into day bands, campaigns collapsed into waves. It is
// a pure presentation of the cached hostile snapshot — the same rows the
// frontpage's hostile filter serves — so rendering it costs no new queries.
//
// Within a day, waves lead (largest first) and singles follow by heat. A wave
// is an exact-key campaign: same UTC day, ecosystem, file type, and malecule
// formula, three members or more. Its row is titled by its best exemplar —
// the top-downloaded member when install counts are known, the hottest
// otherwise — because 23 typosquats of one drainer kit are one event, not 23.

import (
	"context"
	"fmt"
	"hash/fnv"
	"html/template"
	"math"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	// falloutWindow is the log's rolling window. A calendar week would empty
	// the page every Monday morning; rolling keeps it continuously alive.
	falloutWindow = 7 * 24 * time.Hour
	// waveMinSize is the smallest campaign worth collapsing: below three
	// members, showing the rows individually reads better than a wave row.
	waveMinSize = 3
	// falloutSinglesPerSector caps how many unwaved rows one ecosystem may
	// place in a single day band — the backstop that keeps a pathological
	// day of distinct npm catches from drowning the rare sectors the log
	// exists to surface. Waves are exempt: they already collapse volume.
	falloutSinglesPerSector = 3
)

// falloutRow is one line of the log: a single catch, or a wave of them
// represented by its exemplar. The embedded feedRow is the exemplar itself,
// so identity, rationale, and chips render with the ledger's grammar.
//
//nolint:govet // fieldalignment: embedded-first reads better on a struct built a page at a time
type falloutRow struct {
	feedRow

	// MolSVG is the row's skeletal-formula thumbnail, rendered server-side
	// from the exemplar's malecule formula.
	MolSVG template.HTML
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
	Rows  []falloutRow
}

// falloutSector is one chip in the ecosystem strip. Quiet sectors (watched,
// nothing hostile this week) render dimmed with their last-catch date — the
// coverage evidence a bare omission would hide.
type falloutSector struct {
	Ecosystem string
	Color     string
	LastCatch string // last catch date for quiet sectors; empty when unknown
	Count     int
	Active    bool
	Quiet     bool
}

type falloutPageData struct {
	Nonce       string
	StyleNonce  string
	BuildCommit string
	SelectedEco string
	// WindowLabel and QuietOverflow mirror falloutView; MeterSegs are the
	// peak-meter segments (lit = today's share of the window's busiest day).
	WindowLabel   string
	Sectors       []falloutSector
	Days          []falloutDay
	MeterSegs     []bool
	QuietOverflow int
	WeeklyCount   int
	HasHopper     bool
	FeedDegraded  bool
	Filtered      bool
}

const falloutMeterSegs = 6

func handleFallout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	eco := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("ecosystem")))
	if !validEcosystem(eco) {
		eco = ""
	}
	data := falloutPageData{
		Nonce:       nonceFor(r),
		StyleNonce:  styleNonceFor(r),
		BuildCommit: buildCommit,
		SelectedEco: eco,
		Filtered:    eco != "",
		HasHopper:   hopperDB.Load() != nil,
	}
	var diags []queryDiag
	if data.HasHopper {
		snapshot, diag, err := loadFeedSnapshot(
			r.Context(), feedQueryArgs{criticality: "hostile"}, logger, isHardRefresh(r),
		)
		if err != nil {
			logger.Warn("failed to load fallout rows", "error", err)
			data.FeedDegraded = true
		} else {
			diags = append(diags, diag)
			data.FeedDegraded = diag.Source == "stale"
			view := buildFalloutView(feedRowsFromSnapshot(snapshot), snapshot.Ecosystems, time.Now().UTC(), eco)
			data.Days = view.Days
			data.Sectors = view.Sectors
			data.WeeklyCount = view.WeeklyCount
			data.MeterSegs = view.MeterSegs
			data.WindowLabel = view.WindowLabel
			data.QuietOverflow = view.QuietOverflow
		}
	}
	if err := falloutTemplate.Execute(w, data); err != nil {
		logger.Error("template execution failed", "template", "fallout", "error", err)
		return
	}
	writeQueryDiags(w, diags)
}

// weeklyHostileCount is the number behind the Fallout nav pill's badge on the
// index page: hostile catches inside the log's window, read from the same
// cached hostile snapshot the log itself renders from. A cold or failing
// snapshot degrades to zero, which simply hides the badge.
func weeklyHostileCount(ctx context.Context) int {
	if hopperDB.Load() == nil {
		return 0
	}
	snapshot, _, err := loadFeedSnapshot(ctx, feedQueryArgs{criticality: "hostile"}, logger, false)
	if err != nil {
		return 0
	}
	cutoff := time.Now().UTC().Add(-falloutWindow)
	n := 0
	for i := range snapshot.Rows {
		if snapshot.Rows[i].Classification == "hostile" && snapshot.Rows[i].CreatedAt.After(cutoff) {
			n++
		}
	}
	return n
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
	// QuietOverflow counts the watched-but-clean sectors beyond the strip's
	// cap, summarized in one trailing chip instead of a wall of dim ones.
	QuietOverflow int
	WeeklyCount   int
}

// buildFalloutView assembles the log from the hostile snapshot rows: the
// weekly window, the sector strip (with quiet sectors from the watched list),
// and the day bands with waves first. selectedEco, when set, narrows the day
// bands to one sector; the strip always shows every sector so the filter
// chips stay navigable.
func buildFalloutView(rows []feedRow, watched []string, now time.Time, selectedEco string) falloutView {
	cutoff := now.Add(-falloutWindow)
	var week []feedRow
	oldest := now
	for i := range rows {
		if rows[i].Classification == "hostile" && rows[i].AnalyzedAt.After(cutoff) {
			week = append(week, rows[i])
			if rows[i].AnalyzedAt.Before(oldest) {
				oldest = rows[i].AnalyzedAt
			}
		}
	}

	view := falloutView{
		WeeklyCount: len(week),
		WindowLabel: "this week",
	}
	// When a full snapshot lands entirely inside the window, the snapshot
	// ran out of depth (feedLimit rows) before the window ran out of days —
	// the log covers less than a week, and the label says exactly how much.
	if len(week) == len(rows) && len(rows) >= feedLimit {
		view.WindowLabel = "since " + oldest.Format("Jan 2")
	}
	view.Sectors, view.QuietOverflow = falloutSectors(week, rows, watched, selectedEco)

	// Heat needs distribution counts over the whole weekly pool — not the
	// filtered one — so a wave of common typosquats dilutes its own formula
	// even when the reader is looking at one sector.
	ecoCount := make(map[string]int, 16)
	formulaCount := make(map[string]int, len(week))
	perDay := make(map[string]int, 8)
	for i := range week {
		ecoCount[week[i].Ecosystem]++
		formulaCount[week[i].Formula]++
		perDay[week[i].AnalyzedAt.Format("2006-01-02")]++
	}
	view.MeterSegs = falloutMeter(perDay[now.Format("2006-01-02")], perDay)

	shown := week
	if selectedEco != "" {
		shown = slices.DeleteFunc(slices.Clone(week), func(r feedRow) bool {
			return r.Ecosystem != selectedEco
		})
	}
	view.Days = falloutDays(shown, ecoCount, formulaCount, len(week), now)
	return view
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

// falloutQuietMax caps the strip's dimmed quiet chips. The watched list runs
// to dozens of sectors; a wall of dim chips reads as noise, so the strip
// shows the most recently active few and folds the rest into one summary.
const falloutQuietMax = 6

// falloutSectors builds the strip: every sector with damage in the window
// (count-descending), then the most recently active watched-but-clean sectors
// as dimmed quiet chips, with the overflow count folded into the second
// return value.
func falloutSectors(week, all []feedRow, watched []string, selectedEco string) (sectors []falloutSector, quietOverflow int) {
	counts := make(map[string]int, 16)
	for i := range week {
		if week[i].Ecosystem != "" {
			counts[week[i].Ecosystem]++
		}
	}
	sectors = make([]falloutSector, 0, len(counts))
	for eco, n := range counts {
		sectors = append(sectors, falloutSector{
			Ecosystem: eco,
			Color:     ecosystemColor(eco),
			Count:     n,
			Active:    eco == selectedEco,
		})
	}
	sort.Slice(sectors, func(i, j int) bool {
		if sectors[i].Count != sectors[j].Count {
			return sectors[i].Count > sectors[j].Count
		}
		return sectors[i].Ecosystem < sectors[j].Ecosystem
	})

	// Quiet sectors: watched (on the recency-gated dropdown list) but with
	// nothing hostile in the window. The last catch may predate the window
	// while still living in the snapshot; sectors the snapshot has forgotten
	// entirely sort last and usually fall into the overflow summary.
	lastCatch := make(map[string]time.Time, len(watched))
	for i := range all {
		if all[i].Classification != "hostile" || all[i].Ecosystem == "" {
			continue
		}
		if all[i].AnalyzedAt.After(lastCatch[all[i].Ecosystem]) {
			lastCatch[all[i].Ecosystem] = all[i].AnalyzedAt
		}
	}
	var quiet []falloutSector
	for _, eco := range watched {
		if eco == "" || counts[eco] > 0 {
			continue
		}
		q := falloutSector{
			Ecosystem: eco,
			Color:     ecosystemColor(eco),
			Quiet:     true,
			Active:    eco == selectedEco,
		}
		if last, ok := lastCatch[eco]; ok {
			q.LastCatch = last.Format("Jan 2")
		}
		quiet = append(quiet, q)
	}
	sort.SliceStable(quiet, func(i, j int) bool {
		return lastCatch[quiet[i].Ecosystem].After(lastCatch[quiet[j].Ecosystem])
	})
	if len(quiet) > falloutQuietMax {
		// An actively-filtered quiet sector must keep its chip so the strip
		// still shows where the reader stands.
		kept := quiet[:falloutQuietMax:falloutQuietMax]
		for _, q := range quiet[falloutQuietMax:] {
			if q.Active {
				kept = append(kept, q)
				continue
			}
			quietOverflow++
		}
		quiet = kept
	}
	return append(sectors, quiet...), quietOverflow
}

// falloutDays groups the shown rows into day bands, newest day first, each
// band waves-first then singles by heat.
func falloutDays(shown []feedRow, ecoCount, formulaCount map[string]int, poolSize int, now time.Time) []falloutDay {
	byDay := make(map[string][]feedRow, 8)
	var order []string
	for i := range shown {
		day := shown[i].AnalyzedAt.Format("2006-01-02")
		if _, seen := byDay[day]; !seen {
			order = append(order, day)
		}
		byDay[day] = append(byDay[day], shown[i])
	}
	sort.Sort(sort.Reverse(sort.StringSlice(order)))

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
		date, err := time.Parse("2006-01-02", day)
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
			Rows: bandRows,
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
			// A wave of wholly anonymous members titles as a sha-wall —
			// whichever identity field carries it. Shorten to the sha
			// prefix; the row still links to the full record.
			if hexWall(ex.Title()) {
				ex.RegistryTitle, ex.Package, ex.Version = "", "", ""
				ex.Filename = shortSHA(ex.SHA256) + "…"
			}
			waves = append(waves, falloutRow{feedRow: ex, WaveSize: len(members), Siblings: len(members) - 1})
			continue
		}
		for i := range members {
			singles = append(singles, falloutRow{feedRow: members[i]})
		}
	}
	sort.Slice(waves, func(i, j int) bool { return waves[i].WaveSize > waves[j].WaveSize })
	sort.Slice(singles, func(i, j int) bool {
		hi, hj := heat(&singles[i].feedRow), heat(&singles[j].feedRow)
		if hi != hj {
			return hi > hj
		}
		return singles[i].AnalyzedAt.After(singles[j].AnalyzedAt)
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

// decorateFalloutRows applies the presentation layer to a finished day band:
// skeletal thumbnails, decay classes, trimmed chips, and the day's ribbons.
func decorateFalloutRows(rows []falloutRow, now time.Time) {
	for i := range rows {
		rows[i].MolSVG = skeletalSVG(rows[i].Formula, rows[i].TopTraits)
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

// falloutDayLabel names a day band relative to now (both UTC).
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

// molGroupPriority ranks which composite deserves the ring: objectives carry
// the hostile structure, micro-behaviors second; metadata and provenance
// groups only draw when nothing better exists.
func molGroupPriority(lead string) int {
	switch lead {
	case "O":
		return 0
	case "H":
		return 1
	case "K":
		return 2
	case "Th":
		return 3
	case "Md":
		return 4
	default:
		return 5
	}
}

// molMaxAtoms bounds the thumbnail: a ring of up to five plus a chain of up
// to three keeps the drawing legible at 38px; deeper formulas are truncated,
// which is fine — the thumbnail is a fingerprint, not a census.
const (
	molRingMax  = 5
	molChainMax = 3
)

// traitSeverityBySymbol maps element symbols to the highest criticality among
// the row's top traits whose category path touches that element — the only
// per-atom severity signal the feed projection carries.
func traitSeverityBySymbol(traits []feedTrait) map[string]string {
	rank := map[string]int{"hostile": 2, "suspicious": 1}
	out := make(map[string]string, 4)
	for _, t := range traits {
		if rank[t.Crit] == 0 {
			continue
		}
		for _, seg := range strings.FieldsFunc(t.Full, func(r rune) bool { return r == '/' || r == '.' }) {
			el, ok := categoryToElement(seg)
			if !ok {
				continue
			}
			if rank[t.Crit] > rank[out[el.Symbol]] {
				out[el.Symbol] = t.Crit
			}
		}
	}
	return out
}

// skeletalSVG renders the bond-line thumbnail for a formula. The ring is the
// highest-priority composite (objectives first — that's where the hostile
// structure lives); the chain is the runner-up group. Returns an empty
// document when the formula parses to nothing — the template renders the
// frame either way so rows stay aligned.
func skeletalSVG(formula string, traits []feedTrait) template.HTML {
	groups := parseFormulaGroups(formula)
	sort.SliceStable(groups, func(i, j int) bool {
		return molGroupPriority(groups[i].Lead) < molGroupPriority(groups[j].Lead)
	})
	var ring, chain []string
	if len(groups) > 0 {
		ring = groups[0].Members[:min(len(groups[0].Members), molRingMax)]
	}
	if len(groups) > 1 {
		chain = groups[1].Members[:min(len(groups[1].Members), molChainMax)]
	}
	severity := traitSeverityBySymbol(traits)

	var svg strings.Builder
	svg.WriteString(`<svg width="38" height="32" viewBox="0 0 38 32" aria-hidden="true">`)

	// Deterministic rotation: the same formula always draws the same shape,
	// different formulas start their rings at different angles.
	h := fnv.New32a()
	_, _ = h.Write([]byte(formula)) // fnv's Write never fails
	rot := float64(h.Sum32()%64) / 64 * 2 * math.Pi

	type pt struct{ x, y float64 }
	var ringPts []pt
	if len(ring) > 0 {
		cx, cy, radius := 14.0, 16.0, 9.0
		if len(chain) == 0 {
			cx = 19
		}
		if len(ring) == 1 {
			ringPts = []pt{{cx, cy}}
		} else {
			for i := range ring {
				a := rot + 2*math.Pi*float64(i)/float64(len(ring))
				ringPts = append(ringPts, pt{cx + radius*math.Sin(a), cy - radius*math.Cos(a)})
			}
		}
		for i := range ringPts {
			next := ringPts[(i+1)%len(ringPts)]
			if len(ringPts) > 1 {
				line(&svg, ringPts[i].x, ringPts[i].y, next.x, next.y)
			}
		}
	}

	// The chain zigzags rightward, bonded to the ring's first vertex when a
	// ring exists.
	var chainPts []pt
	if len(chain) > 0 {
		startX, startY := 8.0, 20.0
		if len(ringPts) > 0 {
			startX, startY = ringPts[0].x, ringPts[0].y
		}
		x, y := startX, startY
		up := true
		for range chain {
			nx := x + 9
			ny := y - 9
			if !up {
				ny = y + 9
			}
			ny = math.Min(math.Max(ny, 6), 27)
			nx = math.Min(nx, 35)
			chainPts = append(chainPts, pt{nx, ny})
			line(&svg, x, y, nx, ny)
			x, y, up = nx, ny, !up
		}
	}

	label := func(p pt, sym string) {
		crit, ok := severity[sym]
		if !ok {
			return // neutral atoms stay bare vertices
		}
		class := "e-s"
		if crit == "hostile" {
			class = "e-h"
		}
		//nolint:gosec // sym is HTML-escaped; class and coordinates are program values
		fmt.Fprintf(&svg, `<text class="%s" x="%.0f" y="%.0f">%s</text>`,
			class, p.x, p.y+3, template.HTMLEscapeString(sym))
	}
	for i, p := range ringPts {
		label(p, ring[i])
	}
	for i, p := range chainPts {
		label(p, chain[i])
	}
	svg.WriteString(`</svg>`)
	//nolint:gosec // built from numeric coordinates, fixed markup, and HTML-escaped element symbols only
	return template.HTML(svg.String())
}

func line(b *strings.Builder, x1, y1, x2, y2 float64) {
	fmt.Fprintf(b, `<line class="bond" x1="%.0f" y1="%.0f" x2="%.0f" y2="%.0f"/>`, x1, y1, x2, y2)
}
