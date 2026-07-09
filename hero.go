package main

// The Hot Particle is the feed's daily featured catch — in fallout terms, the
// discrete, intensely radioactive fragment worth pointing at. It fronts the
// frontpage views with the full rationale and identity of the most interesting
// hostile verdict of the last day.
//
// Selection is deterministic from the cached hostile snapshot: eligibility
// gates first (the hero is the shop window, so it must carry a package
// attribution, a rationale, and a confident hostile verdict), then a simple
// additive "heat" score — ecosystem surprisal plus trait-composition novelty
// plus a point for an uncorroborated (first-seen-here) catch. Install-count
// reach joins the sum once marketplace metadata lands in hopper.

import (
	"context"
	"log/slog"
	"math"
	"os"
	"strings"
	"time"
)

const (
	// heroWindow is how far back the Hot Particle looks for candidates;
	// heroWindowWide is the fallback for a quiet day — the window widens
	// rather than the gates lowering.
	heroWindow     = 24 * time.Hour
	heroWindowWide = 72 * time.Hour
	// heroMinConf is the eligibility floor for the blended verdict
	// confidence percentage: a borderline verdict, however interesting,
	// never fronts the page.
	heroMinConf = 85
)

// heroPinSHA, when set, features the named sample regardless of score — the
// hand-curation lever for days when an operator wants a specific catch on top.
var heroPinSHA = strings.ToLower(strings.TrimSpace(os.Getenv("PRISM_HERO_SHA256")))

// feedHero is the Hot Particle card rendered above the frontpage feed.
//
//nolint:govet // fieldalignment conflicts with embeddedstructfieldcheck here; embedded-first reads better on a struct allocated once per render
type feedHero struct {
	feedRow

	// Reasons is the eyebrow tooltip: the human-readable expansion of the
	// selection score ("rare catch for chrome · first seen here").
	Reasons string
}

// loadFeedHero picks the Hot Particle for a frontpage render. The candidate
// pool is the cached hostile snapshot — the same view the default page serves —
// so on the default view the hero reuses rows already in hand, and on the
// other frontpage variants it costs one warm cache read. A missing snapshot
// degrades to no hero, never to an error page.
func loadFeedHero(ctx context.Context, selectedCrit string, rows []feedRow, reqLogger *slog.Logger) *feedHero {
	if selectedCrit != "hostile" {
		snapshot, _, err := loadFeedSnapshot(ctx, feedQueryArgs{criticality: "hostile"}, reqLogger, false)
		if err != nil {
			reqLogger.Debug("hot particle: hostile snapshot unavailable", "error", err)
			return nil
		}
		rows = feedRowsFromSnapshot(snapshot)
	}
	return chooseHero(rows, time.Now(), heroPinSHA)
}

// chooseHero selects the Hot Particle from the hostile feed rows: the pinned
// sample when the operator named one, otherwise the highest-scoring eligible
// row of the last heroWindow (widened to heroWindowWide on a quiet day). Nil
// when nothing qualifies — the template drops the section.
func chooseHero(rows []feedRow, now time.Time, pin string) *feedHero {
	if pin != "" {
		for i := range rows {
			if rows[i].SHA256 == pin {
				return &feedHero{feedRow: rows[i], Reasons: "operator pick of the day"}
			}
		}
	}
	// Distribution counts feed the surprisal terms. They span every row in
	// the pool — not just eligible ones — so a wave of common typosquats
	// dilutes its own ecosystem and formula even when most of the wave
	// fails an eligibility gate.
	ecoCount := make(map[string]int, 16)
	formulaCount := make(map[string]int, len(rows))
	for i := range rows {
		ecoCount[rows[i].Ecosystem]++
		formulaCount[rows[i].Formula]++
	}

	best := bestHero(rows, ecoCount, formulaCount, now.Add(-heroWindow))
	if best == nil {
		best = bestHero(rows, ecoCount, formulaCount, now.Add(-heroWindowWide))
	}
	if best == nil {
		return nil
	}
	return &feedHero{feedRow: *best, Reasons: heroReasons(best, ecoCount, formulaCount, len(rows))}
}

// heroEligible gates hero candidacy: a confident hostile verdict, with the
// rationale and package attribution the card renders, analyzed after cutoff.
func heroEligible(row *feedRow, cutoff time.Time) bool {
	return row.Classification == "hostile" &&
		row.Conf >= heroMinConf &&
		row.Why != "" &&
		row.Package != "" &&
		row.AnalyzedAt.After(cutoff)
}

// heroScore is one eligible row's "heat": ecosystem surprisal plus trait-
// composition novelty (each -log2 of the row's share of the pool), plus the
// blast-radius term (log10 of the marketplace install count, when known),
// plus a point when no external feed has it.
func heroScore(row *feedRow, ecoCount, formulaCount map[string]int, total float64) float64 {
	score := math.Log2(total / float64(ecoCount[row.Ecosystem]))
	score += math.Log2(total / float64(formulaCount[row.Formula]))
	score += math.Log10(1 + float64(row.Downloads))
	if !row.Corroborated {
		score++
	}
	return score
}

// bestHero returns the highest-scoring eligible row analyzed after cutoff,
// tie-broken by confidence and then recency. Nil when none qualifies.
func bestHero(rows []feedRow, ecoCount, formulaCount map[string]int, cutoff time.Time) *feedRow {
	total := float64(len(rows))
	var best *feedRow
	var bestScore float64
	for i := range rows {
		row := &rows[i]
		if !heroEligible(row, cutoff) {
			continue
		}
		score := heroScore(row, ecoCount, formulaCount, total)
		if best != nil {
			if score < bestScore {
				continue
			}
			if score == bestScore && (row.Conf < best.Conf ||
				row.Conf == best.Conf && !row.AnalyzedAt.After(best.AnalyzedAt)) {
				continue
			}
		}
		best, bestScore = row, score
	}
	return best
}

// heroReasons renders the selection score's components for the eyebrow
// tooltip — the same transparency the trait evidence gets, applied to the
// selection itself.
func heroReasons(row *feedRow, ecoCount, formulaCount map[string]int, total int) string {
	var parts []string
	if row.Downloads >= 10_000 {
		parts = append(parts, formatCount(row.Downloads)+" installs exposed")
	}
	if row.Ecosystem != "" && ecoCount[row.Ecosystem]*20 <= total {
		parts = append(parts, "rare catch for "+row.Ecosystem)
	}
	if row.Formula != "" && formulaCount[row.Formula] == 1 {
		parts = append(parts, "novel trait composition")
	}
	if !row.Corroborated {
		parts = append(parts, "first seen here")
	}
	if len(parts) == 0 {
		return "today's most confident hostile verdict"
	}
	return strings.Join(parts, " · ")
}
