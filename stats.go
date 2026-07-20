package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// indexStats is a point-in-time snapshot of the analyzed-corpus size and the
// recent ingestion rate, powering the live "samples analyzed" counter on the
// feed masthead. The rate is top-level only (parent = ”) on purpose: exploded
// archive members are bulk-inserted already-analyzed, so counting them as
// throughput inflates the rate ~80x (see hopper's AnalysisRatesSince). The
// client anchors on Total and extrapolates with RatePerMin between polls, so a
// coarse refresh cadence is invisible.
type indexStats struct {
	GeneratedAt time.Time // when this snapshot was computed (server clock, UTC)
	Total       int64     // samples with an analysis result (hopper CountAnalyzed)
	RatePerMin  float64   // top-level samples analyzed per minute, trailing statsWindow average
	WindowSecs  int       // the averaging window, in seconds
}

const (
	// statsWindow is the trailing window for the ingestion-rate estimate. A
	// 15-minute average smooths the bursty per-archive analysis cadence into a
	// steady rate the client can extrapolate the counter with between polls.
	statsWindow = 15 * time.Minute
	// statsCacheTTL bounds how often the corpus-size + rate queries run. Every
	// viewer polls /_/stats, but FetchTTL singleflights concurrent callers onto
	// one query pair, so all traffic collapses to at most one refresh per window
	// regardless of concurrency — the discipline feedCache already uses. The
	// only full-table scan (CountAnalyzed) therefore runs at most once a minute,
	// and only while someone is watching; the client extrapolates the in-between
	// digits from the rate.
	statsCacheTTL = time.Minute
	// statsStaleTTL is the degraded-mode fallback lifetime, long like
	// feedStaleTTL so the counter keeps showing the last-known value through a
	// multi-hour hopper outage instead of blanking.
	statsStaleTTL = 24 * time.Hour
	// statsCacheKey is the single fixed key: the snapshot is global, not
	// per-request, so one key serves every visitor.
	statsCacheKey = "index"
)

// loadIndexStats returns the cached corpus snapshot, refreshing it at most once
// per statsCacheTTL (FetchTTL singleflights concurrent callers onto one query
// pair). On any live-query failure it serves the last-known-good snapshot from
// statsStaleCache, mirroring loadFeedSnapshot's degraded-mode fallback.
func loadIndexStats(ctx context.Context) (indexStats, error) {
	if statsCache == nil {
		return buildIndexStats(ctx)
	}
	snap, err := statsCache.FetchTTL(ctx, statsCacheKey, statsCacheTTL, func(lctx context.Context) (indexStats, error) {
		// Detach from the first caller's request context (FetchTTL shares one
		// loader across coalesced waiters, so a client disconnect must not abort
		// the shared refresh) but keep a bound so a slow scan can't wedge the
		// singleflight — same rationale as the feed rebuild.
		bctx, cancel := context.WithTimeout(context.WithoutCancel(lctx), hopperQueryTimeout)
		defer cancel()
		return buildIndexStats(bctx)
	})
	if err != nil {
		if statsStaleCache != nil {
			if stale, found, gerr := statsStaleCache.Get(ctx, statsCacheKey); gerr == nil && found {
				return stale, nil
			}
		}
		return indexStats{}, err
	}
	return snap, nil
}

// buildIndexStats runs the two corpus queries behind the shared hopper-db
// breaker and records the result as last-known-good in statsStaleCache. The
// rate query is an index range-scan over ~statsWindow of rows
// (idx_samples_analyzed_at); the total is a full count, which is why it sits
// behind statsCacheTTL rather than running per request.
func buildIndexStats(ctx context.Context) (indexStats, error) {
	db := hopperDB.Load()
	if db == nil {
		return indexStats{}, errors.New("hopper not connected")
	}
	// Gate behind the shared hopper-db breaker so a degraded hopper sheds these
	// reads fast instead of every poll queueing a scan (the same breaker the
	// feed and per-sample lookups use).
	if berr := dbBreaker.allow(); berr != nil {
		recordDep(ctx, "hopper-db", "stats", "rejected", time.Time{})
		return indexStats{}, fmt.Errorf("hopper-db stats: %w", berr)
	}
	start := time.Now()
	fail := func() {
		dbBreaker.failure()
		recordDep(ctx, "hopper-db", "stats", "error", start)
	}
	total, err := db.CountAnalyzed(ctx)
	if err != nil {
		fail()
		return indexStats{}, fmt.Errorf("count analyzed: %w", err)
	}
	rates, err := db.AnalysisRatesSince(ctx, statsWindow)
	if err != nil {
		fail()
		return indexStats{}, fmt.Errorf("analysis rates: %w", err)
	}
	dbBreaker.success()
	recordDep(ctx, "hopper-db", "stats", "ok", start)

	snap := indexStats{
		GeneratedAt: time.Now().UTC(),
		Total:       total,
		RatePerMin:  float64(rates.TopLevel) / statsWindow.Minutes(),
		WindowSecs:  int(statsWindow.Seconds()),
	}
	if statsStaleCache != nil {
		if serr := statsStaleCache.SetTTL(context.WithoutCancel(ctx), statsCacheKey, snap, statsStaleTTL); serr != nil {
			logger.Debug("stats: stale cache write failed", "error", serr)
		}
	}
	return snap, nil
}

// cachedIndexStats returns the current snapshot only if one is already cached,
// never triggering a query. renderFeed uses it to server-render an initial
// counter value without adding a scan to the feed's hot path; the client's
// /_/stats poll takes over from there.
func cachedIndexStats(ctx context.Context) (indexStats, bool) {
	if statsCache == nil {
		return indexStats{}, false
	}
	snap, found, err := statsCache.Get(ctx, statsCacheKey)
	if err != nil || !found {
		return indexStats{}, false
	}
	return snap, true
}

// handleStats serves the live corpus snapshot as JSON for the masthead's
// "samples analyzed" counter. It mirrors handleFileStatus's shape (JSON,
// no-store, hopper nil-guard) but reads through statsCache so concurrent polls
// collapse to one query per statsCacheTTL and degrade to the stale snapshot on
// failure.
func handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if hopperDB.Load() == nil {
		writeStatsError(w, "hopper not connected")
		return
	}
	snap, err := loadIndexStats(r.Context())
	if err != nil {
		writeStatsError(w, "stats unavailable")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck,errchkjson // primitive values are JSON-safe
		"total":        snap.Total,
		"rate_per_min": math.Round(snap.RatePerMin*10) / 10,
		"window_secs":  snap.WindowSecs,
		"as_of":        snap.GeneratedAt.UnixMilli(),
	})
}

// writeStatsError writes a 503 JSON error for the stats endpoint. The caller
// has already set the JSON content-type and no-store headers.
func writeStatsError(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg}) //nolint:errcheck,errchkjson // JSON-safe; response already failing
}

// commaInt formats a non-negative integer with thousands separators
// (2847213 → "2,847,213") for the counter's server-rendered initial value; the
// client counter takes over once /_/stats responds.
func commaInt(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}
