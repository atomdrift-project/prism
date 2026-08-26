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
	"sync/atomic"
	"time"
)

// indexStats is the exact sample-count baseline published to the masthead
// counter, plus the recent ingestion rate used to advance the digits between
// exact recounts. The baseline comes from COUNT(*) and is therefore
// independent of PostgreSQL's planner statistics.
type indexStats struct {
	GeneratedAt time.Time // when Total was last refreshed/projected (server clock, UTC)
	Total       int64     // exact baseline, projected by the recent rate between recounts
	RatePerMin  float64   // exact inserts per minute over statsRateWindow
}

// statsLatest is the most recent snapshot, published by statsPollLoop and read
// lock-free by the endpoint and the feed renderer. Every request just reads
// this pointer and projects a short interval forward, so a client never
// triggers or blocks on a query.
var statsLatest atomic.Pointer[indexStats]

const (
	// statsExactInterval bounds how often the expensive exact baseline is
	// refreshed. On the local replica, COUNT(*) scans a 143 GB table/index set
	// and exceeded five minutes, so it must not share the rate poll cadence.
	statsExactInterval = 24 * time.Hour
	// statsRateInterval controls the indexed recent-ingest query. It is long
	// enough to avoid competing with the replica's normal work while still
	// giving the client a useful rate for the display.
	statsRateInterval = 15 * time.Minute
	// statsRateWindow is the trailing window the ingestion rate — and the
	// rate shown between exact snapshots — is measured over. Long enough to
	// average out ingest bursts while keeping the displayed motion smooth.
	statsRateWindow = 2 * time.Hour
	// statsExactQueryTimeout bounds the exact count so a wedged read can't
	// stall the poller forever. It is deliberately generous because counting
	// the current replica takes multiple minutes.
	statsExactQueryTimeout = 10 * time.Minute
	// statsRateQueryTimeout bounds the indexed rate query independently of the
	// much slower exact baseline.
	statsRateQueryTimeout = 60 * time.Second
)

// statsPollLoop maintains an exact baseline and a cheaper recent-ingest rate.
// COUNT(*) is refreshed daily because the local replica's 143 GB samples table
// takes several minutes to count. The indexed rate query runs every fifteen
// minutes. Between exact recounts the published total advances with that rate;
// this avoids both a minute-by-minute full scan and planner-statistic bounce.
// The loop runs for the life of ctx, independent of the hopper connection, so
// failed reads simply leave the last snapshot in place and retry later.
func statsPollLoop(ctx context.Context) {
	refreshExact := func() {
		qctx, cancel := context.WithTimeout(ctx, statsExactQueryTimeout)
		defer cancel()
		total, err := queryExactTotal(qctx)
		if err != nil {
			logger.Debug("exact stats poll failed", "error", err)
			return
		}
		now := time.Now().UTC()
		previous, ok := cachedIndexStats()
		statsLatest.Store(&indexStats{
			GeneratedAt: now,
			Total:       total,
			RatePerMin:  previousRate(previous, ok),
		})
	}
	refreshRate := func() {
		qctx, cancel := context.WithTimeout(ctx, statsRateQueryTimeout)
		defer cancel()
		recent, err := queryRecentCount(qctx)
		if err != nil {
			logger.Debug("rate stats poll failed", "error", err)
			return
		}
		previous, ok := cachedIndexStats()
		if !ok {
			return // the initial exact baseline has not arrived yet
		}
		now := time.Now().UTC()
		projected := projectIndexStats(previous, now)
		projected.RatePerMin = float64(recent) / statsRateWindow.Minutes()
		statsLatest.Store(&projected)
	}
	refreshExact() // establish an exact baseline; it may take several minutes
	rateTicker := time.NewTicker(statsRateInterval)
	defer rateTicker.Stop()
	exactTicker := time.NewTicker(statsExactInterval)
	defer exactTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-rateTicker.C:
			refreshRate()
		case <-exactTicker.C:
			refreshExact()
		}
	}
}

func previousRate(previous indexStats, ok bool) float64 {
	if !ok {
		return 0
	}
	return previous.RatePerMin
}

// queryExactTotal reads the exact number of rows through the exposed pool.
// COUNT(*) is deliberately used instead of planner statistics: ANALYZE and
// VACUUM cannot change its value. This is run only by the daily baseline
// refresh and never on a browser request.
func queryExactTotal(ctx context.Context) (int64, error) {
	db := hopperDB.Load()
	if db == nil {
		return 0, errors.New("hopper not connected")
	}
	pool := db.Pool()
	if pool == nil {
		return 0, errors.New("hopper pool unavailable")
	}
	// Gate behind the shared hopper-db breaker so a degraded hopper sheds the
	// read fast, exactly like the feed and per-sample lookups.
	if berr := dbBreaker.allow(); berr != nil {
		recordDep(ctx, "hopper-db", "stats", "rejected", time.Time{})
		return 0, fmt.Errorf("hopper-db stats: %w", berr)
	}
	start := time.Now()
	var total int64
	err := pool.QueryRow(ctx, `SELECT count(*) FROM samples`).Scan(&total)
	if err != nil {
		dbBreaker.failure()
		recordDep(ctx, "hopper-db", "stats", "error", start)
		return 0, fmt.Errorf("exact stats query: %w", err)
	}
	dbBreaker.success()
	recordDep(ctx, "hopper-db", "stats", "ok", start)
	return total, nil
}

// queryRecentCount reads only the trailing created_at range. The replica has
// idx_samples_created_at, making this much cheaper than the exact baseline;
// it is still isolated behind its own timeout because the index currently
// incurs heap visibility checks during autovacuum.
func queryRecentCount(ctx context.Context) (int64, error) {
	db := hopperDB.Load()
	if db == nil {
		return 0, errors.New("hopper not connected")
	}
	pool := db.Pool()
	if pool == nil {
		return 0, errors.New("hopper pool unavailable")
	}
	if berr := dbBreaker.allow(); berr != nil {
		recordDep(ctx, "hopper-db", "stats", "rejected", time.Time{})
		return 0, fmt.Errorf("hopper-db stats: %w", berr)
	}
	start := time.Now()
	window := fmt.Sprintf("%d seconds", int(statsRateWindow/time.Second))
	var recent int64
	err := pool.QueryRow(ctx, `
		SELECT count(*) FROM samples
		WHERE created_at >= now() - $1::interval`, window).Scan(&recent)
	if err != nil {
		dbBreaker.failure()
		recordDep(ctx, "hopper-db", "stats", "error", start)
		return 0, fmt.Errorf("recent stats query: %w", err)
	}
	dbBreaker.success()
	recordDep(ctx, "hopper-db", "stats", "ok", start)
	return recent, nil
}

// cachedIndexStats returns the latest published snapshot, if the poller has
// produced one yet. Serving paths should pass it through projectIndexStats so
// a page load between polls still shows a live total.
func cachedIndexStats() (indexStats, bool) {
	s := statsLatest.Load()
	if s == nil {
		return indexStats{}, false
	}
	return *s, true
}

// projectIndexStats advances a snapshot to `now` at the measured 2h rate,
// capped at one rate interval so a stalled poller cannot invent unbounded
// growth. GeneratedAt is rewritten to now so the client does not apply the
// same projection a second time.
func projectIndexStats(s indexStats, now time.Time) indexStats {
	elapsed := min(max(now.Sub(s.GeneratedAt), 0), statsRateInterval)
	s.Total += int64(math.Round(s.RatePerMin * elapsed.Minutes()))
	s.GeneratedAt = now
	return s
}

// handleStats serves the latest exact index-size snapshot as JSON for the masthead
// counter. It only ever reads statsLatest (published by statsPollLoop), so it
// never touches the database and can't block. Before the first poll completes
// it returns {"ready":false} and the client keeps polling.
func handleStats(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	snap, ok := cachedIndexStats()
	if !ok {
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": false}) //nolint:errcheck,errchkjson // JSON-safe; client tolerates and retries
		return
	}
	live := projectIndexStats(snap, time.Now().UTC())
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck,errchkjson // primitive values are JSON-safe
		"total":        live.Total,
		"rate_per_min": math.Round(live.RatePerMin*10) / 10,
		"as_of":        live.GeneratedAt.UnixMilli(),
	})
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
