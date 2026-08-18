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

// indexStats is the live estimate published to the masthead counter: how many
// files are in the index, plus the recent ingestion rate the client (and the
// page renderer) advance the digits with between polls. Total starts at
// reltuples and accumulates exact created_at inserts between polls while that
// catalog value is sticky — still not a full-table COUNT(*), and all a
// truthful counter needs.
type indexStats struct {
	GeneratedAt time.Time // when this snapshot was taken (server clock, UTC)
	Total       int64     // reltuples, plus inserts folded in since it last moved
	RatePerMin  float64   // exact inserts per minute over statsRateWindow
}

// statsLatest is the most recent estimate, published by statsPollLoop and read
// lock-free by the endpoint and the feed renderer. A single background writer
// polls the database on statsPollInterval; every request just reads this
// pointer and projects a few seconds forward, so a client never triggers or
// blocks on a query.
var statsLatest atomic.Pointer[indexStats]

const (
	// statsPollInterval is how often the background poller refreshes the
	// snapshot. Cap skew at ~15s: one cheap query (O(1) catalog read + bounded
	// index range scan for the 2h delta) on this cadence is the entire database
	// cost of the counter, no matter how many clients are watching or how fast
	// they poll.
	statsPollInterval = 15 * time.Second
	// statsRateWindow is the trailing window the ingestion rate — and the
	// arrived-since-catalog correction — are measured over. Long enough to
	// average out ingest bursts, short enough that idx_samples_created_at
	// still answers in well under statsQueryTimeout.
	statsRateWindow = 2 * time.Hour
	// statsQueryTimeout bounds the poll query so a wedged read can't stall the
	// poller. Generous: the catalog read is O(1) and the rate scan is bounded to
	// the rows that landed in the last statsRateWindow.
	statsQueryTimeout = 5 * time.Second
)

// statsQueryResult is one poll's raw readings from the database.
type statsQueryResult struct {
	estimate int64 // pg_class.reltuples — the planner's live-row estimate
	recent   int64 // rows inserted in the last statsRateWindow, for the rate
	arrived  int64 // of those, rows with created_at >= the catalog watermark
}

// statsPollLoop maintains the published index-size estimate. Each poll reads
// pg_class.reltuples (the catalog baseline) and an exact count of rows whose
// created_at falls in the last statsRateWindow (via idx_samples_created_at).
// reltuples already reflects net inserts minus deletes and stays within a
// fraction of a percent of an exact count, so the counter is truthful without
// an O(rows) scan. Between ANALYZE/VACUUM, though, reltuples is sticky — so
// each poll folds in the exact created_at delta since the previous snapshot
// (a subset of that same 2h scan) and the published total tracks growth. The
// rate is the window's count / 2h, so the digits advance at the measured
// average rather than chasing a burst. When reltuples moves, the integral
// resets to the new catalog value (including downward). The loop runs for
// the life of ctx, independent of the hopper connection (queryStats errors
// while hopper is down and it simply retries), so it needs no hookup to the
// connect/reconnect callbacks. All database cost of the counter lives here:
// one bounded query per statsPollInterval.
func statsPollLoop(ctx context.Context) {
	var catalog int64
	poll := func() {
		qctx, cancel := context.WithTimeout(ctx, statsQueryTimeout)
		defer cancel()
		now := time.Now().UTC()
		watermark := now
		prev, hasPrev := cachedIndexStats()
		if hasPrev {
			watermark = prev.GeneratedAt
		}
		res, err := queryStats(qctx, watermark)
		if err != nil {
			logger.Debug("stats poll failed", "error", err)
			return
		}
		now = time.Now().UTC()
		total := res.estimate
		if !hasPrev || res.estimate != catalog {
			// First snapshot, or ANALYZE/VACUUM moved reltuples: trust the
			// catalog and start a fresh integral. The 2h arrived-count is not
			// added here — those rows are already in reltuples, or the
			// watermark was "now" and arrived is ~0.
			catalog = res.estimate
		} else {
			// reltuples is sticky between ANALYZE. Fold in the exact inserts
			// since the last snapshot (a subset of the same 2h index scan)
			// so the published total tracks growth without a full COUNT(*).
			total = prev.Total + res.arrived
		}
		statsLatest.Store(&indexStats{
			GeneratedAt: now,
			Total:       total,
			RatePerMin:  float64(res.recent) / statsRateWindow.Minutes(),
		})
	}
	poll() // warm immediately so the counter can appear on the first page load
	ticker := time.NewTicker(statsPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}

// queryStats reads the planner estimate and the trailing-window insert counts
// in a single query through the exposed pool. The estimate is pg_class.reltuples
// — an O(1) catalog read, no table scan. Both counts come from one index range
// scan over the last statsRateWindow via idx_samples_created_at (the Grafana
// ingest-rate index), so the whole poll stays cheap regardless of corpus size.
// `since` is the previous snapshot's clock: arrived counts rows in that window
// whose created_at is at least since (inserts landed since the last poll). It
// goes through the pool rather than a hopper method so a one-line stats read
// needs no hopper release + pin bump to ship.
func queryStats(ctx context.Context, since time.Time) (statsQueryResult, error) {
	db := hopperDB.Load()
	if db == nil {
		return statsQueryResult{}, errors.New("hopper not connected")
	}
	pool := db.Pool()
	if pool == nil {
		return statsQueryResult{}, errors.New("hopper pool unavailable")
	}
	// Gate behind the shared hopper-db breaker so a degraded hopper sheds the
	// read fast, exactly like the feed and per-sample lookups.
	if berr := dbBreaker.allow(); berr != nil {
		recordDep(ctx, "hopper-db", "stats", "rejected", time.Time{})
		return statsQueryResult{}, fmt.Errorf("hopper-db stats: %w", berr)
	}
	start := time.Now()
	// The interval literal is derived from statsRateWindow so the rate divisor
	// can't drift from the window the query measures.
	window := fmt.Sprintf("%d seconds", int(statsRateWindow/time.Second))
	var res statsQueryResult
	err := pool.QueryRow(ctx, `
		SELECT
		  (SELECT reltuples::bigint FROM pg_class WHERE oid = 'samples'::regclass),
		  count(*),
		  count(*) FILTER (WHERE created_at >= $2::timestamptz)
		FROM samples
		WHERE created_at >= now() - $1::interval`,
		window, since).Scan(&res.estimate, &res.recent, &res.arrived)
	if err != nil {
		dbBreaker.failure()
		recordDep(ctx, "hopper-db", "stats", "error", start)
		return statsQueryResult{}, fmt.Errorf("stats query: %w", err)
	}
	dbBreaker.success()
	recordDep(ctx, "hopper-db", "stats", "ok", start)
	if res.estimate < 0 {
		res.estimate = 0 // reltuples is -1 until the table's first ANALYZE
	}
	return res, nil
}

// cachedIndexStats returns the latest published snapshot, if the poller has
// produced one yet. Serving paths should pass it through projectIndexStats so
// a page load a few seconds after the poll still shows a live total.
func cachedIndexStats() (indexStats, bool) {
	s := statsLatest.Load()
	if s == nil {
		return indexStats{}, false
	}
	return *s, true
}

// projectIndexStats advances a poll snapshot to `now` at the measured 2h rate,
// capped at one poll interval so a stalled poller cannot invent more growth
// than the skew budget. GeneratedAt is rewritten to now so the client does not
// apply the same projection a second time.
func projectIndexStats(s indexStats, now time.Time) indexStats {
	elapsed := min(max(now.Sub(s.GeneratedAt), 0), statsPollInterval)
	s.Total += int64(math.Round(s.RatePerMin * elapsed.Minutes()))
	s.GeneratedAt = now
	return s
}

// handleStats serves the latest index-size estimate as JSON for the masthead
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
