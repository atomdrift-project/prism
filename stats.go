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
// files are in the index, plus the recent ingestion rate the client
// extrapolates the digits with between polls. It is a planner estimate, not an
// exact count — all a "roughly N and climbing" counter needs, and all a
// zero-scan query can give.
type indexStats struct {
	GeneratedAt time.Time // when the estimate was taken (server clock, UTC)
	Total       int64     // estimated rows in the samples table
	RatePerMin  float64   // estimated rows added per minute, over statsRateWindow
}

// statsLatest is the most recent estimate, published by statsPollLoop and read
// lock-free by the endpoint and the feed renderer. A single background writer
// polls the database once a minute; every request just reads this pointer, so a
// client never triggers or blocks on a query.
var statsLatest atomic.Pointer[indexStats]

const (
	// statsPollInterval is how often the background poller refreshes the
	// estimate. One cheap query a minute — an O(1) catalog read plus a bounded
	// index range scan for the rate — is the entire database cost of the counter,
	// no matter how many clients are watching or how fast they poll.
	statsPollInterval = time.Minute
	// statsRateWindow is the trailing window the ingestion rate is measured over.
	statsRateWindow = 15 * time.Minute
	// statsQueryTimeout bounds the poll query so a wedged read can't stall the
	// poller. Generous: the catalog read is O(1) and the rate scan is bounded to
	// the rows that landed in the last statsRateWindow.
	statsQueryTimeout = 5 * time.Second
)

// statsQueryResult is one poll's raw readings from the database.
type statsQueryResult struct {
	estimate int64 // pg_class.reltuples — the planner's live-row estimate
	recent   int64 // rows inserted in the last statsRateWindow, for the rate
}

// statsPollLoop maintains the published index-size estimate. Each poll publishes
// the planner's live-row estimate for the samples table (pg_class.reltuples) as
// the total, plus the recent ingestion rate the client extrapolates the digits
// with between polls. reltuples already reflects net inserts minus deletes and
// stays within a fraction of a percent of an exact count, so the counter is
// truthful without an O(rows) scan. A purely additive running total, by
// contrast, could never give back the rows reconciliation deletes and drifted
// permanently high — which is why this publishes the estimate directly and lets
// it correct downward. The loop runs for the life of ctx, independent of the
// hopper connection (queryStats errors while hopper is down and it simply
// retries), so it needs no hookup to the connect/reconnect callbacks. All
// database cost of the counter lives here: one bounded query a minute.
func statsPollLoop(ctx context.Context) {
	poll := func() {
		qctx, cancel := context.WithTimeout(ctx, statsQueryTimeout)
		defer cancel()
		res, err := queryStats(qctx)
		if err != nil {
			logger.Debug("stats poll failed", "error", err)
			return
		}
		snap := indexStats{
			GeneratedAt: time.Now().UTC(),
			Total:       res.estimate,
			RatePerMin:  float64(res.recent) / statsRateWindow.Minutes(),
		}
		statsLatest.Store(&snap)
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

// queryStats reads the planner estimate and the trailing-window insert count in
// a single query through the exposed pool. The estimate is pg_class.reltuples —
// an O(1) catalog read, no table scan. The count comes from one index range scan
// over just the last statsRateWindow via idx_samples_created_at (the Grafana
// ingest-rate index), so the whole poll stays cheap regardless of corpus size.
// It goes through the pool rather than a hopper method so a one-line stats read
// needs no hopper release + pin bump to ship.
func queryStats(ctx context.Context) (statsQueryResult, error) {
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
	window := fmt.Sprintf("%d minutes", int(statsRateWindow.Minutes()))
	var res statsQueryResult
	err := pool.QueryRow(ctx, `
		SELECT
		  (SELECT reltuples::bigint FROM pg_class WHERE oid = 'samples'::regclass),
		  count(*)
		FROM samples
		WHERE created_at >= now() - $1::interval`,
		window).Scan(&res.estimate, &res.recent)
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

// cachedIndexStats returns the latest published estimate, if the poller has
// produced one yet. renderFeed uses it to seed the counter's initial value.
func cachedIndexStats() (indexStats, bool) {
	s := statsLatest.Load()
	if s == nil {
		return indexStats{}, false
	}
	return *s, true
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
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck,errchkjson // primitive values are JSON-safe
		"total":        snap.Total,
		"rate_per_min": math.Round(snap.RatePerMin*10) / 10,
		"as_of":        snap.GeneratedAt.UnixMilli(),
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
