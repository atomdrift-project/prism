package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// indexStats is the exact number of rows in `samples`, published to the
// masthead counter. There is deliberately no ingest rate and no projection:
// the counter renders the last polled figure with a trailing "+", which is
// true between polls without the client or the server inventing digits.
type indexStats struct {
	GeneratedAt time.Time // when Total was last refreshed (server clock, UTC)
	Total       int64     // exact row count as of GeneratedAt
	// maxID is the highest samples.id included in Total. It is the watermark
	// the next incremental poll counts forward from; unexported because it is
	// poller bookkeeping, not something the page or /_/stats ever shows.
	maxID int64
}

// statsLatest is the most recent snapshot, published by statsPollLoop and read
// lock-free by the endpoint and the feed renderer. Every request just reads
// this pointer, so a client never triggers or blocks on a query.
var statsLatest atomic.Pointer[indexStats]

const (
	// statsPollInterval is how often the published total moves. Each poll is
	// the incremental query below, not a full count.
	statsPollInterval = 20 * time.Minute
	// statsBaselineInterval bounds how often the full COUNT(*) re-runs. The
	// incremental poll is exact for inserts but cannot see a delete below the
	// watermark, so a periodic recount reconciles any drift. `samples` is
	// effectively insert-only (n_tup_del = 0 on the replica), so this is a
	// safety net rather than a correction that is expected to find anything.
	statsBaselineInterval = 24 * time.Hour
	// statsBaselineQueryTimeout bounds the full count. Counting the current
	// replica is a ~208 GB sequential scan, measured at 80-90 s, so this is
	// deliberately generous.
	statsBaselineQueryTimeout = 10 * time.Minute
	// statsDeltaQueryTimeout bounds the incremental poll. That query is a
	// primary-key range scan over one interval's worth of new rows (~40 k),
	// so it should finish in milliseconds; the timeout only catches a wedge.
	statsDeltaQueryTimeout = 30 * time.Second
)

// statsPollLoop keeps the published total exact and cheap. It counts the table
// once at startup to establish a baseline, then every statsPollInterval counts
// only the rows above the previous high-water id and adds them. That keeps the
// per-poll cost proportional to what was ingested rather than to the size of
// the table -- the whole point, since the old rate query seq-scanned all
// 208 GB every 15 minutes, took ~90 s against a 60 s timeout, and therefore
// never once succeeded. The loop runs for the life of ctx, so a failed read
// simply leaves the last snapshot in place and retries at the next tick.
func statsPollLoop(ctx context.Context) {
	refreshBaseline := func() {
		qctx, cancel := context.WithTimeout(ctx, statsBaselineQueryTimeout)
		defer cancel()
		total, maxID, err := queryExactTotal(qctx)
		if err != nil {
			logger.Debug("baseline stats poll failed", "error", err)
			return
		}
		statsLatest.Store(&indexStats{
			GeneratedAt: time.Now().UTC(),
			Total:       total,
			maxID:       maxID,
		})
	}
	refreshDelta := func() {
		previous, ok := cachedIndexStats()
		if !ok {
			refreshBaseline() // no baseline yet -- an earlier count must have failed
			return
		}
		qctx, cancel := context.WithTimeout(ctx, statsDeltaQueryTimeout)
		defer cancel()
		added, maxID, err := queryDeltaSince(qctx, previous.maxID)
		if err != nil {
			logger.Debug("incremental stats poll failed", "error", err)
			return
		}
		statsLatest.Store(&indexStats{
			GeneratedAt: time.Now().UTC(),
			Total:       previous.Total + added,
			maxID:       maxID,
		})
	}
	refreshBaseline() // establish the baseline; it may take a couple of minutes
	pollTicker := time.NewTicker(statsPollInterval)
	defer pollTicker.Stop()
	baselineTicker := time.NewTicker(statsBaselineInterval)
	defer baselineTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-pollTicker.C:
			refreshDelta()
		case <-baselineTicker.C:
			refreshBaseline()
		}
	}
}

// statsCount runs a stats query through the exposed pool, gated behind the
// shared hopper-db breaker so a degraded hopper sheds the read fast, exactly
// like the feed and per-sample lookups. Both stats queries return the same
// (count, high-water id) shape.
func statsCount(ctx context.Context, operation, sql string, args ...any) (int64, int64, error) {
	db := hopperDB.Load()
	if db == nil {
		return 0, 0, errors.New("hopper not connected")
	}
	pool := db.Pool()
	if pool == nil {
		return 0, 0, errors.New("hopper pool unavailable")
	}
	if berr := dbBreaker.allow(); berr != nil {
		recordDep(ctx, "hopper-db", "stats", "rejected", time.Time{})
		return 0, 0, fmt.Errorf("hopper-db stats: %w", berr)
	}
	start := time.Now()
	var count, maxID int64
	if err := pool.QueryRow(ctx, sql, args...).Scan(&count, &maxID); err != nil {
		dbBreaker.failure()
		recordDep(ctx, "hopper-db", "stats", "error", start)
		return 0, 0, fmt.Errorf("%s stats query: %w", operation, err)
	}
	dbBreaker.success()
	recordDep(ctx, "hopper-db", "stats", "ok", start)
	return count, maxID, nil
}

// queryExactTotal reads the exact number of rows, plus the id watermark that
// the incremental polls count forward from. COUNT(*) is deliberately used
// instead of planner statistics: reltuples ran ~6% high on this replica
// (129.3 M against a true 122.1 M), and ANALYZE and VACUUM move it.
func queryExactTotal(ctx context.Context) (int64, int64, error) {
	return statsCount(ctx, "exact",
		`SELECT count(*), coalesce(max(id), 0) FROM samples`)
}

// queryDeltaSince counts the rows inserted above a previous high-water id and
// returns the new watermark. This is an index range scan on samples_pkey over
// only the new rows, so its cost tracks the ingest rate (~1.9 k rows/min) and
// not the 122 M-row table. It cannot observe deletes below the watermark;
// statsBaselineInterval is what reconciles those.
func queryDeltaSince(ctx context.Context, since int64) (int64, int64, error) {
	return statsCount(ctx, "delta",
		`SELECT count(*), coalesce(max(id), $1::bigint) FROM samples WHERE id > $1::bigint`, since)
}

// cachedIndexStats returns the latest published snapshot, if the poller has
// produced one yet.
func cachedIndexStats() (indexStats, bool) {
	s := statsLatest.Load()
	if s == nil {
		return indexStats{}, false
	}
	return *s, true
}

// handleStats serves the latest exact count as JSON for the masthead counter.
// It only ever reads statsLatest (published by statsPollLoop), so it never
// touches the database and can't block. Before the first poll completes it
// returns {"ready":false} and the client keeps polling.
func handleStats(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	snap, ok := cachedIndexStats()
	if !ok {
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": false}) //nolint:errcheck,errchkjson // JSON-safe; client tolerates and retries
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck,errchkjson // primitive values are JSON-safe
		"total": snap.Total,
		"as_of": snap.GeneratedAt.UnixMilli(),
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
