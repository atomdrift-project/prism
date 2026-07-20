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
	// statsPollInterval is how often the background poller reads the estimate.
	// One O(1) catalog read a minute is the entire database cost of the counter,
	// no matter how many clients are watching or how fast they poll.
	statsPollInterval = time.Minute
	// statsRateWindow is the span the ingestion rate is averaged over. The
	// poller keeps ~this much history of readings and derives the rate from the
	// oldest-to-newest delta, so the rate costs no extra query.
	statsRateWindow = 15 * time.Minute
	// statsQueryTimeout bounds a single estimate read so a wedged catalog query
	// can't stall the poller (it never should — the read is O(1)).
	statsQueryTimeout = 3 * time.Second
)

// statsReading is one timestamped estimate, retained only long enough to derive
// the trailing-window rate.
type statsReading struct {
	at    time.Time
	value int64
}

// statsPollLoop reads the index-size estimate once per statsPollInterval and
// publishes it (with a trailing-window rate) to statsLatest. It runs for the
// life of ctx, independent of the hopper connection: sampleCountEstimate errors
// while hopper is down and the loop simply retries, so it needs no hookup to
// the connect/reconnect callbacks. All database cost of the counter lives here.
func statsPollLoop(ctx context.Context) {
	var readings []statsReading
	poll := func() {
		qctx, cancel := context.WithTimeout(ctx, statsQueryTimeout)
		defer cancel()
		total, err := sampleCountEstimate(qctx)
		if err != nil {
			logger.Debug("stats poll failed", "error", err)
			return
		}
		now := time.Now()
		readings = append(readings, statsReading{at: now, value: total})
		// Keep only readings inside the rate window.
		cutoff := now.Add(-statsRateWindow)
		kept := readings[:0]
		for _, rd := range readings {
			if rd.at.After(cutoff) {
				kept = append(kept, rd)
			}
		}
		readings = kept

		rate := 0.0
		if len(readings) >= 2 {
			oldest := readings[0]
			if span := now.Sub(oldest.at).Minutes(); span > 0 {
				if rate = float64(total-oldest.value) / span; rate < 0 {
					rate = 0 // reltuples can wobble down between analyzes
				}
			}
		}
		statsLatest.Store(&indexStats{GeneratedAt: now.UTC(), Total: total, RatePerMin: rate})
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

// sampleCountEstimate reads pg_class.reltuples for the samples table — the
// planner's live-tuple estimate, maintained by (auto)ANALYZE and replicated to
// our read replica. It is an O(1) catalog read: no scan of the samples table,
// no dependency on any index or migration, so it costs the same whether the
// corpus is a thousand rows or a hundred million. It goes through the exposed
// pool because wrapping a one-line stats read in a hopper method would force a
// hopper release + go.mod pin bump to ship.
func sampleCountEstimate(ctx context.Context) (int64, error) {
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
	err := pool.QueryRow(ctx,
		`SELECT reltuples::bigint FROM pg_class WHERE oid = 'samples'::regclass`).Scan(&total)
	if err != nil {
		dbBreaker.failure()
		recordDep(ctx, "hopper-db", "stats", "error", start)
		return 0, fmt.Errorf("sample count estimate: %w", err)
	}
	dbBreaker.success()
	recordDep(ctx, "hopper-db", "stats", "ok", start)
	if total < 0 {
		total = 0 // reltuples is -1 until the table's first ANALYZE
	}
	return total, nil
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
