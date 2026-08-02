package main

// Escalation: spending a person's attention as queue priority.
//
// A sample hopper has ingested but not analyzed is one row among hundreds of
// thousands, and workers claim that backlog in random SHA order — nothing about
// being looked at makes a worker reach it any sooner. Somebody sitting on the
// "Analyzing…" page is the best signal prism has that this particular row is
// the one that matters, and it is a signal nothing else in the pipeline can
// see. Escalation spends it two ways:
//
//   - Always: ask hopper to promote the sample to the forced-rescan tier, which
//     workers drain ahead of the unanalyzed backlog. Costs one POST, moves no
//     bytes, and works even when the local scan server is down or absent.
//   - Whenever a scan server is configured and healthy: analyze the sample here,
//     publish the verdict back to hopper, and let the waiting page resolve in
//     seconds rather than on some later worker poll.
//
// The second half is what makes escalation mean anything on a clock. Promotion
// moves a sample from a random draw out of a backlog of hundreds of thousands
// to the head of a tier that is usually empty, which is an enormous improvement
// in expectation and no guarantee at all: workers claim in batches whenever a
// slot frees, so the wait is bounded by nothing. The local scan is the only
// path prism can watch to completion, so it is on by default wherever --litmus
// points somewhere. See noEscalateScan for the override.
//
// The two compose. Publishing a result clears hopper's queue fields, so a local
// scan that wins the race retires the promotion it just made.
//
// Escalation is deliberately hung off the pending page's SSE channel rather
// than off GET /file/{sha}: the detail page is public and every feed entry
// links one, so a crawler sweep would escalate the whole feed. Reaching the
// wait channel takes a browser that ran the page's JavaScript, which is the
// closest thing prism has to proof that a person is waiting.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	// escalateTimeout bounds one escalation end to end: the promotion POST plus,
	// when enabled, a download and a full analysis. Generous because the work is
	// off the request path — nobody is blocked on it — but finite so a wedged
	// backend can't accumulate goroutines one waiting tab at a time.
	escalateTimeout = 5 * time.Minute

	// escalateScanMaxBytes caps what a page view will pull into prism's memory.
	// Well below the 100 MB browser-upload ceiling on purpose: an upload is a
	// deliberate act by someone who chose the file, while an escalation is a
	// side effect of loading a URL. Samples past this size stay hopper's work —
	// the promotion still happened, so they are merely queued, not dropped.
	escalateScanMaxBytes = 16 << 20
)

// escalateLimiter caps aggregate escalation pressure the way rescanLimiter caps
// the rescan button: 1/sec sustained with a burst of 10. The per-SHA guard below
// stops one popular sample from being escalated repeatedly; this stops a swarm
// of distinct SHAs from doing the same thing across the whole feed.
var escalateLimiter = newTokenBucket(1.0, 10)

// escalating holds the SHAs with an escalation in flight, so N tabs on the same
// pending sample cost one promotion and one analysis rather than N of each.
//
// Entries live only for the duration of the work, which means a reconnecting
// EventSource can escalate the same SHA again five minutes later. That is the
// intended behavior and needs no expiry cache: a successful escalation resolves
// the page, so the only SHA that comes back around is one still genuinely
// waiting — and escalateLimiter bounds how often any of them can.
var escalating sync.Map // sha string -> struct{}{}

// escalate promotes a pending sample and, when the local scan path is enabled,
// analyzes it. It blocks, so callers run it in a goroutine on a context
// detached from the request:
//
//	go escalate(context.WithoutCancel(ctx), sha, filename, log)
//
// filename is hopper's name for the sample. It is a hint, not an identifier —
// the analysis keys on the bytes — but litmus reads the extension when it picks
// a format, so passing the real name is worth the plumbing.
func escalate(ctx context.Context, sha, filename string, log *slog.Logger) {
	// The handler validates before calling, so this can only fire if a future
	// caller forgets. It is worth the two lines: sha is interpolated into two
	// hopper-api URL paths below, and 64 hex characters is what keeps that from
	// being a request-forgery primitive rather than string concatenation.
	if !validSHA256(sha) {
		log.Error("refusing to escalate a malformed sha256", "input", sha)
		return
	}
	if _, busy := escalating.LoadOrStore(sha, struct{}{}); busy {
		return
	}
	defer escalating.Delete(sha)

	if !escalateLimiter.Allow() {
		log.Debug("escalation rate-limited")
		return
	}

	ctx, cancel := context.WithTimeout(ctx, escalateTimeout)
	defer cancel()

	// The promotion is also the admission check for everything below it. hopper
	// only accepts one for a top-level, non-skipped sample, so a 200 is proof
	// that this SHA is a thing prism may analyze and publish a verdict for — an
	// archive child gets its cleave_result from the reassembly of its parent,
	// and writing one directly would corrupt that. Nothing prism can see
	// distinguishes a child from a sample that is merely queued already, so the
	// only safe reading of a refusal is to stop.
	//
	// Little is lost by it: a refusal means the sample is already at the head of
	// the tier the scan would have raced, and the first view of a genuinely
	// pending sample — the one that matters — is accepted.
	if err := postRescanToHopper(ctx, sha); err != nil {
		if errors.Is(err, errSampleNotEligible) {
			log.Debug("escalation declined by hopper")
			return
		}
		log.Warn("escalation failed", "error", err)
		return
	}
	log.Info("escalated: promoted to hopper's forced-rescan tier")

	scanLocally(ctx, sha, filename, log)
}

// scanLocally runs the sample through the configured scan server and publishes
// the verdict, turning a queued escalation into a finished one. Every reason to
// decline is a normal operating state, not a failure: the path is off, a
// backend is down, the analysis slots are full, or the sample is too big. In
// all of them the promotion already queued the work for hopper's own workers.
func scanLocally(ctx context.Context, sha, filename string, log *slog.Logger) {
	if noEscalateScan {
		return
	}
	// litmusAnalyzeURL is empty when --litmus is unset, which is also how an
	// operator says "there is no scan server here" — so the configuration
	// answers this without a second flag to keep in sync with it.
	target := litmusAnalyzeURL()
	if target == "" || !hopperAPIAvailable() || !litmusAvailable() {
		log.Debug("escalation: local scan unavailable; leaving the sample queued")
		return
	}
	// Non-blocking, like the upload fast path: a saturated scan server must shed
	// escalations rather than queue memory-heavy work behind them. Uploads and
	// escalations share the semaphore, and uploads are someone waiting on a
	// redirect, so losing the race here is the right outcome.
	select {
	case litmusSlots <- struct{}{}:
		defer func() { <-litmusSlots }()
	default:
		log.Info("escalation: scan slots full; leaving the sample queued")
		return
	}

	buf, err := fetchSampleBytes(ctx, sha)
	if err != nil {
		log.Warn("escalation: fetching sample bytes failed", "error", err)
		return
	}

	start := time.Now()
	env, err := analyzeWithLitmus(ctx, target, buf, filename)
	if err != nil {
		log.Warn("escalation: analysis failed", "error", err)
		return
	}
	ms := time.Since(start).Milliseconds()

	// Cache before publishing: the page watches prism's cache as well as
	// hopper's row, so this is what actually ends the wait.
	cacheLitmusResult(ctx, sha, filename, env, int64(len(buf)), log)
	if err := publishResultToHopper(ctx, sha, env, ms); err != nil {
		// The verdict is cached and the sample is still queued, so a worker will
		// redo the work. Wasteful, not wrong.
		log.Warn("escalation: publishing to hopper failed", "error", err)
		return
	}
	log.Info("escalation: analyzed locally and published", "bytes", len(buf), "analyze_ms", ms)
}

// errSampleTooLarge reports a sample past escalateScanMaxBytes. Escalation
// treats it as a reason to stop, not as a fault.
var errSampleTooLarge = fmt.Errorf("sample exceeds the %d-byte escalation limit", escalateScanMaxBytes)

// errSampleMismatch reports bytes that are not the sample that was asked for.
var errSampleMismatch = errors.New("hopper returned bytes that do not match the requested sha256")

// fetchSampleBytes reads a sample from hopper-api into memory, refusing anything
// past escalateScanMaxBytes or anything whose content does not hash to sha. It
// is the escalation counterpart to fetchHopperFile, which streams to a client
// and reports failure by writing an HTTP status; here there is no client and no
// response to write, so this is a plain fetch under the same breaker.
//
// The limit is enforced on the bytes read rather than on Content-Length: a
// missing or dishonest length must not be able to talk prism into an unbounded
// read.
//
// The hash check is what makes these bytes safe to build a verdict on. Prism
// reads everywhere else, where wrong bytes cost one wrong page; here it writes,
// and hopper marks the sample analyzed on the strength of it. Bytes fetched
// under one sha and analyzed as another would file a verdict for a file nobody
// scanned, and it would stick — no worker re-queues a row that looks done. The
// expected digest is free, so prism does not take hopper-api's word for which
// file came back.
func fetchSampleBytes(ctx context.Context, sha string) ([]byte, error) {
	if err := apiBreaker.allow(); err != nil {
		recordDep(ctx, "hopper-api", "escalate", "rejected", time.Time{})
		return nil, fmt.Errorf("hopper-api fetch: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hopperFileURL(sha), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	start := time.Now()
	resp, err := hopperClient.Do(req) //nolint:gosec // hopperFileURL builds from the admin-configured hopper-api host and a validated SHA path
	if err != nil {
		apiBreaker.failure()
		recordDep(ctx, "hopper-api", "escalate", "error", start)
		return nil, fmt.Errorf("hopper request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort
	if resp.StatusCode >= http.StatusInternalServerError {
		apiBreaker.failure()
		recordDep(ctx, "hopper-api", "escalate", "error", start)
	} else {
		apiBreaker.success()
		recordDep(ctx, "hopper-api", "escalate", "ok", start)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hopper /api/file status %d", resp.StatusCode)
	}
	// One byte past the limit is enough to know the sample is over it.
	buf, err := io.ReadAll(io.LimitReader(resp.Body, escalateScanMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(buf) > escalateScanMaxBytes {
		return nil, errSampleTooLarge
	}
	sum := sha256.Sum256(buf)
	if got := hex.EncodeToString(sum[:]); got != sha {
		return nil, fmt.Errorf("%w: got %s", errSampleMismatch, got)
	}
	return buf, nil
}
