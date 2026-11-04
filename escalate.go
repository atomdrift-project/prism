package main

// Escalation: spending a person's attention as queue priority.
//
// A sample hopper has ingested but not analyzed is one row among hundreds of
// thousands, and workers claim that backlog in random SHA order — nothing about
// being looked at makes a worker reach it any sooner. Somebody sitting on the
// "Analyzing…" page is the best signal prism has that this particular row is
// the one that matters, and it is a signal nothing else in the pipeline can
// see. Escalation spends it by asking hopper to promote the sample to the
// forced-rescan tier, which workers drain ahead of the unanalyzed backlog. It
// costs one POST and moves no bytes.
//
// Promotion moves a sample from a random draw out of a backlog of hundreds of
// thousands to the head of a tier that is usually empty: an enormous
// improvement in expectation, though no guarantee, since workers claim in
// batches whenever a slot frees.
//
// Escalation is deliberately hung off the pending page's SSE channel rather
// than off GET /file/{sha}: the detail page is public and every feed entry
// links one, so a crawler sweep would escalate the whole feed. Reaching the
// wait channel takes a browser that ran the page's JavaScript, which is the
// closest thing prism has to proof that a person is waiting.

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// escalateTimeout bounds one promotion. It is off the request path, so nobody
// is blocked on it, but finite so a wedged hopper-api can't accumulate
// goroutines one waiting tab at a time.
const escalateTimeout = 30 * time.Second

// escalateLimiter caps aggregate escalation pressure the way rescanLimiter caps
// the rescan button: 1/sec sustained with a burst of 10. The per-SHA guard below
// stops one popular sample from being escalated repeatedly; this stops a swarm
// of distinct SHAs from doing the same thing across the whole feed.
var escalateLimiter = newTokenBucket(1.0, 10)

// escalating holds the SHAs with an escalation in flight, so N tabs on the same
// pending sample cost one promotion rather than N.
//
// Entries live only for the duration of the work, which means a reconnecting
// EventSource can escalate the same SHA again later. That is the intended
// behavior and needs no expiry cache: hopper refuses a promotion within its
// re-queue cooldown, and escalateLimiter bounds how often any SHA can try.
var escalating sync.Map // sha string -> struct{}{}

// escalate promotes a pending sample in hopper's queue. It blocks, so callers
// run it in a goroutine on a context detached from the request:
//
//	go escalate(context.WithoutCancel(ctx), sha, log)
func escalate(ctx context.Context, sha string, log *slog.Logger) {
	// The handler validates before calling, so this can only fire if a future
	// caller forgets. It is worth the two lines: sha is interpolated into a
	// hopper-api URL path below, and 64 hex characters is what keeps that from
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

	// hopper refuses a promotion for an archive child, a skipped sample, or one
	// already within its re-queue cooldown. Each means there is nothing for
	// escalation to add, so a refusal is routine rather than a failure.
	if err := postRescanToHopper(ctx, sha); err != nil {
		if errors.Is(err, errSampleNotEligible) {
			log.Debug("escalation declined by hopper")
			return
		}
		log.Warn("escalation failed", "error", err)
		return
	}
	log.Info("escalated: promoted to hopper's forced-rescan tier")
}
