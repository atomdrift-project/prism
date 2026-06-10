package main

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// errBreakerOpen is returned by a dependency call site when its circuit
// breaker is open. Callers treat it as a fast-fail: the dependency is
// presumed unhealthy, so the request degrades immediately (serving stale
// cache or a 503) instead of blocking until its context deadline.
var errBreakerOpen = errors.New("circuit breaker open")

// breakerState is the position of a breaker in its closed -> open ->
// half-open -> closed lifecycle.
type breakerState int

const (
	breakerClosed   breakerState = iota // calls pass through; failures are counted
	breakerOpen                         // calls fast-fail until the cooldown elapses
	breakerHalfOpen                     // a single probe is allowed through
)

// breaker is a minimal per-dependency circuit breaker. It trips open after
// threshold consecutive failures, fast-fails every call for cooldown, then
// admits one probe (half-open). The probe's outcome decides whether to close
// (success) or re-open (failure).
//
// Each tier-1 dependency gets its own breaker so that a slow or failing
// dependency consumes only its own budget and cannot cascade into the request
// paths that touch a healthy dependency — the bulkhead boundary (RC-067). The
// fast-fail-with-stale-cache behaviour is the graceful-degradation path
// (RC-018).
// Fields are ordered to keep the two pointer-bearing members (name's string
// header and openedAt's *Location) adjacent, minimising the GC pointer-scan
// span (govet fieldalignment). mu guards failures, state, and openedAt.
type breaker struct {
	openedAt time.Time // monotonic; when the breaker last tripped open (guarded by mu)
	name     string    // dependency label, used in state-transition logs

	threshold int           // consecutive failures that trip the breaker open
	cooldown  time.Duration // how long to stay open before admitting a probe

	mu       sync.Mutex
	failures int
	state    breakerState
}

// allow reports whether a call may proceed; nil means go ahead. When open it
// admits exactly one probe once the cooldown has elapsed; all other callers
// receive an error wrapping errBreakerOpen that says why the breaker is open
// and when the next probe will be admitted.
func (b *breaker) allow() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case breakerOpen:
		if wait := b.cooldown - time.Since(b.openedAt); wait > 0 {
			return fmt.Errorf("%w after %d consecutive failures, next probe in %s",
				errBreakerOpen, b.failures, wait.Round(time.Millisecond))
		}
		b.state = breakerHalfOpen // this caller becomes the probe
		return nil
	case breakerHalfOpen:
		return fmt.Errorf("%w, recovery probe in flight", errBreakerOpen)
	default:
		return nil
	}
}

// success records a healthy outcome, closing the breaker and clearing the
// failure count.
func (b *breaker) success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	if b.state != breakerClosed {
		b.state = breakerClosed
		logger.Info("circuit breaker closed", "dependency", b.name)
	}
}

// failure records a dependency failure. A half-open probe failure re-opens
// immediately; otherwise the breaker opens once threshold consecutive
// failures accumulate.
func (b *breaker) failure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	if b.state == breakerOpen {
		return
	}
	if b.state == breakerHalfOpen || b.failures >= b.threshold {
		b.state = breakerOpen
		b.openedAt = time.Now()
		logger.Warn("circuit breaker opened",
			"dependency", b.name,
			"failures", b.failures,
			"cooldown", b.cooldown,
		)
	}
}

// Per-dependency breakers. hopper-api guards the HTTP file/upload calls;
// hopper-db guards the PostgreSQL sample-registry reads. Separate instances
// keep a failure in one from tripping the other (bulkhead isolation).
var (
	apiBreaker = &breaker{name: "hopper-api", threshold: 5, cooldown: 10 * time.Second}
	dbBreaker  = &breaker{name: "hopper-db", threshold: 5, cooldown: 10 * time.Second}
)
