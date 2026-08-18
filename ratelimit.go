package main

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// rateLimiter is a per-client token-bucket limiter. Each client — keyed by the
// real client IP (see clientIP, which honors Cloudflare's CF-Connecting-IP) —
// draws from a bucket that starts full at burst tokens and refills at rate
// tokens/second. A request that finds its bucket empty is shed with 429. This
// lets traffic, bots included, flow freely up to a sustained rate with a burst
// allowance, and only rejects the excess — rather than blocking or challenging.
//
// State is in-memory only: a restart resets every bucket, which is correct for
// overload protection (it is a cache, not durable data, per the project's
// no-persistent-storage rule). A background sweep evicts idle buckets so the map
// cannot grow unbounded under a flood of distinct source IPs.
type rateLimiter struct {
	buckets map[string]*clientBucket
	mu      sync.Mutex

	rate  float64       // tokens replenished per second
	burst float64       // bucket capacity, i.e. the maximum burst
	ttl   time.Duration // idle buckets older than this are evicted
}

type clientBucket struct {
	last   time.Time
	tokens float64
}

// newRateLimiter builds a limiter that admits up to limit requests per window as
// a sustained rate, with an initial burst of limit. A non-positive limit or
// window returns nil, which the middleware treats as "limiting disabled".
func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	if limit <= 0 || window <= 0 {
		return nil
	}
	return &rateLimiter{
		rate:    float64(limit) / window.Seconds(),
		burst:   float64(limit),
		ttl:     window,
		buckets: make(map[string]*clientBucket),
	}
}

// allow reports whether a request from key may proceed at time now. When it may
// not, it returns how long until the next token frees up, for the Retry-After
// header. now is passed in (not read from the clock here) so the policy is
// deterministically testable.
func (rl *rateLimiter) allow(key string, now time.Time) (ok bool, retryAfter time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b := rl.buckets[key]
	if b == nil {
		// First request from this client: a full bucket, minus this request.
		rl.buckets[key] = &clientBucket{tokens: rl.burst - 1, last: now}
		return true, 0
	}
	// Lazily replenish based on time elapsed since the client's last request,
	// capped at burst. No background refill goroutine is needed.
	b.tokens = min(rl.burst, b.tokens+now.Sub(b.last).Seconds()*rl.rate)
	b.last = now
	if b.tokens < 1 {
		// Time to accrue the fraction of a token still owed.
		return false, time.Duration((1 - b.tokens) / rl.rate * float64(time.Second))
	}
	b.tokens--
	return true, 0
}

// limit is the rate-limiting middleware. Requests over the configured rate get a
// 429 with Retry-After. Static assets and page chrome never draw from the
// budget, so probes and a rendered page's follow-on fetches stay reachable. A
// nil receiver is a pass-through, so main can wire it unconditionally whether
// or not limiting is enabled.
func (rl *rateLimiter) limit(next http.Handler) http.Handler {
	if rl == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A visitor who already solved the challenge browses unthrottled, and
		// exempt paths (static assets, page chrome, health, and the challenge
		// endpoint) are never limited — the last so a throttled human can
		// always reach it.
		if rateLimitExempt(r.URL.Path) || hasValidPass(r) {
			next.ServeHTTP(w, r)
			return
		}
		ip := clientIP(r)
		ok, retryAfter := rl.allow(ip, time.Now())
		if ok {
			next.ServeHTTP(w, r)
			return
		}
		// Over the rate. Browser navigations get the solvable challenge page
		// (which logs "challenge shown" itself); scripts and download bots get a
		// bare 429 + Retry-After they can honor — logged at Debug, since the
		// access log already records the 429 and a flood must not self-amplify.
		if wantsChallenge(r) {
			serveChallenge(w, r, retryAfter)
			return
		}
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
		http.Error(w, "rate limit exceeded; please slow down", http.StatusTooManyRequests)
		logger.Debug("rate limited", "client_ip", ip, "path", r.URL.RequestURI())
	})
}

// rateLimitExempt reports whether a path bypasses rate limiting. The budget is
// for document requests (HTML pages, feeds, downloads, mutations) — static
// assets and the cheap chrome a rendered page then fetches must not consume
// it, or three real page views burn the default burst of 10. Exempt:
//
//   - /static/ and /favicon.ico: the page's scripts, fonts, images, and icon.
//     favicon sits outside /static/ so it does not fall through to the
//     /{ecosystem} feed route (see handleFavicon).
//   - /_/stats: masthead counter poll, every 15s on the feed.
//   - /file/{sha}/members|rum|wait|status: JS hydrations of a page already
//     counted. Crawlers do not run JS, so these are not a scraper vector.
//   - /_/health, /_/metrik, /_/challenge: probes and the challenge form.
func rateLimitExempt(path string) bool {
	switch path {
	case "/favicon.ico", "/_/health", "/_/metrik", "/_/challenge", "/_/stats":
		return true
	}
	if strings.HasPrefix(path, "/static/") {
		return true
	}
	if strings.HasPrefix(path, "/file/") {
		if i := strings.LastIndexByte(path, '/'); i >= 0 {
			switch path[i:] {
			case "/members", "/rum", "/wait", "/status":
				return true
			}
		}
	}
	return false
}

// sweepIdle evicts buckets untouched for a full ttl, bounding memory under a
// flood of distinct source IPs. A bucket idle that long has fully replenished,
// so dropping it is indistinguishable from keeping it: the next request from
// that client simply starts fresh. It runs until ctx is cancelled; ctx is passed
// from main per the project convention that libraries never create their own.
func (rl *rateLimiter) sweepIdle(ctx context.Context) {
	if rl == nil {
		return
	}
	ticker := time.NewTicker(rl.ttl)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			rl.mu.Lock()
			for key, b := range rl.buckets {
				if now.Sub(b.last) > rl.ttl {
					delete(rl.buckets, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}
