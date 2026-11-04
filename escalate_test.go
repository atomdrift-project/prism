package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// testSHA is the sample this feature was built for: a wheel that sat unanalyzed
// in hopper for 26 hours because nothing in the pipeline could tell that anyone
// cared about it.
const testSHA = "d4f02335e277c03b7fe88fb4da3d5e6f1a47604bcd6256a1bc49e7b24faaa7de"

// setupEscalate points hopper-api at a stand-in server running fn and installs
// a fresh limiter so tests can't inherit each other's rate-limit tokens. It
// returns the count of requests the stand-in received; a nil fn fails every
// request it gets.
func setupEscalate(t *testing.T, fn http.HandlerFunc) *atomic.Int32 {
	t.Helper()
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	var reqs atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs.Add(1)
		if fn == nil {
			http.Error(w, "unexpected request", http.StatusInternalServerError)
			return
		}
		fn(w, r)
	}))
	t.Cleanup(srv.Close)

	oldAPI, oldClient, oldLimiter := hopperAPIAddr, hopperClient, escalateLimiter
	t.Cleanup(func() {
		hopperAPIAddr, hopperClient, escalateLimiter = oldAPI, oldClient, oldLimiter
	})
	hopperAPIAddr, hopperClient = srv.URL, srv.Client()
	escalateLimiter = newTokenBucket(1.0, 10)
	return &reqs
}

// queued answers a promotion the way hopper does when it accepts one.
func queued(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`{"status":"queued"}`)); err != nil {
			t.Errorf("write: %v", err)
		}
	}
}

// TestEscalatePromotes asserts a waited-on sample is promoted through hopper's
// rescan API, and that the promotion is the whole of it.
func TestEscalatePromotes(t *testing.T) {
	var path, method string
	reqs := setupEscalate(t, func(w http.ResponseWriter, r *http.Request) {
		path, method = r.URL.Path, r.Method
		queued(t)(w, r)
	})

	escalate(context.Background(), testSHA, logger)

	if want := "/api/rescan/" + testSHA; path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if method != http.MethodPost {
		t.Errorf("method = %q, want POST", method)
	}
	if got := reqs.Load(); got != 1 {
		t.Errorf("hopper requests = %d, want 1 (promotion only)", got)
	}
}

// TestEscalateSurvivesRefusal asserts a refused promotion, whether a hard
// failure or hopper's 409 for an ineligible sample, is one request and leaves
// no in-flight marker behind.
func TestEscalateSurvivesRefusal(t *testing.T) {
	// 400 rather than 5xx so the shared apiBreaker stays closed for other tests.
	cases := map[string]int{
		"hard failure": http.StatusBadRequest,
		"not eligible": http.StatusConflict,
	}
	for name, status := range cases {
		t.Run(name, func(t *testing.T) {
			reqs := setupEscalate(t, func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, `{"error":"refused"}`, status)
			})

			escalate(context.Background(), testSHA, logger)

			if got := reqs.Load(); got != 1 {
				t.Errorf("hopper requests = %d, want 1 (the refused promotion)", got)
			}
			if _, busy := escalating.Load(testSHA); busy {
				t.Error("in-flight marker outlived a refused escalation")
			}
		})
	}
}

// TestEscalateDedupesPerSHA asserts N tabs on one pending sample cost one
// promotion, not N.
func TestEscalateDedupesPerSHA(t *testing.T) {
	arrived, release := make(chan struct{}, 1), make(chan struct{})
	reqs := setupEscalate(t, func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-release
		queued(t)(w, r)
	})

	// The first escalation parks inside the promotion POST, holding the per-SHA
	// marker, while the rest arrive and must find it taken.
	var wg sync.WaitGroup
	wg.Go(func() { escalate(context.Background(), testSHA, logger) })
	<-arrived
	for range 8 {
		wg.Go(func() { escalate(context.Background(), testSHA, logger) })
	}
	close(release)
	wg.Wait()

	if got := reqs.Load(); got != 1 {
		t.Errorf("hopper requests = %d, want 1 for 9 concurrent escalations", got)
	}
	if _, busy := escalating.Load(testSHA); busy {
		t.Error("in-flight marker outlived the escalation")
	}
}

// TestEscalateRateLimited asserts the aggregate cap sheds distinct SHAs once
// the burst is spent, so a swarm across the feed can't turn into a promotion
// storm against hopper.
func TestEscalateRateLimited(t *testing.T) {
	reqs := setupEscalate(t, queued(t))
	escalateLimiter = newTokenBucket(0, 2) // two tokens, no refill

	for i := range 6 {
		sha := strings.Repeat("a", 63) + string(rune('0'+i))
		escalate(context.Background(), sha, logger)
	}

	if got := reqs.Load(); got != 2 {
		t.Errorf("hopper requests = %d, want 2 (the burst) out of 6 escalations", got)
	}
}

// TestEscalateRejectsMalformedSHA asserts the defence-in-depth guard: a sha that
// never passed a handler's validation reaches no upstream at all, so it can
// never be interpolated into a hopper-api URL path.
func TestEscalateRejectsMalformedSHA(t *testing.T) {
	reqs := setupEscalate(t, nil)

	for _, bad := range []string{"", "../../etc/passwd", strings.Repeat("a", 63), strings.Repeat("z", 64), testSHA + "/x"} {
		escalate(context.Background(), bad, logger)
	}

	if got := reqs.Load(); got != 0 {
		t.Errorf("hopper requests = %d, want 0 for malformed input", got)
	}
}
