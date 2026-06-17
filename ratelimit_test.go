package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterBurstThenShed(t *testing.T) {
	// 5 requests per minute: burst of 5, then ~1 every 12s.
	rl := newRateLimiter(5, time.Minute)
	now := time.Unix(1_700_000_000, 0)

	// The burst is admitted.
	for i := range 5 {
		if ok, _ := rl.allow("1.2.3.4", now); !ok {
			t.Fatalf("request %d within burst should be allowed", i+1)
		}
	}
	// The 6th, with no time elapsed, is shed with a positive Retry-After.
	ok, retry := rl.allow("1.2.3.4", now)
	if ok {
		t.Fatal("request beyond burst should be shed")
	}
	if retry <= 0 {
		t.Fatalf("shed request must report a positive Retry-After, got %v", retry)
	}

	// A different client has its own bucket and is unaffected.
	if ok, _ := rl.allow("5.6.7.8", now); !ok {
		t.Fatal("a distinct client IP must not share another's bucket")
	}

	// After one refill interval (window/limit = 12s) a token is back.
	if ok, _ := rl.allow("1.2.3.4", now.Add(12*time.Second)); !ok {
		t.Fatal("a token should replenish after the refill interval")
	}
}

func TestRateLimiterDisabled(t *testing.T) {
	if rl := newRateLimiter(0, time.Minute); rl != nil {
		t.Error("non-positive limit must disable limiting (nil)")
	}
	if rl := newRateLimiter(10, 0); rl != nil {
		t.Error("non-positive window must disable limiting (nil)")
	}
}

func TestRateLimiterMiddleware(t *testing.T) {
	rl := newRateLimiter(1, time.Minute)
	var served int
	h := rl.limit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		w.WriteHeader(http.StatusOK)
	}))

	call := func(path string) int {
		r := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		r.Header.Set("Cf-Connecting-Ip", "9.9.9.9")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	if got := call("/file/abc"); got != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", got)
	}
	if got := call("/file/abc"); got != http.StatusTooManyRequests {
		t.Fatalf("second request over limit: got %d, want 429", got)
	}
	// Exempt paths bypass the limiter even when the bucket is empty.
	if got := call("/static/app.css"); got != http.StatusOK {
		t.Fatalf("exempt path should never be limited: got %d, want 200", got)
	}
	if got := call("/_/health"); got != http.StatusOK {
		t.Fatalf("health check should never be limited: got %d, want 200", got)
	}
}

func TestRateLimiterNilPassThrough(t *testing.T) {
	var rl *rateLimiter // disabled
	h := rl.limit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	for range 100 {
		r := httptest.NewRequest(http.MethodGet, "/file/abc", http.NoBody)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("nil limiter must pass through every request, got %d", w.Code)
		}
	}
}
