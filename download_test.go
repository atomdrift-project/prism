package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseRetryAfter(t *testing.T) {
	def := 7 * time.Second
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"3", 3 * time.Second},
		{"0", 0},
		{" 5 ", 5 * time.Second},
		{"", def},
		{"-1", def},
		{"abc", def},
		{"Wed, 21 Oct 2099 07:28:00 GMT", def}, // HTTP-date form isn't parsed; falls back.
	}
	for _, c := range cases {
		if got := parseRetryAfter(c.in, def); got != c.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want int
	}{
		{0, 1},
		{500 * time.Millisecond, 1},
		{1 * time.Second, 1},
		{30 * time.Second, 30},
	}
	for _, c := range cases {
		if got := retryAfterSeconds(c.in); got != c.want {
			t.Errorf("retryAfterSeconds(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

// fetchOutcome captures everything a test needs to assert about one
// fetchHopperFile call. The response body is read and closed inside the helper,
// so it never escapes and tests stay free of lifecycle boilerplate.
type fetchOutcome struct {
	w        *httptest.ResponseRecorder // records the error fetchHopperFile wrote on failure
	gotResp  bool                       // true when fetchHopperFile returned a live response
	status   int                        // status of that response
	body     string                     // its body
	rawCalls *atomic.Int32              // hopper hit count
}

// fetchTest points the hopper client at srv with a tiny backoff, runs one
// fetchHopperFile call, and returns its outcome. Globals are restored on
// cleanup.
func fetchTest(t *testing.T, handler http.HandlerFunc) fetchOutcome {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		handler(w, r)
	}))
	defer srv.Close()

	oldAddr, oldClient, oldBackoff := hopperAPIAddr, hopperClient, downloadBackoff
	hopperAPIAddr = srv.URL
	hopperClient = srv.Client()
	downloadBackoff = []time.Duration{time.Millisecond, time.Millisecond}
	defer func() { hopperAPIAddr, hopperClient, downloadBackoff = oldAddr, oldClient, oldBackoff }()

	const sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/file/"+sha+".dl", http.NoBody)
	resp, cancel := fetchHopperFile(w, r, sha, time.Now(), slog.New(slog.DiscardHandler))
	out := fetchOutcome{w: w, rawCalls: &calls}
	if resp != nil {
		defer cancel()
		defer func() { _ = resp.Body.Close() }() //nolint:errcheck // test cleanup
		out.gotResp = true
		out.status = resp.StatusCode
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		out.body = string(b)
	}
	return out
}

func TestFetchHopperFileOK(t *testing.T) {
	out := fetchTest(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "payload") //nolint:errcheck // test handler write
	})
	if !out.gotResp {
		t.Fatalf("expected a live response, got error status %d", out.w.Code)
	}
	if out.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", out.status)
	}
	if out.body != "payload" {
		t.Fatalf("body = %q, want %q", out.body, "payload")
	}
}

func TestFetchHopperFileRetriesThenSucceeds(t *testing.T) {
	var n atomic.Int32
	out := fetchTest(t, func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) <= 2 {
			// No Retry-After: the loop falls back to the (test-shrunk) backoff.
			http.Error(w, `{"error":"busy"}`, http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok") //nolint:errcheck // test handler write
	})
	if !out.gotResp || out.status != http.StatusOK {
		t.Fatalf("expected 200 after retries, got resp=%v status=%d", out.gotResp, out.status)
	}
	if got := out.rawCalls.Load(); got != 3 {
		t.Fatalf("hopper called %d times, want 3 (2 x 503 then 200)", got)
	}
}

func TestFetchHopperFileExhausts503AndSurfacesRetryAfter(t *testing.T) {
	out := fetchTest(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, `{"error":"busy"}`, http.StatusServiceUnavailable)
	})
	if out.gotResp {
		t.Fatalf("expected no live response after exhausting retries, got status %d", out.status)
	}
	// Three attempts: the original plus one per backoff entry.
	if got := out.rawCalls.Load(); got != 3 {
		t.Fatalf("hopper called %d times, want 3", got)
	}
	if out.w.Code != http.StatusServiceUnavailable {
		t.Fatalf("client status = %d, want 503", out.w.Code)
	}
	// The final attempt hands hopper's own Retry-After hint back to the client.
	if ra := out.w.Header().Get("Retry-After"); ra != "1" {
		t.Fatalf("client Retry-After = %q, want hopper's hint %q", ra, "1")
	}
}

// Permanent statuses (410/413/415/422) must pass straight through without a
// retry so the user sees a precise, actionable message instead of a generic 502.
func TestFetchHopperFilePermanentStatusesNoRetry(t *testing.T) {
	for _, status := range []int{
		http.StatusGone,
		http.StatusRequestEntityTooLarge,
		http.StatusUnsupportedMediaType,
		http.StatusUnprocessableEntity,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			out := fetchTest(t, func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, `{"error":"permanent"}`, status)
			})
			if !out.gotResp {
				t.Fatalf("permanent status %d should be returned to caller, got error", status)
			}
			if out.status != status {
				t.Fatalf("status = %d, want %d", out.status, status)
			}
			if got := out.rawCalls.Load(); got != 1 {
				t.Fatalf("hopper called %d times for %d, want exactly 1 (no retry)", got, status)
			}
		})
	}
}

func TestFetchHopperFileRetryAfterOverridesBackoff(t *testing.T) {
	// hopper asks to retry immediately (Retry-After: 0), overriding the default
	// backoff; the loop must honor the hint and not stall.
	var n atomic.Int32
	start := time.Now()
	out := fetchTest(t, func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, `{"error":"busy"}`, http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok") //nolint:errcheck // test handler write
	})
	if !out.gotResp || out.status != http.StatusOK {
		t.Fatalf("expected 200 after one retry, got resp=%v status=%d", out.gotResp, out.status)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("retry honored a slow backoff (%v) instead of the Retry-After: 0 hint", elapsed)
	}
}

func TestFetchHopperFileTerminalStatusBodyReadable(t *testing.T) {
	// A terminal non-200 carries a JSON error body; fetchHopperFile returns it
	// unread so the caller maps the status and the body stays available.
	out := fetchTest(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	})
	if !out.gotResp || out.status != http.StatusNotFound {
		t.Fatalf("expected 404 passthrough, got resp=%v status=%d", out.gotResp, out.status)
	}
	if !strings.Contains(out.body, "not found") {
		t.Fatalf("body = %q, want it to contain hopper's error", out.body)
	}
}
