package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
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

// escalateEnv is one escalation's worth of wiring: stand-in hopper-api and
// litmus servers, the globals repointed at them, and a fresh limiter and
// in-flight set so tests can't inherit each other's rate-limit tokens.
//
// Both servers answer their own liveness endpoint, so the handlers a test
// writes see only the paths that test cares about.
type escalateEnv struct {
	hopperReqs atomic.Int32
	litmusReqs atomic.Int32
}

func setupEscalate(t *testing.T, hopperFn, litmusFn http.HandlerFunc) *escalateEnv {
	t.Helper()
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	env := &escalateEnv{}
	health := func(next http.HandlerFunc, count *atomic.Int32) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" || r.URL.Path == "/_/health" {
				w.WriteHeader(http.StatusOK)
				return
			}
			count.Add(1)
			if next == nil {
				http.Error(w, "unexpected request", http.StatusInternalServerError)
				return
			}
			next(w, r)
		}
	}
	hopperSrv := httptest.NewServer(health(hopperFn, &env.hopperReqs))
	litmusSrv := httptest.NewServer(health(litmusFn, &env.litmusReqs))
	t.Cleanup(hopperSrv.Close)
	t.Cleanup(litmusSrv.Close)

	oldAPI, oldHopperClient := hopperAPIAddr, hopperClient
	oldLitmus, oldLitmusClient := litmusAddr, litmusClient
	oldStatus, oldCache, oldLimiter := backendStatus, cache, escalateLimiter
	t.Cleanup(func() {
		hopperAPIAddr, hopperClient = oldAPI, oldHopperClient
		litmusAddr, litmusClient = oldLitmus, oldLitmusClient
		backendStatus, cache, escalateLimiter = oldStatus, oldCache, oldLimiter
	})

	hopperAPIAddr, hopperClient = hopperSrv.URL, hopperSrv.Client()
	litmusAddr, litmusClient = litmusSrv.URL, litmusSrv.Client()
	cache = openNullCache[storedResult]("escalation test cache")
	escalateLimiter = newTokenBucket(1.0, 10)

	backendStatus = newBackendAvailabilityMonitor(hopperSrv.URL, litmusSrv.URL, hopperSrv.Client())
	backendStatus.refresh(context.Background())
	if !hopperAPIAvailable() || !litmusAvailable() {
		t.Fatal("test backends did not probe healthy")
	}
	return env
}

// withoutEscalateScan applies the --no-escalate-scan override for one test.
func withoutEscalateScan(t *testing.T) {
	t.Helper()
	old := noEscalateScan
	noEscalateScan = true
	t.Cleanup(func() { noEscalateScan = old })
}

// TestEscalatePromotes asserts the always-on half: a waited-on sample is
// promoted through hopper's rescan API. With the local scan overridden off,
// that is the whole of it — no bytes move.
func TestEscalatePromotes(t *testing.T) {
	withoutEscalateScan(t)

	var path, method string
	env := setupEscalate(t, func(w http.ResponseWriter, r *http.Request) {
		path, method = r.URL.Path, r.Method
		if _, err := w.Write([]byte(`{"status":"queued"}`)); err != nil {
			t.Errorf("write: %v", err)
		}
	}, nil)

	escalate(context.Background(), testSHA, "nbpl-0.1.2-py3-none-any.whl", logger)

	if want := "/api/rescan/" + testSHA; path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if method != http.MethodPost {
		t.Errorf("method = %q, want POST", method)
	}
	if got := env.hopperReqs.Load(); got != 1 {
		t.Errorf("hopper requests = %d, want 1 (promotion only)", got)
	}
	if got := env.litmusReqs.Load(); got != 0 {
		t.Errorf("litmus requests = %d, want 0 with --no-escalate-scan", got)
	}
}

// TestEscalateScansLocally covers the default path end to end: fetch the sample
// from hopper-api, analyze it on the scan server, publish the verdict back. No
// flag is set — a configured, healthy scan server is the whole opt-in.
func TestEscalateScansLocally(t *testing.T) {
	// The sample's identity is its content, so the fixture derives one from the
	// other — the integrity check in fetchSampleBytes rejects any pairing that lies.
	const body = "sample bytes"
	sum := sha256.Sum256([]byte(body))
	sha := hex.EncodeToString(sum[:])

	var published []byte
	var gotFilename string
	env := setupEscalate(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/rescan/"):
			if _, err := w.Write([]byte(`{"status":"queued"}`)); err != nil {
				t.Errorf("write: %v", err)
			}
		case r.URL.Path == "/api/file/"+sha:
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write: %v", err)
			}
		case r.URL.Path == "/api/result":
			raw, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read published result: %v", err)
			}
			published = raw
			if _, err := w.Write([]byte(`{"ok":true}`)); err != nil {
				t.Errorf("write: %v", err)
			}
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/analyze" {
			http.Error(w, "unexpected litmus path "+r.URL.Path, http.StatusNotFound)
			return
		}
		if err := r.ParseMultipartForm(1 << 20); err == nil {
			if fhs := r.MultipartForm.File["file"]; len(fhs) > 0 {
				gotFilename = fhs[0].Filename
			}
		}
		if _, err := w.Write([]byte(`{"ml":{"class":2,"prob":0.97},"raw":{}}`)); err != nil {
			t.Errorf("write: %v", err)
		}
	})

	escalate(context.Background(), sha, "nbpl-0.1.2-py3-none-any.whl", logger)

	if got := env.litmusReqs.Load(); got != 1 {
		t.Fatalf("litmus requests = %d, want 1", got)
	}
	if gotFilename != "nbpl-0.1.2-py3-none-any.whl" {
		t.Errorf("filename sent to litmus = %q, want the sample's name", gotFilename)
	}
	if len(published) == 0 {
		t.Fatal("no result published to hopper")
	}
	if !bytes.Contains(published, []byte(sha)) {
		t.Errorf("published result does not name the sample: %s", published)
	}
	if !bytes.Contains(published, []byte(litmusWorkerName)) {
		t.Errorf("published result does not identify prism as the worker: %s", published)
	}
}

// TestEscalateStopsWhenHopperRefuses asserts nothing is analyzed unless hopper
// accepted the promotion first. A hard failure means the verdict could not be
// published anyway; a 409 may mean the SHA is an archive child, whose
// cleave_result belongs to the reassembly of its parent and must not be written
// directly. Neither is distinguishable from prism, so both stop.
func TestEscalateStopsWhenHopperRefuses(t *testing.T) {
	// 400 rather than 5xx so the shared apiBreaker stays closed for other tests.
	cases := map[string]int{
		"hard failure": http.StatusBadRequest,
		"not eligible": http.StatusConflict,
	}
	for name, status := range cases {
		t.Run(name, func(t *testing.T) {
			env := setupEscalate(t, func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasPrefix(r.URL.Path, "/api/rescan/") {
					t.Errorf("unexpected hopper path %q after a refused promotion", r.URL.Path)
				}
				http.Error(w, `{"error":"refused"}`, status)
			}, nil)

			escalate(context.Background(), testSHA, "x.whl", logger)

			if got := env.litmusReqs.Load(); got != 0 {
				t.Errorf("litmus requests = %d, want 0 after a refused promotion", got)
			}
			if got := env.hopperReqs.Load(); got != 1 {
				t.Errorf("hopper requests = %d, want 1 (the refused promotion)", got)
			}
		})
	}
}

// TestEscalateDedupesPerSHA asserts N tabs on one pending sample cost one
// promotion, not N.
func TestEscalateDedupesPerSHA(t *testing.T) {
	withoutEscalateScan(t) // count promotions, not the scan path's fetches

	arrived, release := make(chan struct{}, 1), make(chan struct{})
	env := setupEscalate(t, func(w http.ResponseWriter, _ *http.Request) {
		arrived <- struct{}{}
		<-release
		if _, err := w.Write([]byte(`{"status":"queued"}`)); err != nil {
			t.Errorf("write: %v", err)
		}
	}, nil)

	// The first escalation parks inside the promotion POST, holding the per-SHA
	// marker, while the rest arrive and must find it taken.
	var wg sync.WaitGroup
	wg.Go(func() { escalate(context.Background(), testSHA, "x.whl", logger) })
	<-arrived
	for range 8 {
		wg.Go(func() { escalate(context.Background(), testSHA, "x.whl", logger) })
	}
	close(release)
	wg.Wait()

	if got := env.hopperReqs.Load(); got != 1 {
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
	withoutEscalateScan(t) // count promotions, not the scan path's fetches

	env := setupEscalate(t, func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte(`{"status":"queued"}`)); err != nil {
			t.Errorf("write: %v", err)
		}
	}, nil)
	escalateLimiter = newTokenBucket(0, 2) // two tokens, no refill

	for i := range 6 {
		sha := strings.Repeat("a", 63) + string(rune('0'+i))
		escalate(context.Background(), sha, "x.whl", logger)
	}

	if got := env.hopperReqs.Load(); got != 2 {
		t.Errorf("hopper requests = %d, want 2 (the burst) out of 6 escalations", got)
	}
}

// TestEscalateSurvivesDeadScanServer covers the window between a scan server
// dying and the 15-second health probe noticing: the availability check still
// says healthy, so escalation commits to the scan path and the connection is
// refused underneath it.
//
// What must hold is that the floor survives — the promotion already landed, so
// the sample is queued for hopper's own workers — and that a failed analysis
// publishes nothing. Marking a sample analyzed on the strength of a verdict
// that was never produced would be far worse than the delay it saves.
func TestEscalateSurvivesDeadScanServer(t *testing.T) {
	// Real bytes for a real digest: the fetch must succeed so the failure under
	// test is the scan server's, not the integrity check's.
	const body = "sample bytes"
	sum := sha256.Sum256([]byte(body))
	sha := hex.EncodeToString(sum[:])

	var promoted, published, fetched atomic.Int32
	setupEscalate(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/rescan/"):
			promoted.Add(1)
			if _, err := w.Write([]byte(`{"status":"queued"}`)); err != nil {
				t.Errorf("write: %v", err)
			}
		case r.URL.Path == "/api/file/"+sha:
			fetched.Add(1)
			if _, err := w.Write([]byte(body)); err != nil {
				t.Errorf("write: %v", err)
			}
		case r.URL.Path == "/api/result":
			published.Add(1)
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}, nil)

	// Point the analyze call at a closed port while the probe still reports the
	// server healthy — the state a just-died scan server leaves behind.
	litmusAddr = "127.0.0.1:1" // restored by setupEscalate's cleanup
	if !litmusAvailable() {
		t.Fatal("probe should still read healthy; the test is not exercising the window it claims to")
	}

	escalate(context.Background(), sha, "nbpl-0.1.2-py3-none-any.whl", logger)

	if got := promoted.Load(); got != 1 {
		t.Errorf("promotions = %d, want 1: the queue floor must hold when the scan server is down", got)
	}
	if got := fetched.Load(); got != 1 {
		t.Fatalf("sample fetches = %d, want 1 — the test must reach the dead scan server, not stop short of it", got)
	}
	if got := published.Load(); got != 0 {
		t.Errorf("publishes = %d, want 0: a failed analysis must never mark a sample analyzed", got)
	}
	// The slot is returned, so the next escalation and every upload can still
	// take one.
	if len(litmusSlots) != 0 {
		t.Errorf("held scan slots = %d, want 0 after a failed analysis", len(litmusSlots))
	}
	if _, busy := escalating.Load(sha); busy {
		t.Error("in-flight marker outlived a failed escalation")
	}
}

// TestScanLocallyOverride asserts --no-escalate-scan keeps the scan server for
// uploads only, leaving escalated samples to hopper's workers.
func TestScanLocallyOverride(t *testing.T) {
	withoutEscalateScan(t)
	env := setupEscalate(t, nil, nil)

	scanLocally(context.Background(), testSHA, "x.whl", logger)

	if got := env.hopperReqs.Load() + env.litmusReqs.Load(); got != 0 {
		t.Errorf("backend requests = %d, want 0 with --no-escalate-scan", got)
	}
}

// TestScanLocallyNeedsAScanServer asserts the default derives from the litmus
// configuration rather than a second flag: with --litmus unset there is nowhere
// to send the sample, so escalation is promotion-only without anyone saying so.
func TestScanLocallyNeedsAScanServer(t *testing.T) {
	env := setupEscalate(t, nil, nil)
	litmusAddr = "" // restored by setupEscalate's cleanup

	scanLocally(context.Background(), testSHA, "x.whl", logger)

	if got := env.hopperReqs.Load() + env.litmusReqs.Load(); got != 0 {
		t.Errorf("backend requests = %d, want 0 with no scan server configured", got)
	}
}

// TestScanLocallyShedsWhenSlotsFull asserts escalation loses the race for a
// scan slot rather than queueing behind uploads, which are someone waiting on
// a redirect.
func TestScanLocallyShedsWhenSlotsFull(t *testing.T) {
	env := setupEscalate(t, nil, nil)

	for range cap(litmusSlots) {
		litmusSlots <- struct{}{}
	}
	defer func() {
		for range cap(litmusSlots) {
			<-litmusSlots
		}
	}()

	scanLocally(context.Background(), testSHA, "x.whl", logger)

	if got := env.hopperReqs.Load() + env.litmusReqs.Load(); got != 0 {
		t.Errorf("backend requests = %d, want 0 when every scan slot is busy", got)
	}
}

// TestSampleBytesEnforcesLimit asserts the ceiling is enforced on the bytes
// actually read. The response below declares no length at all — prism never
// consults Content-Length, so a missing or dishonest one cannot talk it into an
// unbounded read.
func TestSampleBytesEnforcesLimit(t *testing.T) {
	setupEscalate(t, func(w http.ResponseWriter, _ *http.Request) {
		chunk := bytes.Repeat([]byte("A"), 1<<20)
		for range (escalateScanMaxBytes >> 20) + 1 {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}, nil)

	if _, err := fetchSampleBytes(context.Background(), testSHA); !errors.Is(err, errSampleTooLarge) {
		t.Fatalf("fetchSampleBytes = %v, want errSampleTooLarge", err)
	}
}

// TestSampleBytesRejectsMismatchedContent is the integrity check that makes a
// published verdict trustworthy. prism asks hopper-api for one sha and files an
// analysis against that sha's authoritative row; if the bytes that came back
// were some other sample, the verdict would describe a file nobody scanned and
// would stick, because hopper does not re-queue a row that looks analyzed.
func TestSampleBytesRejectsMismatchedContent(t *testing.T) {
	setupEscalate(t, func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write([]byte("bytes of some entirely different sample")); err != nil {
			t.Errorf("write: %v", err)
		}
	}, nil)

	if _, err := fetchSampleBytes(context.Background(), testSHA); !errors.Is(err, errSampleMismatch) {
		t.Fatalf("fetchSampleBytes = %v, want errSampleMismatch", err)
	}
}

// TestSampleBytesAcceptsMatchingContent pins the other side of the check, so a
// hash comparison that never matches can't pass as a working integrity guard.
func TestSampleBytesAcceptsMatchingContent(t *testing.T) {
	const body = "the real sample bytes"
	sum := sha256.Sum256([]byte(body))
	sha := hex.EncodeToString(sum[:])

	setupEscalate(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/file/"+sha {
			t.Errorf("path = %q, want the requested sha", r.URL.Path)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Errorf("write: %v", err)
		}
	}, nil)

	buf, err := fetchSampleBytes(context.Background(), sha)
	if err != nil {
		t.Fatalf("fetchSampleBytes: %v", err)
	}
	if string(buf) != body {
		t.Errorf("bytes = %q, want %q", buf, body)
	}
}

// TestEscalateRejectsMalformedSHA asserts the defence-in-depth guard: a sha that
// never passed a handler's validation reaches no upstream at all, so it can
// never be interpolated into a hopper-api URL path.
func TestEscalateRejectsMalformedSHA(t *testing.T) {
	env := setupEscalate(t, nil, nil)

	for _, bad := range []string{"", "../../etc/passwd", strings.Repeat("a", 63), strings.Repeat("z", 64), testSHA + "/x"} {
		escalate(context.Background(), bad, "x.whl", logger)
	}

	if got := env.hopperReqs.Load() + env.litmusReqs.Load(); got != 0 {
		t.Errorf("backend requests = %d, want 0 for malformed input", got)
	}
}

// TestSampleBytesSurfacesNotFound asserts a non-200 from hopper-api is an
// error rather than an empty sample handed to the scan server.
func TestSampleBytesSurfacesNotFound(t *testing.T) {
	setupEscalate(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}, nil)

	buf, err := fetchSampleBytes(context.Background(), testSHA)
	if err == nil {
		t.Fatalf("fetchSampleBytes = %d bytes, want an error", len(buf))
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error = %v, want it to name the status", err)
	}
}
