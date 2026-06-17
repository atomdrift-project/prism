package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLitmusAnalyzeURL(t *testing.T) {
	old := litmusAddr
	defer func() { litmusAddr = old }()

	cases := []struct {
		addr string
		want string
	}{
		{"litmus:49999", "http://litmus:49999/analyze"},
		{"http://litmus:49999", "http://litmus:49999/analyze"},
		{"https://litmus.internal/x/", "https://litmus.internal/x/analyze"},
		{"", ""},
	}
	for _, c := range cases {
		litmusAddr = c.addr
		if got := litmusAnalyzeURL(); got != c.want {
			t.Errorf("litmusAnalyzeURL(%q) = %q, want %q", c.addr, got, c.want)
		}
	}
}

func TestHopperResultURL(t *testing.T) {
	old := hopperAPIAddr
	defer func() { hopperAPIAddr = old }()

	hopperAPIAddr = "hopper-api:8081"
	if got, want := hopperResultURL(), "http://hopper-api:8081/api/result"; got != want {
		t.Errorf("hopperResultURL() = %q, want %q", got, want)
	}
	hopperAPIAddr = ""
	if got, want := hopperResultURL(), "http://"+defaultHopperAPIAddr+"/api/result"; got != want {
		t.Errorf("hopperResultURL() empty = %q, want %q", got, want)
	}
}

// TestAnalyzeWithLitmus drives a fake litmus /analyze: it must receive the
// file as a multipart "file" part and its ml/raw envelope must round-trip.
func TestAnalyzeWithLitmus(t *testing.T) {
	old := litmusClient
	defer func() { litmusClient = old }()
	litmusClient = &http.Client{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, hdr, err := r.FormFile("file")
		if err != nil {
			http.Error(w, `{"error":"no file"}`, http.StatusBadRequest)
			return
		}
		defer func() {
			if cerr := f.Close(); cerr != nil {
				t.Errorf("close file part: %v", cerr)
			}
		}()
		if hdr.Filename != "sample.bin" {
			t.Errorf("filename = %q, want sample.bin", hdr.Filename)
		}
		got, err := io.ReadAll(f)
		if err != nil {
			t.Errorf("read file part: %v", err)
		}
		if string(got) != "PAYLOAD" {
			t.Errorf("uploaded bytes = %q, want PAYLOAD", got)
		}
		if _, err := w.Write([]byte(`{"ml":{"v":"7","lvl":-1},"raw":{"files":[]}}`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer srv.Close()

	env, err := analyzeWithLitmus(context.Background(), srv.URL+"/analyze", []byte("PAYLOAD"), "sample.bin")
	if err != nil {
		t.Fatalf("analyzeWithLitmus: %v", err)
	}
	if !json.Valid(env.ML) || !strings.Contains(string(env.ML), `"lvl":-1`) {
		t.Errorf("ml = %s, want the litmus ml section", env.ML)
	}
	if !json.Valid(env.Raw) {
		t.Errorf("raw = %s, want valid json", env.Raw)
	}
}

func TestAnalyzeWithLitmusErrors(t *testing.T) {
	old := litmusClient
	defer func() { litmusClient = old }()
	litmusClient = &http.Client{}

	cases := []struct {
		name   string
		body   string
		status int
	}{
		{name: "non_200", status: http.StatusServiceUnavailable, body: `{"error":"saturated"}`},
		{name: "error_body", status: http.StatusOK, body: `{"error":"unsupported file"}`},
		{name: "missing_ml", status: http.StatusOK, body: `{"raw":{}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(c.status)
				if _, err := w.Write([]byte(c.body)); err != nil {
					t.Errorf("write response: %v", err)
				}
			}))
			defer srv.Close()
			if _, err := analyzeWithLitmus(context.Background(), srv.URL+"/analyze", []byte("x"), "f"); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

// TestStoredResultFromLitmus confirms a litmus /analyze envelope becomes a
// cacheable result the renderer can use without hopper: RawLitmus carries the
// {ml,raw} envelope, classification is derived from ml, and size/timestamps
// are populated.
func TestStoredResultFromLitmus(t *testing.T) {
	env := &litmusEnvelope{
		ML:  json.RawMessage(`{"v":"7","lvl":-1,"conf":0}`),
		Raw: json.RawMessage(`{"files":[{"sha":"abc","type":"crate"}]}`),
	}
	res := storedResultFromLitmus("onering-1.4.1.crate", env, 4096)

	if res.Filename != "onering-1.4.1.crate" {
		t.Errorf("filename = %q", res.Filename)
	}
	if res.SizeBytes != 4096 {
		t.Errorf("size = %d, want 4096", res.SizeBytes)
	}
	if res.AnalyzedAt.IsZero() || res.CachedAt.IsZero() {
		t.Error("timestamps must be set so the result renders as analyzed")
	}
	// RawLitmus must be the {ml,raw} envelope prepareResultData parses.
	var env2 struct {
		ML  json.RawMessage `json:"ml"`
		Raw json.RawMessage `json:"raw"`
	}
	if err := json.Unmarshal([]byte(res.RawLitmus), &env2); err != nil {
		t.Fatalf("RawLitmus not valid envelope JSON: %v", err)
	}
	if !strings.Contains(string(env2.ML), `"lvl":-1`) {
		t.Errorf("envelope ml = %s, want litmus ml section", env2.ML)
	}
	if !strings.Contains(string(env2.Raw), `"crate"`) {
		t.Errorf("envelope raw = %s, want cleave raw section", env2.Raw)
	}
}

// TestStoredResultFromLitmusDropsInvalid ensures malformed ml/raw don't poison
// the envelope (omitted rather than embedded as broken JSON).
func TestStoredResultFromLitmusDropsInvalid(t *testing.T) {
	env := &litmusEnvelope{ML: json.RawMessage(`not json`), Raw: json.RawMessage(`{"ok":true}`)}
	res := storedResultFromLitmus("x", env, 1)
	if !json.Valid([]byte(res.RawLitmus)) {
		t.Fatalf("RawLitmus must stay valid JSON, got %q", res.RawLitmus)
	}
	if strings.Contains(res.RawLitmus, "not json") {
		t.Errorf("invalid ml leaked into envelope: %s", res.RawLitmus)
	}
}

// TestLitmusSlotsBounded verifies the fast-path semaphore admits exactly
// maxConcurrentLitmus tokens and then refuses (non-blocking), which is what
// makes a saturated fast path degrade to hopper instead of queueing work.
func TestLitmusSlotsBounded(t *testing.T) {
	if cap(litmusSlots) != maxConcurrentLitmus {
		t.Fatalf("litmusSlots cap = %d, want %d", cap(litmusSlots), maxConcurrentLitmus)
	}
	// Fill every slot.
	for i := range maxConcurrentLitmus {
		select {
		case litmusSlots <- struct{}{}:
		default:
			t.Fatalf("slot %d should have been free", i)
		}
	}
	// The next acquire must fail without blocking.
	select {
	case litmusSlots <- struct{}{}:
		t.Error("acquired a slot past capacity; semaphore is not bounding concurrency")
		<-litmusSlots
	default:
	}
	// Drain so the shared global is clean for other tests.
	for range maxConcurrentLitmus {
		<-litmusSlots
	}
}

// TestPublishResultToHopper asserts prism posts the worker-shaped payload to
// hopper /api/result and that a rejection surfaces as an error.
func TestPublishResultToHopper(t *testing.T) {
	oldClient, oldAddr := hopperClient, hopperAPIAddr
	defer func() { hopperClient, hopperAPIAddr = oldClient, oldAddr }()
	hopperClient = &http.Client{}

	sha := strings.Repeat("a", 64)
	var got hopperResultRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/result" {
			t.Errorf("path = %q, want /api/result", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		if _, err := w.Write([]byte(`{"ok":true}`)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer srv.Close()
	hopperAPIAddr = srv.URL

	env := &litmusEnvelope{ML: json.RawMessage(`{"lvl":-1}`), Raw: json.RawMessage(`{"files":[]}`)}
	if err := publishResultToHopper(context.Background(), sha, env, 1234); err != nil {
		t.Fatalf("publishResultToHopper: %v", err)
	}
	if got.SHA256 != sha {
		t.Errorf("sha256 = %q, want %q", got.SHA256, sha)
	}
	if got.Worker != litmusWorkerName {
		t.Errorf("worker = %q, want %q", got.Worker, litmusWorkerName)
	}
	if got.DurationMs != 1234 {
		t.Errorf("duration_ms = %d, want 1234", got.DurationMs)
	}
	if string(got.ML) != `{"lvl":-1}` {
		t.Errorf("ml = %s, want forwarded litmus ml", got.ML)
	}
}

func TestPublishResultToHopperRejected(t *testing.T) {
	oldClient, oldAddr := hopperClient, hopperAPIAddr
	defer func() { hopperClient, hopperAPIAddr = oldClient, oldAddr }()
	hopperClient = &http.Client{}

	// 400 keeps the breaker closed (success() fires for <500) so this test
	// stays independent of breaker state.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"unknown sample"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	hopperAPIAddr = srv.URL

	env := &litmusEnvelope{ML: json.RawMessage(`{"lvl":0}`)}
	if err := publishResultToHopper(context.Background(), strings.Repeat("b", 64), env, 0); err == nil {
		t.Error("expected error on non-200 response, got nil")
	}
}
