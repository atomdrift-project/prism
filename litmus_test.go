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

func TestAnalyzeWithBeamline(t *testing.T) {
	oldAddr, oldClient := beamlineAPIAddr, beamlineClient
	defer func() { beamlineAPIAddr, beamlineClient = oldAddr, oldClient }()
	beamlineClient = &http.Client{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/analyze" {
			t.Errorf("path = %q, want /v1/analyze", r.URL.Path)
		}
		if got := r.URL.Query().Get("full"); got != "1" {
			t.Errorf("full query = %q, want 1", got)
		}
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		} else if string(got) != "PAYLOAD" {
			t.Errorf("body = %q, want PAYLOAD", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/octet-stream" {
			t.Errorf("content type = %q, want application/octet-stream", got)
		}
		w.Header().Set("X-Beamline-Worker", "scan-test")
		if _, err := w.Write([]byte("{\"state\":\"analyzing\"}\n{\"status\":\"analyzed\",\"sha256\":\"" + strings.Repeat("a", 64) + "\",\"fires_at\":-1}\n")); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	defer srv.Close()
	beamlineAPIAddr = srv.URL

	var frames []string
	assessment, err := analyzeWithBeamline(context.Background(), []byte("PAYLOAD"), "sample.bin", func(frame []byte) {
		frames = append(frames, string(frame))
	}, nil)
	if err != nil {
		t.Fatalf("analyzeWithBeamline: %v", err)
	}
	if assessment.Status != "analyzed" || assessment.SHA != strings.Repeat("a", 64) {
		t.Fatalf("assessment = %+v", assessment)
	}
	if assessment.Server != "scan-test" {
		t.Fatalf("server = %q, want scan-test", assessment.Server)
	}
	if len(frames) != 2 || frames[0] != `{"state":"analyzing"}` {
		t.Fatalf("frames = %#v, want both streamed Beamline frames", frames)
	}
}

func TestAnalyzeWithBeamlineAcceptsFullEnvelopeTerminal(t *testing.T) {
	oldAddr, oldClient := beamlineAPIAddr, beamlineClient
	defer func() { beamlineAPIAddr, beamlineClient = oldAddr, oldClient }()
	beamlineClient = &http.Client{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := io.WriteString(w, "{\"state\":\"analyzing\",\"phase\":\"unpack\"}\n{\"status\":\"analyzed\",\"ml\":{\"lvl\":-1},\"raw\":{\"files\":[]}}\n"); err != nil {
			return
		}
	}))
	defer srv.Close()
	beamlineAPIAddr = srv.URL

	assessment, err := analyzeWithBeamline(context.Background(), []byte("PAYLOAD"), "sample.bin", nil, nil)
	if err != nil {
		t.Fatalf("analyzeWithBeamline full envelope: %v", err)
	}
	if assessment.Status != "analyzed" || len(assessment.ML) == 0 || len(assessment.Raw) == 0 {
		t.Fatalf("assessment = %+v, want full terminal envelope", assessment)
	}
}

// TestStoredResultFromLitmus confirms an analysis envelope becomes a
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
