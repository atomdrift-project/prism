package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCommaInt(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0"},
		{7, "7"},
		{42, "42"},
		{999, "999"},
		{1000, "1,000"},
		{12400, "12,400"},
		{999999, "999,999"},
		{2847213, "2,847,213"},
		{1000000, "1,000,000"},
		{-1234, "-1,234"},
		{-1000000, "-1,000,000"},
	}
	for _, tc := range cases {
		if got := commaInt(tc.in); got != tc.want {
			t.Errorf("commaInt(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestHandleStatsCold verifies that before the poller has published a snapshot
// the endpoint responds fast with {"ready":false} and the JSON + no-store
// headers — never a hang or a 5xx — so a polling client just keeps trying.
func TestHandleStatsCold(t *testing.T) {
	old := statsLatest.Load()
	statsLatest.Store(nil)
	t.Cleanup(func() { statsLatest.Store(old) })

	rec := httptest.NewRecorder()
	handleStats(rec, httptest.NewRequest(http.MethodGet, "/_/stats", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not valid JSON: %v (%q)", err, rec.Body.String())
	}
	if ready, ok := body["ready"].(bool); !ok || ready {
		t.Errorf("expected ready=false, got %v", body)
	}
	if _, hasTotal := body["total"]; hasTotal {
		t.Errorf("cold response should not carry a total, got %v", body)
	}
}

// TestHandleStatsWarm verifies the JSON shape once the poller has published an
// exact snapshot: the total exactly as counted, and as_of in unix millis. The
// total is served verbatim — there is no rate and nothing is projected onto it.
func TestHandleStatsWarm(t *testing.T) {
	old := statsLatest.Load()
	statsLatest.Store(&indexStats{
		GeneratedAt: time.Now().UTC(),
		Total:       2847213,
	})
	t.Cleanup(func() { statsLatest.Store(old) })

	rec := httptest.NewRecorder()
	handleStats(rec, httptest.NewRequest(http.MethodGet, "/_/stats", http.NoBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not valid JSON: %v (%q)", err, rec.Body.String())
	}
	if got, ok := body["total"].(float64); !ok || int64(got) != 2847213 {
		t.Errorf("total = %v, want 2847213", body["total"])
	}
	if _, hasRate := body["rate_per_min"]; hasRate {
		t.Errorf("response should not carry a rate, got %v", body)
	}
	gotAsOf, ok := body["as_of"].(float64)
	if !ok {
		t.Fatalf("as_of missing: %v", body)
	}
	if drift := time.Since(time.UnixMilli(int64(gotAsOf))); drift > 2*time.Second || drift < -2*time.Second {
		t.Errorf("as_of drift = %s, want ~now", drift)
	}
}

// TestHandleStatsDoesNotProject pins the contract that replaced the old
// between-poll projection: however stale the snapshot is, /_/stats returns the
// counted total unchanged. The trailing "+" in the masthead is what stands in
// for rows ingested since — the server never invents digits.
func TestHandleStatsDoesNotProject(t *testing.T) {
	old := statsLatest.Load()
	statsLatest.Store(&indexStats{
		GeneratedAt: time.Now().UTC().Add(-3 * statsPollInterval),
		Total:       100000,
	})
	t.Cleanup(func() { statsLatest.Store(old) })

	rec := httptest.NewRecorder()
	handleStats(rec, httptest.NewRequest(http.MethodGet, "/_/stats", http.NoBody))

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	got, ok := body["total"].(float64)
	if !ok {
		t.Fatalf("total missing: %v", body)
	}
	if int64(got) != 100000 {
		t.Errorf("total = %v, want 100000 (stale snapshot served verbatim)", got)
	}
	asOf, ok := body["as_of"].(float64)
	if !ok {
		t.Fatalf("as_of missing: %v", body)
	}
	// as_of must report when the count was taken, not when it was served, so a
	// client (or /_/metrik) can tell a fresh number from a stuck poller.
	if age := time.Since(time.UnixMilli(int64(asOf))); age < 2*statsPollInterval {
		t.Errorf("as_of age = %s, want the snapshot's own age (~%s)", age, 3*statsPollInterval)
	}
}

// TestUploadTemplateRendersCounter renders the masthead with a populated Stats
// snapshot and asserts the counter's server-rendered value and the data-*
// attributes the client seeds from are present and correct.
func TestUploadTemplateRendersCounter(t *testing.T) {
	tmpl := uploadTemplateForTest(t)
	var buf bytes.Buffer
	data := feedPageData{
		HasHopper:    true,
		SelectedCrit: ">=1",
		Stats: &indexStats{
			GeneratedAt: time.Unix(1_700_000_000, 0).UTC(),
			Total:       2847213,
		},
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`id="index-counter"`,
		`data-total="2847213"`, // published total, for the client's first paint
		`2,847,213+`,           // commaInt-formatted value with the "+" suffix
		"Files indexed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered masthead is missing %q", want)
		}
	}
}
