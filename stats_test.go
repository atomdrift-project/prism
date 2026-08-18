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

// TestHandleStatsCold verifies that before the poller has published an estimate
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
// estimate: total, rate rounded to one decimal, and as_of in unix millis.
// GeneratedAt is "now" so projectIndexStats does not add a poll-gap delta.
func TestHandleStatsWarm(t *testing.T) {
	old := statsLatest.Load()
	statsLatest.Store(&indexStats{
		GeneratedAt: time.Now().UTC(),
		Total:       2847213,
		RatePerMin:  128.34,
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
	if got, ok := body["rate_per_min"].(float64); !ok || got != 128.3 { // rounded to one decimal
		t.Errorf("rate_per_min = %v, want 128.3", body["rate_per_min"])
	}
	gotAsOf, ok := body["as_of"].(float64)
	if !ok {
		t.Fatalf("as_of missing: %v", body)
	}
	if drift := time.Since(time.UnixMilli(int64(gotAsOf))); drift > 2*time.Second || drift < -2*time.Second {
		t.Errorf("as_of drift = %s, want ~now", drift)
	}
}

// TestProjectIndexStats checks the between-poll projection: advance at the
// measured rate, never go backwards in time, and never invent more than one
// statsPollInterval of growth.
func TestProjectIndexStats(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_700_000_000, 0).UTC()
	snap := indexStats{GeneratedAt: base, Total: 1000, RatePerMin: 60} // 1/sec

	got := projectIndexStats(snap, base)
	if got.Total != 1000 || !got.GeneratedAt.Equal(base) {
		t.Errorf("zero elapsed: total=%d at %s, want 1000 at base", got.Total, got.GeneratedAt)
	}

	got = projectIndexStats(snap, base.Add(10*time.Second))
	if got.Total != 1010 {
		t.Errorf("10s elapsed: total=%d, want 1010", got.Total)
	}
	if !got.GeneratedAt.Equal(base.Add(10 * time.Second)) {
		t.Errorf("GeneratedAt = %s, want now", got.GeneratedAt)
	}

	got = projectIndexStats(snap, base.Add(-5*time.Second))
	if got.Total != 1000 {
		t.Errorf("clock skew: total=%d, want 1000 (no negative elapsed)", got.Total)
	}

	got = projectIndexStats(snap, base.Add(time.Hour))
	want := 1000 + int64(60*statsPollInterval.Minutes()) // 15s → +15
	if got.Total != want {
		t.Errorf("stale cap: total=%d, want %d (one poll interval)", got.Total, want)
	}
}

// TestHandleStatsProjectsPollGap verifies that /_/stats advances the published
// total by the 2h rate across a gap shorter than statsPollInterval, so a page
// load a few seconds after the poll is still live.
func TestHandleStatsProjectsPollGap(t *testing.T) {
	old := statsLatest.Load()
	statsLatest.Store(&indexStats{
		GeneratedAt: time.Now().UTC().Add(-10 * time.Second),
		Total:       100000,
		RatePerMin:  60, // 1/sec → +10 over 10s
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
	if got < 100009 || got > 100012 {
		t.Errorf("total = %v, want ~100010 (10s at 1/sec)", got)
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
			RatePerMin:  128.3,
		},
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`id="index-counter"`,
		`data-total="2847213"`,      // published total the client projects from
		`data-rate="128.3"`,         // 2h ingest rate for between-poll ticks
		`data-asof="1700000000000"`, // GeneratedAt.UnixMilli
		`2,847,213`,                 // commaInt-formatted server-rendered value
		`id="counter-meter"`,        // peak-meter mount point
		"Files indexed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered masthead is missing %q", want)
		}
	}
}
