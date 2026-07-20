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

// TestHandleStatsNoHopper verifies the endpoint degrades to a 503 JSON error
// (never a panic or 500) when hopper is not connected, and always sets the
// JSON + no-store headers so a polling client can distinguish "not ready" from
// a real value.
func TestHandleStatsNoHopper(t *testing.T) {
	old := hopperDB.Load()
	hopperDB.Store(nil)
	t.Cleanup(func() { hopperDB.Store(old) })

	rec := httptest.NewRecorder()
	handleStats(rec, httptest.NewRequest(http.MethodGet, "/_/stats", http.NoBody))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
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
	if _, ok := body["error"]; !ok {
		t.Errorf("expected an \"error\" field, got %v", body)
	}
}

// TestUploadTemplateRendersCounter renders the masthead with a populated Stats
// snapshot and asserts the counter's server-rendered value and the data-*
// attributes the client extrapolates from are present and correct.
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
			WindowSecs:  900,
		},
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`id="index-counter"`,
		`data-total="2847213"`,      // raw anchor for the client
		`data-asof="1700000000000"`, // GeneratedAt.UnixMilli, for extrapolation
		`2,847,213`,                 // commaInt-formatted server-rendered value
		`id="counter-meter"`,        // peak-meter mount point
		"Samples analyzed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered masthead is missing %q", want)
		}
	}
}
