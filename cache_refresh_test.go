package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFeedPopularityTopRanks confirms the hot-tier tracker ranks by observed
// traffic, collapses the domain dimension into the plain ecosystem view, and
// excludes one-off search/formula queries.
func TestFeedPopularityTopRanks(t *testing.T) {
	p := &feedPopularity{counts: make(map[feedQueryArgs]uint64)}

	for range 5 {
		p.record(feedQueryArgs{ecosystem: "npm", criticality: "hostile"})
	}
	for range 3 {
		p.record(feedQueryArgs{ecosystem: "pypi"})
	}
	// A domain-filtered npm visit folds into the plain npm/hostile view.
	p.record(feedQueryArgs{ecosystem: "npm", criticality: "hostile", domain: "evil.test"})
	// Free-text and formula queries are never tracked.
	p.record(feedQueryArgs{search: "malware.js"})
	p.record(feedQueryArgs{formula: "C6H12O6"})

	top := p.top(10)
	if len(top) != 2 {
		t.Fatalf("want 2 tracked pivots (search/formula excluded), got %d: %+v", len(top), top)
	}
	if top[0].ecosystem != "npm" || top[0].criticality != "hostile" {
		t.Errorf("top pivot = %+v, want npm/hostile (6 hits)", top[0])
	}
	if top[0].domain != "" {
		t.Errorf("domain should be collapsed out of the key, got %q", top[0].domain)
	}
	if top[1].ecosystem != "pypi" {
		t.Errorf("second pivot = %+v, want pypi (3 hits)", top[1])
	}
}

// TestFeedPopularityCap confirms the tracker stops admitting new keys past the
// cap, so cycling distinct pivots can't grow it without bound.
func TestFeedPopularityCap(t *testing.T) {
	p := &feedPopularity{counts: make(map[feedQueryArgs]uint64)}
	for i := range feedPopularityCap + 50 {
		p.record(feedQueryArgs{ecosystem: "eco" + string(rune('a'+i%26)) + itoaTest(i)})
	}
	if len(p.counts) > feedPopularityCap {
		t.Errorf("counts grew past cap: %d > %d", len(p.counts), feedPopularityCap)
	}
}

func itoaTest(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// TestIsHardRefresh pins the hard-reload detection: a hard refresh sends
// Cache-Control: no-cache (or Pragma: no-cache); a normal reload sends
// max-age=0, which must NOT count so it still serves from cache.
func TestIsHardRefresh(t *testing.T) {
	cases := []struct {
		name         string
		cacheControl string
		pragma       string
		want         bool
	}{
		{"hard reload cache-control", "no-cache", "", true},
		{"hard reload pragma", "", "no-cache", true},
		{"chrome hard reload both", "no-cache", "no-cache", true},
		{"normal reload", "max-age=0", "", false},
		{"plain navigation", "", "", false},
		{"mixed directives", "no-cache, no-store", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/file/abc", http.NoBody)
			if tc.cacheControl != "" {
				r.Header.Set("Cache-Control", tc.cacheControl)
			}
			if tc.pragma != "" {
				r.Header.Set("Pragma", tc.pragma)
			}
			if got := isHardRefresh(r); got != tc.want {
				t.Errorf("isHardRefresh(cc=%q pragma=%q) = %v, want %v", tc.cacheControl, tc.pragma, got, tc.want)
			}
		})
	}
}
