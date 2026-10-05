package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestFeedPopularityTopRanks confirms the hot-tier tracker ranks by observed
// traffic, collapses the domain dimension into the plain ecosystem view, and
// excludes one-off search/formula queries.
func TestFeedPopularityTopRanks(t *testing.T) {
	p := &feedPopularity{counts: make(map[feedQueryArgs]uint64)}

	for range 5 {
		p.record(&feedQueryArgs{ecosystem: "npm", criticality: "hostile"})
	}
	for range 3 {
		p.record(&feedQueryArgs{ecosystem: "pypi"})
	}
	// A domain-filtered npm visit folds into the plain npm/hostile view.
	p.record(&feedQueryArgs{ecosystem: "npm", criticality: "hostile", domain: "evil.test"})
	// Free-text and formula queries are never tracked.
	p.record(&feedQueryArgs{search: "malware.js"})
	p.record(&feedQueryArgs{formula: "C6H12O6"})

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
		p.record(&feedQueryArgs{ecosystem: "eco" + string(rune('a'+i%26)) + itoaTest(i)})
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
// max-age=0, which must NOT count so it still serves from cache. Only a browser
// navigation earns the bypass: monitors and scrapers send no-cache on every
// request and must keep being served from cache.
func TestIsHardRefresh(t *testing.T) {
	const (
		chrome  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
		firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:157.0) Gecko/20100101 Firefox/157.0"
		uptime  = "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)"
		gptbot  = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.4; +https://openai.com/gptbot)"
		curlUA  = "curl/8.10.1"
	)
	cases := []struct {
		name         string
		cacheControl string
		pragma       string
		secFetchMode string
		userAgent    string
		want         bool
	}{
		{"hard reload cache-control", "no-cache", "", "navigate", chrome, true},
		{"hard reload pragma", "", "no-cache", "navigate", chrome, true},
		{"chrome hard reload both", "no-cache", "no-cache", "navigate", chrome, true},
		{"firefox hard reload", "no-cache", "", "navigate", firefox, true},
		{"mixed directives", "no-cache, no-store", "", "navigate", chrome, true},
		{"normal reload", "max-age=0", "", "navigate", chrome, false},
		{"plain navigation", "", "", "navigate", chrome, false},
		{"uptimerobot", "no-cache", "", "", uptime, false},
		{"spoofed chrome without fetch metadata", "no-cache", "no-cache", "", chrome, false},
		{"fetch from script", "no-cache", "", "cors", chrome, false},
		{"self-identified bot in a browser", "no-cache", "", "navigate", gptbot, false},
		{"curl with fetch metadata", "no-cache", "", "navigate", curlUA, false},
		{"empty user agent", "no-cache", "", "navigate", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/file/abc", http.NoBody)
			r.Header.Set("User-Agent", tc.userAgent)
			if tc.cacheControl != "" {
				r.Header.Set("Cache-Control", tc.cacheControl)
			}
			if tc.pragma != "" {
				r.Header.Set("Pragma", tc.pragma)
			}
			if tc.secFetchMode != "" {
				r.Header.Set("Sec-Fetch-Mode", tc.secFetchMode)
			}
			if got := isHardRefresh(r); got != tc.want {
				t.Errorf("isHardRefresh(cc=%q pragma=%q mode=%q ua=%q) = %v, want %v",
					tc.cacheControl, tc.pragma, tc.secFetchMode, tc.userAgent, got, tc.want)
			}
		})
	}
}

// TestFeedCacheKeyWindow: a windowed query is a different snapshot from the
// unwindowed one and from every other window, or the fallout log's weeks would
// serve each other's rows.
func TestFeedCacheKeyWindow(t *testing.T) {
	base := feedQueryArgs{criticality: "hostile"}
	week := base
	week.since = time.Date(2026, 8, 3, 0, 0, 0, 0, time.UTC)
	week.until = time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	before := week
	before.since = week.since.AddDate(0, 0, -7)
	before.until = week.until.AddDate(0, 0, -7)

	keys := map[string]string{
		"unwindowed":      feedCacheKey(&base),
		"a week":          feedCacheKey(&week),
		"the week before": feedCacheKey(&before),
	}
	seen := make(map[string]string, len(keys))
	for name, key := range keys {
		if other, dup := seen[key]; dup {
			t.Errorf("%s and %s share cache key %q", name, other, key)
		}
		seen[key] = name
	}

	// The same window expressed in another zone is the same instant, so it
	// must not fragment the cache.
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("no zone database: %v", err)
	}
	shifted := week
	shifted.since = week.since.In(ny)
	shifted.until = week.until.In(ny)
	if feedCacheKey(&shifted) != feedCacheKey(&week) {
		t.Errorf("the same instants in another zone keyed differently:\n %q\n %q",
			feedCacheKey(&shifted), feedCacheKey(&week))
	}
}

// TestFeedCacheTTLFor: a window that has already closed can never gain a row,
// so it is held long; anything still open keeps the working TTL.
func TestFeedCacheTTLFor(t *testing.T) {
	now := time.Now()
	closed := feedQueryArgs{criticality: "hostile", since: now.AddDate(0, 0, -14), until: now.AddDate(0, 0, -7)}
	if got := feedCacheTTLFor(&closed); got != feedArchiveTTL {
		t.Errorf("closed window TTL = %v, want %v", got, feedArchiveTTL)
	}
	open := feedQueryArgs{criticality: "hostile", since: now.AddDate(0, 0, -2), until: now.AddDate(0, 0, 5)}
	if got := feedCacheTTLFor(&open); got != feedCacheTTL {
		t.Errorf("open window TTL = %v, want %v", got, feedCacheTTL)
	}
	if got := feedCacheTTLFor(&feedQueryArgs{}); got != feedCacheTTL {
		t.Errorf("unwindowed TTL = %v, want %v", got, feedCacheTTL)
	}
}
