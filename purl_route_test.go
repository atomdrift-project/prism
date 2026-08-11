package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPURLRoutes covers the redirecting edges of the record-by-Package-URL
// path: a degenerate coordinate (no name) drops to the frontpage instead of
// a dead filter, and a first segment that isn't a plausible ecosystem (e.g.
// a pasted pkg: scheme) keeps the ecosystem route's old redirect-home
// behavior. The direct /file/{sha} redirect needs a live hopper sample to
// pin exactly one record, so it isn't reachable here.
func TestPURLRoutes(t *testing.T) {
	mux := newMux()
	tests := []struct {
		path string
		want string
	}{
		{"/npm/%20", "/"},
		{"/pkg:npm/lodash@4.17.21", "/"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, tt.path, http.NoBody))
			if rr.Code != http.StatusFound {
				t.Fatalf("GET %s = %d, want %d", tt.path, rr.Code, http.StatusFound)
			}
			if got := rr.Header().Get("Location"); got != tt.want {
				t.Errorf("GET %s redirects to %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

// TestPURLIndexURL covers the hero Package-row link target: the rooted path
// for a plain base, the ?purl= filter form when an identity qualifier's "?"
// can't survive a path round-trip, and empty for samples with no purl_base.
func TestPURLIndexURL(t *testing.T) {
	tests := []struct {
		base string
		want string
	}{
		{"pkg:npm/lodash", "/npm/lodash"},
		{"pkg:npm/@scope/pkg", "/npm/@scope/pkg"},
		{"pkg:golang/github.com/user/repo", "/golang/github.com/user/repo"},
		{
			"pkg:vscode-extension/pub/name?repository_url=https://open-vsx.org",
			"/?purl=pkg%3Avscode-extension%2Fpub%2Fname%3Frepository_url%3Dhttps%3A%2F%2Fopen-vsx.org",
		},
		{"", ""},
		{"not-a-purl", ""},
	}
	for _, tt := range tests {
		if got := purlIndexURL(tt.base); got != tt.want {
			t.Errorf("purlIndexURL(%q) = %q, want %q", tt.base, got, tt.want)
		}
	}
}

// TestPackageVersionIndex covers the in-place render: a URL that continues
// past the ecosystem segment is a package coordinate, and /npm/lodash (with
// or without a trailing slash or version) renders the feed filtered to that
// identity at its own URL — the package's version index. With no hopper DB
// the sole-sample shortcut can't fire, so every well-formed coordinate takes
// this path; the filled search box and og:title prove the filter and the
// coordinate's canonicalization survived the trip.
func TestPackageVersionIndex(t *testing.T) {
	uploadTemplate = uploadTemplateForTest(t)
	t.Cleanup(func() { uploadTemplate = nil })
	mux := newMux()
	tests := []struct {
		path string
		want string // canonical coordinate expected in the search box
	}{
		{"/npm/lodash", "purl:pkg:npm/lodash"},
		{"/npm/lodash/", "purl:pkg:npm/lodash"},
		{"/NPM/lodash@4.17.21", "purl:pkg:npm/lodash@4.17.21"},
		{"/npm/@scope/pkg@1.0.0", "purl:pkg:npm/@scope/pkg@1.0.0"},
		{"/golang/github.com/user/repo@v1.0.0", "purl:pkg:golang/github.com/user/repo@v1.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, tt.path, http.NoBody))
			if rr.Code != http.StatusOK {
				t.Fatalf("GET %s = %d, want %d", tt.path, rr.Code, http.StatusOK)
			}
			if body := rr.Body.String(); !strings.Contains(body, tt.want) {
				t.Errorf("GET %s body missing %q", tt.path, tt.want)
			}
		})
	}
}
