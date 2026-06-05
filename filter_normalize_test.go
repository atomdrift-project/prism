package main

import (
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestNormalizeSearch covers the ?q= canonicalization: trim, collapse internal
// whitespace, lowercase, and the control-byte / oversized hardening. The point
// is that the same logical search arriving with different casing or spacing
// resolves to one value (so one cache key, one query).
func TestNormalizeSearch(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"trim", "  requests  ", "requests"},
		{"lowercase", "Requests", "requests"},
		{"collapse internal whitespace", "foo   bar\tbaz", "foo bar baz"},
		{"case and space together", "  My  APP ", "my app"},
		{"tabs and newlines fold to space", "a\t\nb", "a b"},
		{"nul byte folds away", "ab\x00cd", "ab cd"},
		{"control bytes fold away", "ab\x01\x02cd", "ab cd"},
		{"empty", "", ""},
		{"whitespace only", " \t \n ", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeSearch(tt.in); got != tt.want {
				t.Errorf("normalizeSearch(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNormalizeSearchLengthCap ensures a hostile oversized term is rune-capped
// (bounding the LIKE scan) and that the cap never splits a multi-byte rune —
// the result must stay valid UTF-8 or Postgres would reject the bind param.
func TestNormalizeSearchLengthCap(t *testing.T) {
	got := normalizeSearch(strings.Repeat("é", maxFilterLen+50))
	if r := []rune(got); len(r) > maxFilterLen {
		t.Errorf("got %d runes, want <= %d", len(r), maxFilterLen)
	}
	if !utf8.ValidString(got) {
		t.Errorf("normalizeSearch produced invalid UTF-8")
	}
}

// TestNormalizeDomain covers the ?domain= canonicalization to the lowercase
// eTLD+1 form hopper stores, and the drop-to-"" for anything that could never
// match a stored value (so it can't fragment the cache with a dead filter).
func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lowercase", "GitHub.com", "github.com"},
		{"trim", "  github.com  ", "github.com"},
		{"punycode allowed", "xn--80ak6aa92e.com", "xn--80ak6aa92e.com"},
		{"hyphen and digits", "cdn-3.example.org", "cdn-3.example.org"},
		{"reject slash", "evil.com/path", ""},
		{"reject space", "two words.com", ""},
		{"reject nul", "evil\x00.com", ""},
		{"reject underscore", "a_b.com", ""},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeDomain(tt.in); got != tt.want {
				t.Errorf("normalizeDomain(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestFormulaFromQueryUnifiesAliases locks in that ?m= and ?formula= produce
// the same subscripted value, so the same formula via either alias (or either
// casing of the digits) collapses to one stored value and one cache key.
func TestFormulaFromQueryUnifiesAliases(t *testing.T) {
	want := "CHO₂"
	cases := []url.Values{
		{"m": {"CHO2"}},
		{"formula": {"CHO2"}},
		{"m": {"CHO₂"}},                  // already subscripted
		{"formula": {"CHO₂"}},            // legacy alias, already subscripted
		{"m": {"  CHO2  "}},              // padded
		{"m": {""}, "formula": {"CHO2"}}, // empty m falls back to formula
	}
	for _, v := range cases {
		if got := formulaFromQuery(v); got != want {
			t.Errorf("formulaFromQuery(%v) = %q, want %q", v, got, want)
		}
	}
	if got := formulaFromQuery(url.Values{"formula": {"bad\x00formula"}}); strings.ContainsRune(got, 0) {
		t.Errorf("formulaFromQuery leaked a NUL byte: %q", got)
	}
}

// TestFeedCacheKeyCrossChannelConsistency is the core guarantee: the same
// logical query, however it arrives (dropdown vs search box vs hand-typed URL,
// with arbitrary casing and whitespace), must produce one cache key. We build
// feedQueryArgs the way renderFeed does — through the normalizers — and assert
// the keys match.
func TestFeedCacheKeyCrossChannelConsistency(t *testing.T) {
	argsFor := func(eco string, q url.Values) feedQueryArgs {
		return feedQueryArgs{
			ecosystem:   strings.ToLower(strings.Trim(eco, "/")),
			domain:      normalizeDomain(q.Get("domain")),
			criticality: normalizeCriticality(q.Get("criticality")),
			formula:     formulaFromQuery(q),
			search:      normalizeSearch(q.Get("q")),
		}
	}

	// Channel A: tidy, lowercase, canonical (what the JS buildURL emits).
	a := argsFor("npm", url.Values{
		"domain":      {"github.com"},
		"criticality": {"hostile"},
		"m":           {"CHO2"},
		"q":           {"left-pad"},
	})
	// Channel B: same intent, hand-typed URL with messy casing, spacing,
	// the ?formula= alias, and uppercase ecosystem path.
	b := argsFor("NPM", url.Values{
		"domain":      {"GitHub.com"},
		"criticality": {"  Hostile "},
		"formula":     {"CHO2"},
		"q":           {"  Left-Pad  "},
	})

	if a != b {
		t.Fatalf("args diverged across channels:\n A=%+v\n B=%+v", a, b)
	}
	if feedCacheKey(a) != feedCacheKey(b) {
		t.Errorf("cache keys diverged:\n A=%q\n B=%q", feedCacheKey(a), feedCacheKey(b))
	}
}
