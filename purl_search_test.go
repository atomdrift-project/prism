package main

import (
	"strings"
	"testing"
)

// The reported bug: a reader types "feishu-docx-mcp@0.3.2" into the box. As one
// literal string it matches no filename, no sha256 and no package, so the feed
// came back empty. Split, it is a coordinate the query can actually answer.
func TestPackageVersionSearch(t *testing.T) {
	for _, tc := range []struct {
		in, name, version string
		ok                bool
	}{
		{"feishu-docx-mcp@0.3.2", "feishu-docx-mcp", "0.3.2", true},
		{"lodash@4.17.21", "lodash", "4.17.21", true},
		{"@scope/pkg@1.2.3", "@scope/pkg", "1.2.3", true}, // the leading @ is not a separator
		{"pkg@v2.0.0", "pkg", "v2.0.0", true},             // a v-prefixed release
		{"someone@example.com", "", "", false},            // an address, not a coordinate
		{"lodash", "", "", false},                         // no version to pin
		{"lodash@", "", "", false},                        // trailing separator
		{"@scope/pkg", "", "", false},                     // scope only
		{"purl:npm/lodash@1.0.0", "", "", false},          // a token the purl sniffer owns
		{"pkg:npm/lodash@1.0.0", "", "", false},           // ditto, bare form
		{"two words@1.0", "", "", false},                  // free text, not a coordinate
		{"", "", "", false},
	} {
		name, version, ok := packageVersionSearch(tc.in)
		if ok != tc.ok || name != tc.name || version != tc.version {
			t.Errorf("packageVersionSearch(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.in, name, version, ok, tc.name, tc.version, tc.ok)
		}
	}
}

// The stream's search box used to submit to "/", which was the feed's home
// until the fallout log took it over. After that a search from the box landed
// on the fallout page, which ignores every filter — the query simply vanished.
// Both the no-JS form targets and the JS that intercepts the submit have to
// name the stream explicitly.
func TestStreamSearchTargetsTheStream(t *testing.T) {
	page, err := templatesFS.ReadFile("templates/upload.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`<form method="GET" action="/stream" class="search-form"`,
		`action="{{if .SelectedEco}}/{{.SelectedEco}}/{{else}}/stream{{end}}" class="filter-form"`,
	} {
		if !strings.Contains(string(page), want) {
			t.Errorf("stream template is missing %q; a search from the box lands on the fallout log", want)
		}
	}

	js, err := staticFS.ReadFile("static/upload.js")
	if err != nil {
		t.Fatal(err)
	}
	// The JS preventDefaults the submit and navigates itself, so a correct
	// form action alone does not save the search.
	if !strings.Contains(string(js), `: "/stream";`) {
		t.Error("buildURL no longer falls back to /stream; a search with no ecosystem lands on the fallout log")
	}
	if strings.Contains(string(js), `parsed.ecosystem)}/`+"`"+` : "/";`) {
		t.Error("buildURL still falls back to \"/\", which is the fallout log")
	}
}
