package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// The detail page advertises d and r with aria-keyshortcuts, and j/k have no
// visible control to hang the attribute on — so the page states them once for
// a screen reader. All four are handled by shortcuts.js, which the page has to
// actually load for any of that to be true.
func TestResultPageLoadsShortcuts(t *testing.T) {
	var buf bytes.Buffer
	if err := resultTemplateForTest(t).Execute(&buf, archiveData()); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		`src="/static/js/shortcuts.js?v=`,
		"j for the next sample",
		"k for the previous one",
		"d to download",
		"r to re-queue",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("result page missing %q", want)
		}
	}
}

// A script the page references but the server does not serve is a shortcut
// that silently does nothing.
func TestStaticServesShortcuts(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/static/js/shortcuts.js", http.NoBody)
	rec := httptest.NewRecorder()
	newMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/js/shortcuts.js = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q, want javascript", ct)
	}
	if body := rec.Body.String(); !strings.Contains(body, "prism_nav") {
		t.Error("served shortcuts.js does not read the feed's saved order")
	}
	req = httptest.NewRequest(http.MethodGet, "/static/js/nav-stash.js", http.NoBody)
	rec = httptest.NewRecorder()
	newMux().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /static/js/nav-stash.js = %d, want 200", rec.Code)
	}
}

// j and k are only as good as the list the feed stashed on the way out. The
// two files are the two halves of one contract and nothing in the compiler
// checks it, so the shape is asserted here: same storage key, same field
// names, same sha shape.
func TestNavStashContractMatches(t *testing.T) {
	writer := readStatic(t, "static/js/nav-stash.js")
	reader := readStatic(t, "static/js/shortcuts.js")
	for _, want := range []string{`"prism_nav"`, "samples", "sha"} {
		if !strings.Contains(writer, want) {
			t.Errorf("nav-stash.js no longer writes %s; shortcuts.js still expects it", want)
		}
		if !strings.Contains(reader, want) {
			t.Errorf("shortcuts.js no longer reads %s", want)
		}
	}
	// nav-stash.js only records a sha that looks like one, and shortcuts.js
	// re-checks the same shape before putting it in a URL.
	shaRE := regexp.MustCompile(`\[0-9a-f\]\{8,64\}`)
	if !shaRE.MatchString(writer) || !shaRE.MatchString(reader) {
		t.Error("the two halves of the nav stash disagree about what a sha looks like")
	}
	if !strings.Contains(writer, "a.file-link") {
		t.Fatal("nav-stash.js no longer keys off a.file-link")
	}
}

// The bug this test exists for: j/k worked from /stream and did nothing from
// the fallout feed, because the stash lived inside upload.js and only the
// upload page loaded it. A feed that renders sample links but never records
// their order is a feed whose samples have no neighbours — and it fails
// silently, with nothing in the console to find.
func TestEveryFeedStashesItsOrder(t *testing.T) {
	pages, err := templatesFS.ReadDir("templates")
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	for _, page := range pages {
		if page.IsDir() {
			continue
		}
		body := readStatic(t, "templates/"+page.Name())
		if !strings.Contains(body, `class="file-link"`) {
			continue // not a feed: nothing to stash
		}
		checked++
		if !strings.Contains(body, "/static/js/nav-stash.js") {
			t.Errorf("%s links to samples but never loads nav-stash.js, so j/k is dead there",
				page.Name())
		}
	}
	if checked == 0 {
		t.Fatal("found no feed template rendering a.file-link; the selector has moved")
	}
}

func readStatic(t *testing.T, path string) string {
	t.Helper()
	var (
		data []byte
		err  error
	)
	if strings.HasPrefix(path, "templates/") {
		data, err = templatesFS.ReadFile(path)
	} else {
		data, err = staticFS.ReadFile(path)
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
