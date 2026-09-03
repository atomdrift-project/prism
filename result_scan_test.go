package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestResultPageFromRealScan drives the sample page from a real atomscan
// envelope (paysafe-kyc 1.0.2, a hostile npm package) through the same
// preparation the handler uses, then renders it: the badges name the hostile
// findings, the backbone draws the formula's categories, the evidence regions
// carry titles from the scan's own descriptions, and no trait id leaks into
// the page's prose.
func TestResultPageFromRealScan(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "paysafe-kyc-1.0.2.json"))
	if err != nil {
		t.Fatal(err)
	}
	const sha = "df02dfed9a7504c2024c915a1dc59e6038664e806504b34d151b769c563c1546"
	res := storedResult{
		RawLitmus:      string(raw),
		Classification: "hostile",
		Package:        "paysafe-kyc",
		Version:        "1.0.2",
		Ecosystem:      "javascript",
		Filename:       "paysafe-kyc-1.0.2.tgz",
		SourceURL:      "https://registry.npmjs.org/paysafe-kyc/-/paysafe-kyc-1.0.2.tgz",
		AnalyzedAt:     time.Date(2026, 9, 2, 23, 57, 59, 0, time.UTC),
		CachedAt:       time.Date(2026, 9, 2, 23, 57, 59, 0, time.UTC),
	}
	data := prepareResultData(res.Filename, sha, &res)

	if len(data.Badges) != 3 {
		t.Fatalf("badges = %+v, want the three hostile findings", data.Badges)
	}
	for _, b := range data.Badges {
		if b.Crit != "hostile" || b.Desc == "" || strings.Contains(b.Desc, "/") {
			t.Errorf("badge %+v: want a hostile finding described in words", b)
		}
	}
	if !strings.Contains(string(data.Formula), "O") || !strings.Contains(data.FormulaQuery, "Eu2") {
		t.Errorf("formula = %q / %q, want the scan's tiered formula", data.Formula, data.FormulaQuery)
	}
	for _, want := range []string{">Ca<", ">Eu<", ">Al<", ">Db<", ">Pa<", `<title>exfiltration</title>`} {
		if !strings.Contains(string(data.BackboneSVG), want) {
			t.Errorf("backbone missing %q", want)
		}
	}
	if data.Summary == "" || strings.Contains(data.Summary, "/") {
		t.Errorf("summary = %q, want a sentence", data.Summary)
	}
	var titled int
	for _, fv := range data.FileViews {
		for _, w := range fv.Windows {
			if w.Title == "" || w.Range == "" {
				t.Errorf("window in %s lacks a title or range: %+v", fv.Filename, w)
			}
			titled++
		}
	}
	if titled == 0 {
		t.Fatal("no evidence regions were built from the scan's context windows")
	}
	var folded bool
	for _, fv := range data.FileViews {
		for _, w := range fv.Windows {
			for _, b := range w.Blocks {
				for _, r := range b.Rows {
					if r.Gap > 0 {
						folded = true
					}
				}
			}
			if strings.Contains(w.Range, ":") {
				t.Errorf("range %q leaks a column", w.Range)
			}
		}
	}
	if !folded {
		t.Error("a 28-line window with three matches should fold its plain stretches")
	}
	for _, r := range data.ShortProv {
		if r.Label == "SHA-256" || r.Label == "URL" || r.Label == "Filename" {
			t.Errorf("rail provenance repeats the header: %+v", r)
		}
	}

	data.Nonce, data.StyleNonce, data.BuildCommit = "n", "s", "test"
	var buf bytes.Buffer
	if err := resultTemplateForTest(t).Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	page := buf.String()
	for _, want := range []string{
		`class="verdict hostile"`, `class="badge hostile"`, `class="region file-card"`, "line hit hit-", `class="compound"`,
		`<span class="v">` + sha + `</span>`, "registry.npmjs.org/paysafe-kyc",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if out := os.Getenv("PRISM_RENDER_OUT"); out != "" {
		if err := os.WriteFile(out, buf.Bytes(), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
