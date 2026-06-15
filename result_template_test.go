package main

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"testing"
)

// TestResultTemplateParses ensures the result template parses with the
// same funcs registered in main(). Catches template syntax errors that
// would otherwise crash the server at startup.
func TestResultTemplateParses(t *testing.T) {
	funcs := template.FuncMap{
		"isPublic":         func() bool { return false },
		"buildCommit":      func() string { return "abcdef0123456789" },
		"buildCommitShort": func() string { return "abcde" },
		"mul":              func(a, b float64) float64 { return a * b },
		"formulaQuery":     func(s string) string { return s },
		"deref": func(p *int) int {
			if p == nil {
				return 0
			}
			return *p
		},
		"ecoColor":  func(string) string { return "slate" },
		"chromaCSS": func() template.CSS { return "" },
	}
	tmpl, err := template.New("result.html").Funcs(funcs).ParseFS(templatesFS,
		"templates/base.html", "templates/result.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	cases := []struct {
		name     string
		want     []string
		dontWant string
		data     resultData
	}{
		{name: "single_file", data: singleFileData(), dontWant: "verdict-level", // benign: badge hidden
			want: []string{"tab-provenance", "Provenance", "lodash", "registry.npmjs.org"}},
		// Archive: confidence badge plus a full trait match row
		// (filename — location — highlighted evidence).
		{name: "archive_with_children", data: archiveData(), want: []string{"87%", "postinstall.js", "0x40", "finding-match-evidence chroma"}},
		// File tab: per-file card, lit context span, and a linkable composite trail.
		{name: "file_view", data: fileViewData(), want: []string{
			"tab-content", "file-card", "ctx-hit hostile", "composite-trail",
			`href="#file-cafe"`, "loader.js",
			"win-section", "ctx-anno", `anno hostile`, "spawns a child process",
			`comp-card hostile`, "beacons to a remote host", "loader.js",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tmpl.Execute(&buf, c.data); err != nil {
				t.Fatalf("execute: %v", err)
			}
			if buf.Len() < 1000 {
				t.Errorf("rendered output suspiciously short: %d bytes", buf.Len())
			}
			for _, w := range c.want {
				if !strings.Contains(buf.String(), w) {
					t.Errorf("rendered output missing %q", w)
				}
			}
			if c.dontWant != "" && strings.Contains(buf.String(), c.dontWant) {
				t.Errorf("rendered output unexpectedly contains %q", c.dontWant)
			}
		})
	}
}

// fileViewData drives the File tab: one file card with a lit source-context
// span and a finding whose composite trail links to another file's section.
func fileViewData() resultData {
	d := singleFileData()
	d.FileViews = []fileView{{
		Path: "package/postinstall.js", Filename: "postinstall.js", FileType: "JS",
		SHA256: "deadbeef", Anchor: "file-deadbeef", Crit: "hostile",
		Composites: []compositeFinding{{
			ID: "c2/beacon", Desc: "beacons to a remote host", Crit: "hostile",
			Sources: []compositeLink{{Label: "loader.js", Anchor: "file-cafe", Loc: "3"}},
		}},
		Windows: []fileWindow{{
			Blocks: []contextBlock{{Rows: []contextRow{{
				Loc:   "12",
				Crit:  "hostile",
				Segs:  []contextSeg{{Text: "exec(", Crit: "hostile"}, {Text: "cmd)"}},
				Annos: []rowAnno{{Desc: "spawns a child process", Crit: "hostile"}},
			}}}},
		}},
	}}
	return d
}

func singleFileData() resultData {
	return resultData{
		Filename:     "x.exe",
		SHA256:       strings.Repeat("a", 64),
		SHA256Short:  strings.Repeat("a", 12) + "...",
		Verdict:      "BENIGN",
		Formula:      template.HTML("Os"),
		FileType:     "PE",
		Size:         "1.2 KB",
		FindingCount: "0",
		Duration:     "10ms",
		MoleculeJSON: template.JS("{}"),
		Layout:       "organic2",
		BuildCommit:  "test",
		SuspiciousT:  0.65,
		HostileT:     0.887,
		Nonce:        "n",
		Level:        testInt(-1), // benign sentinel: badge must be hidden, not crash
		Provenance: []ProvenanceGroup{
			{Title: "Identity", Rows: []ProvenanceRow{
				{Label: "SHA-256", Value: strings.Repeat("a", 64), Mono: true},
				{Label: "Package", Value: "lodash"},
				{Label: "Version", Value: "4.17.21", Mono: true},
			}},
			{Title: "Origin", Rows: []ProvenanceRow{
				{Label: "Source", Value: "registry.npmjs.org", Href: "https://registry.npmjs.org/lodash", Mono: true, External: true},
			}},
		},
	}
}

func archiveData() resultData {
	mkSHA := func(c byte) string {
		return strings.Repeat(string(c), 64)
	}
	return resultData{
		Filename:        "archive.tgz",
		SHA256:          mkSHA('a'),
		SHA256Short:     strings.Repeat("a", 12) + "...",
		Verdict:         "HOSTILE",
		Formula:         template.HTML("Os"),
		FileType:        "TAR.GZ",
		Size:            "1.6 KB",
		FindingCount:    "12",
		Duration:        "200ms",
		MoleculeJSON:    template.JS("{}"),
		Layout:          "organic2",
		BuildCommit:     "test",
		SuspiciousT:     0.65,
		HostileT:        0.887,
		Nonce:           "n",
		IsArchive:       true,
		Level:           testInt(72), // real FPR level: badge must render confidence
		LevelConfidence: 87,
		ArchiveCategories: []CategoryGroup{{
			Name: "Objectives",
			Findings: []FindingDisplay{{
				ID: "execution", Crit: "hostile", Desc: "spawns child", ConfPct: 90,
				Matches: []FindingMatch{{
					Evidence: "child_process.exec(cmd)",
					Path:     "package/postinstall.js",
					Filename: "postinstall.js",
					Location: "0x40",
					Tokens:   highlightEvidence("child_process.exec(cmd)", "postinstall.js"),
					Count:    2,
				}},
			}},
		}},
		FileFindings: []FileFindingsDisplay{{
			Path: "archive.tgz!!package/index.js", Basename: "index.js", SHA256: fmt.Sprintf("%64s", "b"), Probability: 0.91,
			Classification: "hostile", Categories: []CategoryGroup{{Name: "Objectives", Findings: []FindingDisplay{{ID: "execution", Crit: "hostile", Desc: "spawns child"}}}},
		}},
	}
}
