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
		"ecoColor":         func(string) string { return "slate" },
		"bandGradient": func(_, _, _ float64) template.CSS {
			return template.CSS("linear-gradient(90deg, #fff, #000)")
		},
		"chromaCSS": func() template.CSS { return "" },
	}
	tmpl, err := template.New("result.html").Funcs(funcs).ParseFS(templatesFS,
		"templates/base.html", "templates/result.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	cases := []struct {
		name string
		data resultData
	}{
		{"single_file", singleFileData()},
		{"archive_with_children", archiveData()},
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
		})
	}
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
	}
}

func archiveData() resultData {
	mkSHA := func(c byte) string {
		return strings.Repeat(string(c), 64)
	}
	return resultData{
		Filename:     "archive.tgz",
		SHA256:       mkSHA('a'),
		SHA256Short:  strings.Repeat("a", 12) + "...",
		Verdict:      "HOSTILE",
		Formula:      template.HTML("Os"),
		FileType:     "TAR.GZ",
		Size:         "1.6 KB",
		FindingCount: "12",
		Duration:     "200ms",
		MoleculeJSON: template.JS("{}"),
		Layout:       "organic2",
		BuildCommit:  "test",
		SuspiciousT:  0.65,
		HostileT:     0.887,
		Nonce:        "n",
		IsArchive:    true,
		TotalFiles:   3,
		ShownFiles:   3,
		Files: []FileTreeEntry{
			{Path: "archive.tgz", Display: "archive.tgz", Basename: "archive.tgz", SHA256: mkSHA('a'), SHA256Short: "aaaaaaaa", Classification: "hostile", Risk: "hostile", Formula: "Os", FileType: "TAR.GZ", SizeStr: "1.6 KB", Probability: 0.95, Depth: 0, IsContainer: true},
			{Path: "archive.tgz!!package/index.js", Display: "package/index.js", Basename: "index.js", SHA256: mkSHA('b'), SHA256Short: "bbbbbbbb", Classification: "hostile", Risk: "hostile", Formula: "H", FileType: "JS", SizeStr: "2.0 KB", Probability: 0.91, Depth: 1},
			{Path: "archive.tgz!!package/postinstall.js", Display: "package/postinstall.js", Basename: "postinstall.js", SHA256: mkSHA('c'), SHA256Short: "cccccccc", Classification: "suspicious", Risk: "suspicious", Formula: "Cm", FileType: "JS", SizeStr: "640 B", Probability: 0.7, Depth: 1},
		},
		FileFindings: []FileFindingsDisplay{{
			Path: "archive.tgz!!package/index.js", Basename: "index.js", SHA256: fmt.Sprintf("%64s", "b"), Probability: 0.91,
			Classification: "hostile", Categories: []CategoryGroup{{Name: "Objectives", Findings: []FindingDisplay{{ID: "execution", Crit: "hostile", Desc: "spawns child"}}}},
		}},
		FileStrings: []FileStringsDisplay{{
			Basename: "index.js", SHA256: mkSHA('b'), Strings: []StringDisplay{{Offset: "0x0", Value: "hello"}},
		}},
		FileSymbols: []FileSymbolsDisplay{{Basename: "index.js", SHA256: mkSHA('b')}},
		FileMetrics: []FileMetricsDisplay{{Basename: "index.js", SHA256: mkSHA('b')}},
	}
}
