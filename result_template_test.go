package main

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"testing"
)

// resultTemplateForTest parses the result template with the same funcs
// registered in main(), so tests catch syntax errors that would otherwise
// crash the server at startup.
func resultTemplateForTest(t *testing.T) *template.Template {
	t.Helper()
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
		"ecoColor":     func(string) string { return "slate" },
		"chromaCSS":    func() template.CSS { return "" },
		"formulaTiers": formulaTiers,
		"tierName":     tierName,
	}
	tmpl, err := template.New("result.html").Funcs(funcs).ParseFS(templatesFS,
		"templates/base.html", "templates/result.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return tmpl
}

// TestResultTemplateParses ensures the result template parses and renders the
// expected structure for the main page states: the brief's header, the
// findings badges, the evidence regions and the rail.
func TestResultTemplateParses(t *testing.T) {
	tmpl := resultTemplateForTest(t)
	cases := []struct {
		name     string
		want     []string
		dontWant []string
		data     resultData
	}{
		// A benign single file: no badges, the rail's provenance, no evidence.
		{
			name: "single_file", data: singleFileData(),
			dontWant: []string{`class="badge `},
			want: []string{
				"Provenance", "registry.npmjs.org", "recorded no findings",
				`class="verdict "`, `<h1>x.exe</h1>`,
			},
		},
		// A hostile archive without per-line context: the verdict carries its
		// confidence, the summary line renders, the download link is gated on size.
		{
			name: "archive_with_children", data: archiveData(),
			want: []string{`class="verdict hostile"`, "87%", "recorded no findings"},
		},
		// Per-line context: a region titled by its strongest finding, the matched
		// line lit whole with its descriptions in the title, and the badge.
		{name: "file_view", data: fileViewData(), want: []string{
			`class="region file-card"`, "postinstall.js", "lines 12–12", "line hit hit-hostile",
			`title="spawns a child process"`, `class="badge hostile"`, "beacons to a remote host",
		}, dontWant: []string{"lines 12–12 ·"}},
		// A compacted archive before its members load: the loading note and the
		// fetch that fills it in.
		{name: "deferred_archive", data: deferredArchiveData(), want: []string{
			`id="members-loading"`, "/members",
		}},
		// A file found inside an archive lists the archive in the rail.
		{name: "parents", data: parentsAndReferrersData(), want: []string{"Found inside", "inner.zip"}, dontWant: []string{"dropper.elf"}},
		// External citations read as one sentence.
		{name: "detected_by", data: detectedByData(), want: []string{"Also flagged by", "bleepingcomputer", `href="https://osv.dev/x"`, "2 more."}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tmpl.Execute(&buf, tc.data); err != nil {
				t.Fatalf("execute: %v", err)
			}
			out := buf.String()
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q", w)
				}
			}
			for _, d := range tc.dontWant {
				if strings.Contains(out, d) {
					t.Errorf("unexpected %q", d)
				}
			}
		})
	}
}

func TestResultDownloadTracksHopperAvailability(t *testing.T) {
	tmpl := resultTemplateForTest(t)

	available := singleFileData()
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, available); err != nil {
		t.Fatalf("execute available: %v", err)
	}
	if !strings.Contains(buf.String(), `class="download-btn" href="/file/`) {
		t.Fatal("available hopper-api did not render the download link")
	}

	unavailable := singleFileData()
	unavailable.DownloadEnabled = false
	buf.Reset()
	if err := tmpl.Execute(&buf, unavailable); err != nil {
		t.Fatalf("execute unavailable: %v", err)
	}
	if !strings.Contains(buf.String(), "download unavailable") {
		t.Fatal("unavailable hopper-api did not render the disabled download control")
	}
	if strings.Contains(buf.String(), `.dl?t=`) {
		t.Fatal("unavailable hopper-api still exposed a download link")
	}
}

// parentsAndReferrersData is a standalone child page with one containing
// archive and one merely-referencing sample, exercising both backlink panels.
func parentsAndReferrersData() resultData {
	d := singleFileData()
	child := d.SHA256
	d.Parents = []ParentArchive{{
		SHA256:      strings.Repeat("b", 64),
		SHA256Short: "bbbbbbbbbbbb",
		Filename:    "inner.zip",
		ChildSHA:    child,
	}}
	d.Referrers = []ParentArchive{{
		SHA256:      strings.Repeat("c", 64),
		SHA256Short: "cccccccccccc",
		Filename:    "dropper.elf",
		ChildSHA:    child,
		Rel:         "fetched",
	}}
	return d
}

// deferredArchiveData is a compacted-archive page before its members load: an
// archive with no member FileViews yet, flagged for lazy hydration.
func deferredArchiveData() resultData {
	d := archiveData()
	d.FileViews = nil
	d.DeferredMembers = true
	return d
}

// TestResultMemberPartials renders the two named blocks the /members endpoint
// serves by name (handleFileMembers), guarding that they stay addressable and
// render the member content the client injects.
func TestResultMemberPartials(t *testing.T) {
	tmpl := resultTemplateForTest(t)

	var content bytes.Buffer
	if err := tmpl.ExecuteTemplate(&content, "contentBody", fileViewData()); err != nil {
		t.Fatalf("contentBody: %v", err)
	}
	if !strings.Contains(content.String(), "file-card") {
		t.Errorf("contentBody missing file-card; got %q", content.String())
	}
	if !strings.Contains(content.String(), "spawns a child process") {
		t.Errorf("contentBody missing the row's finding description; got %q", content.String())
	}

	var traits bytes.Buffer
	if err := tmpl.ExecuteTemplate(&traits, "findingsbody", archiveData()); err != nil {
		t.Fatalf("findingsbody: %v", err)
	}
	if traits.Len() == 0 {
		t.Error("findingsbody rendered empty")
	}
}

// fileViewData drives the File tab: one file card with a lit source-context
// span and a finding whose composite trail links to another file's section.
func fileViewData() resultData {
	d := singleFileData()
	// A cross-file composite now surfaces in the top-traits headline with its
	// member trail, not as a per-file card.
	d.TopTraits = []topTrait{{
		Desc: "beacons to a remote host", Crit: "hostile",
		Sources: []compositeLink{{Label: "loader.js", Anchor: "file-cafe", Loc: "3"}},
	}}
	d.Badges = resultBadges(d.TopTraits, nil)
	d.FileViews = []fileView{{
		Path: "package/postinstall.js", Filename: "postinstall.js", FileType: "JS",
		SHA256: "deadbeef", Anchor: "file-deadbeef", Crit: "hostile",
		Windows: []fileWindow{{
			Title: "beacons to a remote host", Crit: "hostile", Range: "lines 12–12",
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

// detectedByData is a benign single-file page that also carries corroboration
// chips: a linked open database, a blog with no URL, and two unnamed vendor
// sources already rolled up into the count chip.
func detectedByData() resultData {
	d := singleFileData()
	d.DetectedBy = []Citation{
		{Source: "bleepingcomputer", Note: "malware"},
		{Source: "osv", URL: "https://osv.dev/x", Note: "MAL-2026-1234"},
	}
	d.MoreSources = "+2 more"
	return d
}

func singleFileData() resultData {
	return resultData{
		Filename:        "x.exe",
		Headline:        "x.exe",
		SHA256:          strings.Repeat("a", 64),
		SHA256Short:     strings.Repeat("a", 12) + "...",
		Verdict:         "BENIGN",
		Formula:         template.HTML("Os"),
		FileType:        "PE",
		Size:            "1.2 KB",
		SizeBytes:       1200,
		DownloadEnabled: true,
		FindingCount:    "0",
		Duration:        "10ms",
		Layout:          "organic2",
		BuildCommit:     "test",
		SuspiciousT:     0.65,
		HostileT:        0.887,
		Nonce:           "n",
		PURL:            "pkg:npm/lodash@4.17.21",
		PURLIndexURL:    "/npm/lodash",
		Level:           new(-1), // benign sentinel: badge must be hidden, not crash
		ShortProv: []ProvenanceRow{
			{Label: "Source", Value: "registry.npmjs.org", Href: "https://registry.npmjs.org/lodash", Mono: true, External: true},
		},
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
		Headline:        "archive.tgz",
		SHA256:          mkSHA('a'),
		SHA256Short:     strings.Repeat("a", 12) + "...",
		Verdict:         "HOSTILE",
		RiskLevel:       "hostile",
		RiskLabel:       "Hostile",
		Formula:         template.HTML("Os"),
		FileType:        "TAR.GZ",
		Size:            "1.6 KB",
		FindingCount:    "12",
		Duration:        "200ms",
		Layout:          "organic2",
		BuildCommit:     "test",
		SuspiciousT:     0.65,
		HostileT:        0.887,
		Nonce:           "n",
		IsArchive:       true,
		Level:           new(72), // real FPR level: badge must render confidence
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
