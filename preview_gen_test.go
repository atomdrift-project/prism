package main

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"testing"
)

// TestGenerateContentPreview renders result.html with a realistic Content-tab
// fixture to /tmp/prism-content-preview.html so the layout can be eyeballed in a
// browser without the hopper/litmus backend. Skipped unless PRISM_PREVIEW is
// set, so it never runs in CI. The fixture flows through the real buildFileViews
// renderer (chroma highlighting, severity chips, composite trail).
func TestGenerateContentPreview(t *testing.T) {
	if os.Getenv("PRISM_PREVIEW") == "" {
		t.Skip("set PRISM_PREVIEW=1 to regenerate the Content-tab preview")
	}

	funcs := template.FuncMap{
		"isPublic":         func() bool { return true },
		"buildCommit":      func() string { return "preview" },
		"buildCommitShort": func() string { return "prev" },
		"mul":              func(a, b float64) float64 { return a * b },
		"formulaQuery":     func(s string) string { return s },
		"deref": func(p *int) int {
			if p == nil {
				return 0
			}
			return *p
		},
		"ecoColor":  func(string) string { return "slate" },
		"chromaCSS": func() template.CSS { return chromaStylesheet },
	}
	tmpl, err := template.New("result.html").Funcs(funcs).ParseFS(templatesFS,
		"templates/base.html", "templates/result.html")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	data := previewData()
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := "/tmp/prism-content-preview.html"
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Logf("wrote %s (%d bytes) — open it in a browser", out, buf.Len())
}

// previewData builds a multi-file archive result whose Content tab exercises
// every shape: a hostile JS member with a multi-trait window, a suspicious
// member, and a container with a cross-file composite trail.
func previewData() resultData {
	d := singleFileData()
	d.Filename = "wuphf-0.225.0.tgz"
	d.FileType = "TAR.GZ"
	d.Verdict = "HOSTILE"
	d.RiskLevel = "hostile"
	d.RiskLabel = "Hostile"
	d.IsArchive = true
	d.Level = testInt(72)
	d.LevelConfidence = 91
	d.Size = "8.4 KB"

	members := []cleaveFile{
		jsMember(1, "package.json", "bbb", "json", []ctxLine{
			{18, "  \"scripts\": {", nil},
			{19, "    \"postinstall\": \"node ./version-check.js\"", []ctxNote{{ID: "execution/interpreter/script/npm::npm-postinstall-script", Desc: "npm postinstall hook present", Off: 18, Len: 11, Crit: 4}}},
			{20, "  },", nil},
		}),
		jsMember(2, "version-check.js", "ccc", "javascript", []ctxLine{
			{24, "const cp = require('child_process');", []ctxNote{{ID: "process/create/shell/bridge::child-process-require", Desc: "Imports child_process", Off: 11, Len: 24, Crit: 4}}},
			{25, "const { execFile } = cp;", []ctxNote{{ID: "process/create/system::js-execfile-direct-call", Desc: "Executes file via Node.js execFile", Off: 8, Len: 8, Crit: 5}}},
			{26, "execFile('node', [payload], cb);", []ctxNote{{ID: "process/create/system::js-execfile-direct-call", Desc: "Executes file via Node.js execFile", Off: 0, Len: 8, Crit: 5}}},
		}),
		jsMember(4, "bundle.min.js", "eee", "javascript", []ctxLine{
			{1, "!function(e){var t={};function n(r){if(t[r])return t[r].exports;var o=t[r]={i:r,l:!1,exports:{}};return e[r].call(o.exports,o,o.exports,n),o.l=!0,o.exports}n.m=e;var a=eval(atob(\"ZmV0Y2goJ2h0dHBzOi8vZXZpbCcp\"));return n.c=t,n.d=function(e,t,r){n.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:r})},a}([])",
				[]ctxNote{{ID: "execution/interpreter/eval::obfuscated", Desc: "eval of base64-decoded payload", Off: 196, Len: 23, Crit: 5}}},
		}),
		hexMember(3, "libpayload.so", "ddd", 0x10010),
		hexMember(5, "stub.bin", "fff", 0x40),
	}
	container := cleaveFile{
		ID: 0, Depth: 0, SHA256: "aaa", Path: "wuphf-0.225.0.tgz", FileType: "tar.gz",
		Findings: []finding{{
			ID: "command-and-control/dropper/node-bootstrap::spawn-exec", Desc: "Postinstall drops and executes a Node payload", Crit: 5, Conf: 0.95,
			Sources: []compactSource{
				{File: 1, Line: ptrInt64(19)},
				{File: 2, Line: ptrInt64(26)},
			},
		}},
	}
	files := append([]cleaveFile{container}, members...)
	d.FileViews, _ = buildFileViews(files)
	if src, hex := contentLocCh(d.FileViews); src > 0 || hex > 0 {
		d.ContentLocStyle = template.HTMLAttr(fmt.Sprintf(`style="--ctx-loc-src-ch:%d;--ctx-loc-hex-ch:%d"`, src, hex))
	}
	return d
}

type ctxNote struct {
	ID       string
	Desc     string
	Off, Len int64
	Crit     int
}

type ctxLine struct {
	Line  int64
	Text  string
	Notes []ctxNote
}

// jsMember builds a source-code member file with per-line context windows.
func jsMember(id int, name, sha, ftype string, lines []ctxLine) cleaveFile {
	f := cleaveFile{ID: id, Depth: 1, SHA256: sha, Path: "wuphf-0.225.0.tgz!!package/" + name, FileType: ftype}
	for _, l := range lines {
		notes := make([]contextNote, len(l.Notes))
		var top int
		for i, n := range l.Notes {
			notes[i] = contextNote{ID: n.ID, Desc: n.Desc, Offset: n.Off, Size: int(n.Len), Crit: n.Crit}
			if n.Crit > top {
				top = n.Crit
			}
			f.Findings = appendFinding(f.Findings, n.ID, n.Desc, n.Crit)
		}
		f.Ctx = append(f.Ctx, contextWindow{
			Offset: l.Line,
			Addr:   ptrInt64(0),
			Data:   []byte(l.Text),
			Notes:  notes,
		})
	}
	return f
}

// hexMember builds a binary member with one hex context window, including a row
// where two traits match (only the strongest should annotate) and a large
// offset to exercise column alignment against the source line numbers.
func hexMember(id int, name, sha string, base int64) cleaveFile {
	data := make([]byte, 53) // not a multiple of 16, so the last row is short (tests padding)
	for i := range data {
		data[i] = byte(0x20 + (i*7)%90)
	}
	copy(data, []byte("\x7fELF\x02\x01\x01"))
	notes := []contextNote{
		{ID: "net/resolve::getnameinfo", Desc: "Resolve endpoint with getnameinfo", Offset: base + 0x10, Size: 8, Crit: 3},
		{ID: "account/enumerate::lookup", Desc: "Enumerate account names from IDs", Offset: base + 0x14, Size: 8, Crit: 4},
		{ID: "fs/write::single-byte", Desc: "Write single bytes to file", Offset: base + 0x28, Size: 4, Crit: 3},
	}
	f := cleaveFile{ID: id, Depth: 1, SHA256: sha, Path: "wuphf-0.225.0.tgz!!" + name, FileType: "elf"}
	f.Ctx = []contextWindow{{Offset: base, Hex: true, Data: data, Notes: notes}}
	for _, n := range notes {
		f.Findings = appendFinding(f.Findings, n.ID, n.Desc, n.Crit)
	}
	return f
}

func appendFinding(fs []finding, id, desc string, crit int) []finding {
	for _, f := range fs {
		if f.ID == id {
			return fs
		}
	}
	return append(fs, finding{ID: id, Desc: desc, Crit: crit, Conf: 0.9})
}
