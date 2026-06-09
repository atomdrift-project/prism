package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"

	"codeberg.org/atomdrift/hopper"
)

func TestBuildStructuredKV(t *testing.T) {
	files := []cleaveFile{
		{
			Path:   "package.json",
			SHA256: "abc",
			KV: map[string]json.RawMessage{
				"package.name":          json.RawMessage(`"left-pad"`),
				"package.version":       json.RawMessage(`"1.3.0"`),
				"package.scripts.count": json.RawMessage(`3`),
				"package.private":       json.RawMessage(`false`),
				"package.deps":          json.RawMessage(`["foo","bar"]`),
				"empty":                 json.RawMessage(`null`),
			},
		},
		{Path: "no-kv.js", SHA256: "def"}, // skipped
	}
	got := buildStructuredKV(files)
	if len(got) != 1 {
		t.Fatalf("expected 1 file with kv, got %d", len(got))
	}
	pairs := got[0].Pairs
	if len(pairs) != 6 {
		t.Fatalf("expected 6 pairs, got %d", len(pairs))
	}
	// Sorted by key.
	wantOrder := []string{"empty", "package.deps", "package.name", "package.private", "package.scripts.count", "package.version"}
	for i, p := range pairs {
		if p.Key != wantOrder[i] {
			t.Errorf("pair[%d].Key = %q, want %q", i, p.Key, wantOrder[i])
		}
	}
	want := map[string]string{
		"package.name":          "left-pad",
		"package.version":       "1.3.0",
		"package.scripts.count": "3",
		"package.private":       "false",
		"package.deps":          `["foo","bar"]`,
		"empty":                 "",
	}
	for _, p := range pairs {
		if p.Value != want[p.Key] {
			t.Errorf("kv[%s] = %q, want %q", p.Key, p.Value, want[p.Key])
		}
	}
}

func TestHopperWasCompacted(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"empty", "", false},
		{"plain", `{"v":"4","fs":[{"id":0}]}`, false},
		{"truncated", `{"v":"4","fs":[{"id":0}],"truncated":true,"omitted_files":2}`, true},
		{"omitted only", `{"v":"4","fs":[{"id":0}],"omitted_files":3}`, true},
		{"malformed", `not json`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hopperWasCompacted([]byte(c.body))
			if got != c.want {
				t.Errorf("hopperWasCompacted(%q) = %v, want %v", c.body, got, c.want)
			}
		})
	}
}

func TestCleaveReportReadsV5Facts(t *testing.T) {
	var report cleaveReport
	raw := []byte(`{"v":"5","fs":[{"id":0,"sha":"abc","path":"sample.exe","type":"pe","sz":42,"ff":{"m":{"binary":{"overall_entropy":7.2}},"v":{"pe.machine":"x86_64"},"s":[[16,"a","hello"]],"i":[["kernel32.dll","CreateFileW"]],"x":[["DllRegisterServer"]],"sc":[[".text",1024,4096,6.42,"r-x"]]}}]}`)
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshal v5: %v", err)
	}
	if len(report.Files) != 1 {
		t.Fatalf("files len = %d", len(report.Files))
	}
	f := report.Files[0]
	if len(f.Metrics) == 0 || string(f.KV["pe.machine"]) != `"x86_64"` {
		t.Fatalf("v5 facts did not populate metrics/kv: %+v", f)
	}
	if got := f.Imports; len(got) != 1 || got[0] != "kernel32.dll!CreateFileW" {
		t.Fatalf("imports = %#v", got)
	}
	if len(f.Strings) != 1 || len(f.Sections) != 1 || f.Sections[0].Flags != "r-x" {
		t.Fatalf("strings/sections not populated: strings=%d sections=%+v", len(f.Strings), f.Sections)
	}
}

func TestReassembleEnvelope(t *testing.T) {
	logger = slog.New(slog.NewTextHandler(os.Stderr, nil))

	parentEnv := []byte(`{
		"ml": {
			"v":"4",
			"class":2,
			"prob":0.95,
			"thresholds":[0.65,0.887],
			"fs":[{"id":0,"class":2,"prob":0.95}]
		},
		"raw": {
			"v":"4",
			"fs":[{"id":0,"sha":"parentsha","path":"archive.tgz","type":"tar.gz","sz":1671,"f":"Os","dp":0}],
			"truncated":true,
			"omitted_files":2
		}
	}`)

	children := []*hopper.Sample{
		{
			SHA256: "child1sha",
			Path:   "package/index.js",
			CleaveResult: []byte(`{
				"v":"4",
				"fs":[{"id":0,"sha":"child1sha","path":"/tmp/index.js","type":"js","sz":2048,"f":"H3","dp":0}]
			}`),
			LitmusResult: []byte(`{"v":"4","class":2,"prob":0.91,"fs":[{"id":0,"class":2,"prob":0.91}]}`),
		},
		{
			SHA256: "child2sha",
			Path:   "package/postinstall.js",
			CleaveResult: []byte(`{
				"v":"4",
				"fs":[{"id":0,"sha":"child2sha","path":"/tmp/postinstall.js","type":"js","sz":640,"f":"Cm","dp":0}]
			}`),
			LitmusResult: []byte(`{"v":"4","class":1,"prob":0.7,"fs":[{"id":0,"class":1,"prob":0.7}]}`),
		},
	}

	enriched, err := reassembleEnvelope(parentEnv, children, "archive.tgz")
	if err != nil {
		t.Fatalf("reassembleEnvelope failed: %v", err)
	}

	var got struct {
		Raw struct {
			Truncated    *bool `json:"truncated,omitempty"`
			OmittedFiles *int  `json:"omitted_files,omitempty"`
			Files        []struct {
				SHA   string `json:"sha"`
				Path  string `json:"path"`
				ID    int    `json:"id"`
				Depth int    `json:"dp"`
			} `json:"files"`
		} `json:"raw"`
		ML struct {
			Files []struct {
				ID    int     `json:"id"`
				Class int     `json:"class"`
				Prob  float64 `json:"prob"`
			} `json:"files"`
		} `json:"ml"`
	}
	if err := json.Unmarshal(enriched, &got); err != nil {
		t.Fatalf("parse enriched: %v", err)
	}

	if len(got.Raw.Files) != 3 {
		t.Errorf("raw.files len = %d, want 3", len(got.Raw.Files))
	}
	if got.Raw.Truncated != nil {
		t.Errorf("expected truncated marker dropped, got %v", *got.Raw.Truncated)
	}
	if got.Raw.OmittedFiles != nil {
		t.Errorf("expected omitted_files dropped, got %d", *got.Raw.OmittedFiles)
	}

	ids := make(map[int]bool)
	for _, f := range got.Raw.Files {
		if ids[f.ID] {
			t.Errorf("duplicate id %d in merged files", f.ID)
		}
		ids[f.ID] = true
	}

	for _, f := range got.Raw.Files {
		if f.SHA == "child1sha" {
			if f.Depth != 1 {
				t.Errorf("child1 depth = %d, want 1", f.Depth)
			}
			if !strings.HasPrefix(f.Path, "archive.tgz!!") {
				t.Errorf("child1 path = %q, want prefix archive.tgz!!", f.Path)
			}
		}
	}

	if len(got.ML.Files) != 3 {
		t.Errorf("ml.files len = %d, want 3", len(got.ML.Files))
	}
}

func TestReassembleEnvelopeSkipsBrokenChildren(t *testing.T) {
	logger = slog.New(slog.NewTextHandler(os.Stderr, nil))

	parentEnv := []byte(`{
		"ml": {"v":"4","fs":[{"id":0,"class":0,"prob":0.1}]},
		"raw": {"v":"4","fs":[{"id":0,"sha":"p","path":"a.zip","type":"zip","sz":100,"dp":0}],"truncated":true,"omitted_files":2}
	}`)

	children := []*hopper.Sample{
		{SHA256: "good", Path: "a/x", CleaveResult: []byte(`{"fs":[{"id":0,"sha":"good","path":"x","sz":10,"dp":0}]}`)},
		{SHA256: "broken", Path: "a/y", CleaveResult: []byte(`not json`)},
		{SHA256: "empty", Path: "a/z", CleaveResult: []byte(`{"fs":[]}`)},
	}

	enriched, err := reassembleEnvelope(parentEnv, children, "a.zip")
	if err != nil {
		t.Fatalf("reassembleEnvelope failed: %v", err)
	}

	var got struct {
		Raw struct {
			Files []struct {
				SHA string `json:"sha"`
			} `json:"files"`
		} `json:"raw"`
	}
	if err := json.Unmarshal(enriched, &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Raw.Files) != 2 {
		t.Errorf("expected 2 files (parent + 1 good child), got %d", len(got.Raw.Files))
	}
}
