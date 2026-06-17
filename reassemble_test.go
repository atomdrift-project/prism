package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"

	"codeberg.org/atomdrift/hopper"
)

func TestHopperWasCompacted(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"empty", "", false},
		{"plain", `{"v":"4","fs":[{"id":0}]}`, false},
		{"truncated", `{"v":"4","fs":[{"id":0}],"truncated":true,"omitted_files":2}`, true},
		// omitted_files without "truncated" is what prism writes after it has
		// already reassembled a capped archive — it is enriched, not still
		// hopper-compacted, so it must not trigger another child fetch.
		{"omitted only", `{"v":"4","fs":[{"id":0}],"omitted_files":3}`, false},
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

func TestEnvelopeChildSHAs(t *testing.T) {
	a := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	b := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"none", `{"truncated":true,"omitted_files":2}`, nil},
		{"two", `{"truncated":true,"omitted_children":[{"sha":"` + a + `","path":"x.py"},{"sha":"` + b + `","path":"y.js"}]}`, []string{a, b}},
		{"skips empty sha", `{"omitted_children":[{"sha":"","path":"z"},{"sha":"` + a + `"}]}`, []string{a}},
		{"empty", "", nil},
		{"malformed", `not json`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := envelopeChildSHAs([]byte(c.body))
			if len(got) != len(c.want) {
				t.Fatalf("envelopeChildSHAs = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("sha[%d] = %q, want %q", i, got[i], c.want[i])
				}
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

	// total == len(children): every member was fetched, so the envelope is
	// complete and both truncation markers should be cleared.
	enriched, err := reassembleEnvelope(parentEnv, children, "archive.tgz", len(children))
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

	// All 3 members were fetched but only 1 merges (broken + empty are skipped).
	// The 2 that could not be represented must still be reported as omitted so
	// the envelope never claims a completeness it doesn't have.
	enriched, err := reassembleEnvelope(parentEnv, children, "a.zip", len(children))
	if err != nil {
		t.Fatalf("reassembleEnvelope failed: %v", err)
	}

	var got struct {
		Raw struct {
			Truncated    *bool `json:"truncated,omitempty"`
			OmittedFiles *int  `json:"omitted_files,omitempty"`
			Files        []struct {
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
	if got.Raw.Truncated != nil {
		t.Errorf("expected truncated marker dropped, got %v", *got.Raw.Truncated)
	}
	if got.Raw.OmittedFiles == nil || *got.Raw.OmittedFiles != 2 {
		t.Errorf("expected omitted_files = 2 (members that did not merge), got %v", got.Raw.OmittedFiles)
	}
}

// TestReassembleEnvelopeReportsOmittedBeyondCap covers the common case: an
// archive has far more members than prism fetches (archiveMemberFetchLimit),
// so children is the highest-score prefix and omitted_files must account for
// the long tail the cap left behind.
func TestReassembleEnvelopeReportsOmittedBeyondCap(t *testing.T) {
	logger = slog.New(slog.NewTextHandler(os.Stderr, nil))

	parentEnv := []byte(`{
		"ml": {"v":"4","fs":[{"id":0,"class":0,"prob":0.1}]},
		"raw": {"v":"4","fs":[{"id":0,"sha":"p","path":"big.zip","type":"zip","sz":100,"dp":0}],"truncated":true,"omitted_files":999}
	}`)

	children := []*hopper.Sample{
		{SHA256: "c1", Path: "big/a.js", CleaveResult: []byte(`{"fs":[{"id":0,"sha":"c1","path":"a.js","sz":10,"dp":0}]}`)},
		{SHA256: "c2", Path: "big/b.js", CleaveResult: []byte(`{"fs":[{"id":0,"sha":"c2","path":"b.js","sz":10,"dp":0}]}`)},
	}

	// 1000 members in the archive, only the top 2 fetched.
	enriched, err := reassembleEnvelope(parentEnv, children, "big.zip", 1000)
	if err != nil {
		t.Fatalf("reassembleEnvelope failed: %v", err)
	}

	var got struct {
		Raw struct {
			Truncated    *bool `json:"truncated,omitempty"`
			OmittedFiles *int  `json:"omitted_files,omitempty"`
			Files        []struct {
				SHA string `json:"sha"`
			} `json:"files"`
		} `json:"raw"`
	}
	if err := json.Unmarshal(enriched, &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got.Raw.Files) != 3 {
		t.Errorf("expected 3 files (parent + 2 children), got %d", len(got.Raw.Files))
	}
	if got.Raw.Truncated != nil {
		t.Errorf("expected truncated marker dropped after reassembly, got %v", *got.Raw.Truncated)
	}
	if got.Raw.OmittedFiles == nil || *got.Raw.OmittedFiles != 998 {
		t.Errorf("expected omitted_files = 998 (1000 members - 2 merged), got %v", got.Raw.OmittedFiles)
	}
}
