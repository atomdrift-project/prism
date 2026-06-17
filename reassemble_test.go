package main

import (
	"encoding/json"
	"testing"
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
	p := "pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"
	a := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	b := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	cases := []struct {
		name string
		body string
		want []string
	}{
		// Container only (no member stubs): nothing to fetch.
		{"container only", `{"truncated":true,"files":[{"id":0,"sha":"` + p + `","dp":0}]}`, nil},
		// Container + two member stubs: both members, container excluded.
		{"two stubs", `{"truncated":true,"files":[{"id":0,"sha":"` + p + `","dp":0},{"id":1,"sha":"` + a + `","path":"x.py","depth":1},{"id":2,"sha":"` + b + `","path":"y.js","depth":1}]}`, []string{a, b}},
		// Legacy "fs" key is honored too.
		{"fs key", `{"fs":[{"id":0,"sha":"` + p + `","dp":0},{"id":1,"sha":"` + a + `","dp":1}]}`, []string{a}},
		{"empty", "", nil},
		{"malformed", `not json`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := envelopeChildSHAs([]byte(c.body), p)
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
