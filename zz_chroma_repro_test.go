package main

import "testing"

func TestChromaTrailingLen(t *testing.T) {
	for _, tc := range []struct{ fn, line string }{
		{"x.py", "import os"},
		{"a.py", "    data = base64.b64decode(payload)"},
		{"x.js", "eval(x)"},
		{"x.toml", "name = \"mureo\""},
		{"setup.cfg", "[metadata]"},
	} {
		toks := highlightEvidence(tc.line, tc.fn)
		total := 0
		for _, k := range toks {
			total += len(k.Text)
		}
		t.Logf("fn=%-10s inlen=%d toklen=%d delta=%d", tc.fn, len(tc.line), total, total-len(tc.line))
	}
}
