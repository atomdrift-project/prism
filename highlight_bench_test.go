package main

import (
	"fmt"
	"strings"
	"testing"
)

// BenchmarkManyTraits is a regression guard on evidence-highlighting
// allocation, not a speed target. It renders a sample whose findings sprawl
// across far more traits than maxSampleTraits keeps.
//
// Highlighting is deferred to selectTopTraits so only the traits and matches
// that actually reach the template are tokenised. When that deferral was
// introduced on 2026-09-17 this benchmark went from 801 MB and 9.97M allocs
// per render to 14 MB and 141k -- a 57x drop in bytes. Re-introducing eager
// highlighting at either cap (the per-trait match cap or the trait cap) costs
// that back, and nothing else in the suite would notice: the rendered output
// is identical either way, which is exactly why this is measured here.
func BenchmarkManyTraits(b *testing.B) {
	const traits, rowsPerTrait = 300, 4
	filler := strings.Repeat("const a = require('fs'); a.readFileSync(p); ", 12)
	f := cleaveFile{Path: "postinstall.js", FileType: "javascript", Depth: 0}
	off := int64(0x1000)
	for tr := range traits {
		fi := finding{
			ID:   fmt.Sprintf("objectives/execution/interpreter/eval::variant%03d", tr),
			Crit: 3, Conf: 0.9, Desc: "dynamic eval",
		}
		for r := range rowsPerTrait {
			snippet := fmt.Sprintf("child_process.exec(t%03d_%d); %s", tr, r, filler)
			fi.Spans = append(fi.Spans, [2]int64{off, int64(len(snippet))})
			f.Ctx = append(f.Ctx, contextWindow{Offset: off, Data: []byte(snippet)})
			off += 0x800
		}
		f.Findings = append(f.Findings, fi)
	}
	files := []cleaveFile{f}
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = buildStructuredFindings(files)
	}
}
