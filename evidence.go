package main

// The sample page reads as a brief: a verdict, a summary, the strongest
// findings as badges, then the evidence — each matched region titled by its
// strongest finding, with the matched lines lit whole. These helpers derive
// that page from data prism already carries; nothing here consults hopper.

import (
	"fmt"
	"strings"
)

// minNotableCrit is the floor for a finding worth naming on the page.
const minNotableCrit = 3

// maxBadges is how many findings the header names outright.
const maxBadges = 3

// resultBadges picks the findings the header wears: the strongest few at
// suspicious or above, in the order buildFileViews ranked them. A sample whose
// findings carry no byte spans gets no file views at all, so fall back to
// ranking the report's own findings — the badges state the verdict's reasons
// and must never depend on whether cleave recorded a location.
func resultBadges(top []topTrait, files []cleaveFile) []topTrait {
	out := make([]topTrait, 0, maxBadges)
	seen := make(map[string]bool, maxBadges)
	add := func(desc, crit string) bool {
		if desc == "" || seen[desc] {
			return false
		}
		seen[desc] = true
		out = append(out, topTrait{Desc: desc, Crit: crit})
		return len(out) == maxBadges
	}
	for _, t := range top {
		if t.Crit != "hostile" && t.Crit != "suspicious" {
			continue
		}
		if add(t.Desc, t.Crit) {
			return out
		}
	}
	if len(out) > 0 {
		return out
	}
	for _, c := range headlineTraits(files) {
		if add(c.desc, critIntToString(c.crit)) {
			break
		}
	}
	return out
}

// findingCounts tallies a file's findings by severity, notable and up.
type findingCounts struct {
	Hostile, Suspicious, Notable int
}

func countFindings(findings []finding) findingCounts {
	var c findingCounts
	for fi := range findings {
		f := &findings[fi]
		switch f.Crit {
		case 5:
			c.Hostile++
		case 4:
			c.Suspicious++
		case 3:
			c.Notable++
		default:
		}
	}
	return c
}

// summaryLine is the sentence under the title when no written interpretation
// exists: what was found, and how sure the model is.
func summaryLine(c findingCounts, files int, verdict string, confidence int) string {
	total := c.Hostile + c.Suspicious + c.Notable
	if total == 0 {
		return "No notable findings."
	}
	var parts []string
	if c.Hostile > 0 {
		parts = append(parts, plural(c.Hostile, "hostile", "hostile"))
	}
	if c.Suspicious > 0 {
		parts = append(parts, plural(c.Suspicious, "suspicious", "suspicious"))
	}
	if c.Notable > 0 {
		parts = append(parts, plural(c.Notable, "notable", "notable"))
	}
	where := ""
	if files > 1 {
		where = fmt.Sprintf(" across %d files", files)
	}
	s := fmt.Sprintf("%s%s: %s.", plural(total, "finding", "findings"), where, strings.Join(parts, ", "))
	if confidence > 0 && verdict != "" {
		s += fmt.Sprintf(" Model verdict %d%% %s.", confidence, strings.ToLower(verdict))
	}
	return s
}

// shortProvenance keeps the rail to facts the header does not already show:
// no hash, name, version or URL, and no group titles. Labels are rewritten
// for a narrow column.
func shortProvenance(groups []ProvenanceGroup) []ProvenanceRow {
	keep := map[string]string{
		"PURL":           "PURL",
		"Source":         "Source",
		"Feed":           "Feed",
		"Ecosystem":      "Ecosystem",
		"First seen":     "First seen",
		"Last analyzed":  "Analyzed",
		"Label source":   "Labelled by",
		"Traits version": "Traits",
	}
	var out []ProvenanceRow
	for _, g := range groups {
		for _, r := range g.Rows {
			label, ok := keep[r.Label]
			if !ok {
				continue
			}
			r.Label = label
			out = append(out, r)
		}
	}
	return out
}

// windowRange spells the lines (or offsets) a context block covers, for the
// region header: "lines 32–37", "line 12", or "0x40–0x80".
func windowRange(block contextBlock) string {
	if len(block.Rows) == 0 {
		return ""
	}
	first, last := block.Rows[0].Loc, block.Rows[len(block.Rows)-1].Loc
	if !block.Hex {
		first, _, _ = strings.Cut(first, ":")
		last, _, _ = strings.Cut(last, ":")
	}
	if block.Hex {
		if first == last {
			return first
		}
		return first + "–" + last
	}
	if first == last {
		return "line " + first
	}
	return "lines " + first + "–" + last
}

// contextKeep is how many plain rows stay on each side of a matched row when a
// block is folded. Source gets two — an assignment above and a call below carry
// meaning. Hex gets one: a neighbouring 16-byte row is rarely the reason a rule
// fired, and a screen of dot-columns buries the row that is.
const (
	contextKeep    = 2
	contextKeepHex = 1
)

// foldContext contracts a block to what earns its space: every matched row, a
// row or two of surrounding context, and a gap marker standing in for the run
// it dropped. A block with no match is left whole — it is already the bytes
// cleave chose to show.
func foldContext(block contextBlock) contextBlock {
	keepN := contextKeep
	if block.Hex {
		keepN = contextKeepHex
	}
	if len(block.Rows) <= 2*keepN+1 {
		return block
	}
	keep := make([]bool, len(block.Rows))
	matched := false
	for i, r := range block.Rows {
		if r.Crit == "" || r.Cont {
			continue
		}
		matched = true
		for j := max(0, i-keepN); j <= min(len(block.Rows)-1, i+keepN); j++ {
			keep[j] = true
		}
	}
	if !matched {
		// Nothing is lit, so nothing earns a full screen. Keep the head of the
		// window — enough to show the shape of the bytes — and mark the rest.
		head := 2*keepN + 1
		out := contextBlock{Hex: block.Hex, Rows: make([]contextRow, 0, head+1)}
		out.Rows = append(out.Rows, block.Rows[:head]...)
		out.Rows = append(out.Rows, contextRow{Gap: len(block.Rows) - head})
		return out
	}
	// A run shorter than the marker would be is not worth folding.
	for i := 0; i < len(keep); {
		if keep[i] {
			i++
			continue
		}
		j := i
		for j < len(keep) && !keep[j] {
			j++
		}
		if j-i <= keepN+1 {
			for k := i; k < j; k++ {
				keep[k] = true
			}
		}
		i = j
	}
	out := contextBlock{Hex: block.Hex, Rows: make([]contextRow, 0, len(block.Rows))}
	gap := 0
	flush := func() {
		if gap > 0 {
			out.Rows = append(out.Rows, contextRow{Gap: gap})
			gap = 0
		}
	}
	for i, r := range block.Rows {
		if keep[i] {
			flush()
			out.Rows = append(out.Rows, r)
			continue
		}
		gap++
	}
	flush()
	return out
}
