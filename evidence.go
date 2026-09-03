package main

// The sample page reads as a brief: a verdict, a summary, the strongest
// findings as badges, then the evidence — each matched region titled by its
// strongest finding, with the matched lines lit whole. These helpers derive
// that page from data prism already carries; nothing here consults hopper.

import (
	"fmt"
	"strings"
)

// maxBadges is how many findings the header names outright.
const maxBadges = 3

// resultBadges picks the findings the header wears: the strongest few at
// suspicious or above, in the order buildFileViews ranked them.
func resultBadges(top []topTrait) []topTrait {
	var out []topTrait
	for _, t := range top {
		if t.Crit != "hostile" && t.Crit != "suspicious" {
			continue
		}
		out = append(out, topTrait{Desc: t.Desc, Crit: t.Crit})
		if len(out) == maxBadges {
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
	for _, f := range findings {
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
// region is folded; runs longer than twice this collapse to a gap marker.
const contextKeep = 2

// foldContext trims a region to its matches and their surroundings: every
// matched row, contextKeep plain rows on either side of it, and a gap marker
// where a longer run of plain rows was left out. Hex blocks and short blocks
// pass through untouched.
func foldContext(block contextBlock) contextBlock {
	if block.Hex || len(block.Rows) <= 2*contextKeep+1 {
		return block
	}
	keep := make([]bool, len(block.Rows))
	matched := false
	for i, r := range block.Rows {
		if r.Crit == "" || r.Cont {
			continue
		}
		matched = true
		for j := max(0, i-contextKeep); j <= min(len(block.Rows)-1, i+contextKeep); j++ {
			keep[j] = true
		}
	}
	if !matched {
		return block
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
		if j-i <= contextKeep+1 {
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
