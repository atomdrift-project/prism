package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// This file renders cleave's per-line context (`ctx`) into the source and hex
// views shown in the File tab and the per-trait expansion. It mirrors cleave's
// own rendering semantics (numbered source lines with the matched span lit by
// severity; `hex  ascii` rows with the matched bytes lit) so the web view reads
// like the CLI. Legacy text-window reports carry no per-line bytes and fall
// back to the older inline-evidence path; nothing here runs for them.

// z85Alphabet is the ZeroMQ RFC 32 digit set, in value order (0..=84). It backs
// the reverse table used to decode the raw context bytes cleave carries in "b".
const z85Alphabet = "0123456789abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"

var z85Decode = func() func(string) ([]byte, error) {
	var table [256]int16
	for i := range table {
		table[i] = -1
	}
	for i := range len(z85Alphabet) {
		table[z85Alphabet[i]] = int16(i)
	}
	errInvalid := errors.New("invalid z85 input")

	// decode inverts cleave's arbitrary-length Z85: a trailing group of 2–4
	// characters yields 1–3 bytes (the padded high bytes decode unchanged). A
	// group of exactly one character is unreachable from a valid encoder and is
	// rejected, matching the Rust side.
	return func(s string) ([]byte, error) {
		out := make([]byte, 0, len(s)/5*4)
		for i := 0; i < len(s); i += 5 {
			chunk := s[i:min(i+5, len(s))]
			if len(chunk) == 1 {
				return nil, errInvalid
			}
			var value uint64
			for j := range 5 {
				digit := int16(84) // pad short groups with the max digit
				if j < len(chunk) {
					if digit = table[chunk[j]]; digit < 0 {
						return nil, errInvalid
					}
				}
				value = value*85 + uint64(digit)
			}
			if value > 0xFFFFFFFF {
				return nil, errInvalid
			}
			group := [4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}
			keep := 4
			if len(chunk) < 5 {
				keep = len(chunk) - 1
			}
			out = append(out, group[:keep]...)
		}
		return out, nil
	}
}()

// contextBlock is one rendered context window: a contiguous run of source lines
// or a single hex unit. It is the shared shape behind the File tab and the
// per-trait expansion.
type contextBlock struct {
	Rows []contextRow
	Hex  bool
}

// contextRow is one display row — a source line or a hex row. Loc is the line
// number (source) or the byte offset (hex). Crit is the severity class of the
// strongest match on the row, empty for a pure-context row. Segs holds the
// source text split into plain/highlighted runs, or the hex byte cells; ASCII
// holds the hex row's printable gutter.
type contextRow struct {
	Loc   string
	Crit  string
	Segs  []contextSeg
	ASCII []contextSeg
}

// contextSeg is one run of row content. A non-empty Crit marks it as part of a
// matched span, rendered highlighted at that severity. Class is the chroma
// syntax-highlight class for source segments (empty for hex and unlexable text).
type contextSeg struct {
	Text  string
	Crit  string
	Class string
}

// hexStride is the bytes-per-row of the hex view, matching cleave's default.
const hexStride = 16

// maxContextRows caps a single block so a pathologically large merged window
// can't blow up the page. Comfortably above cleave's per-match line budgets.
const maxContextRows = 48

// buildContextBlocks renders a file's `ctx` windows. When filterID is non-empty
// only windows carrying a note for that trait are kept and only that trait's
// spans are lit; an empty filterID keeps every window and lights every note
// (the File-tab view). Returns nil when the file has no current-format context,
// so callers fall back to the legacy inline-evidence path.
func buildContextBlocks(file *cleaveFile, filterID string) []contextBlock {
	if !hasRichContext(file) {
		return nil
	}
	filename := extractBasename(file.Path)
	var blocks []contextBlock
	for i := 0; i < len(file.Ctx); {
		win := &file.Ctx[i]
		if win.Data == nil {
			i++
			continue
		}
		// Source lines (Addr set, not hex) merge into one block while their line
		// numbers stay contiguous; hex units and minified text slices each stand
		// alone.
		if win.Hex || win.Addr == nil {
			if block, ok := renderWindow(file.Ctx[i:i+1], filterID, filename); ok {
				blocks = append(blocks, block)
			}
			i++
			continue
		}
		j := i + 1
		for j < len(file.Ctx) && file.Ctx[j].Data != nil && !file.Ctx[j].Hex &&
			file.Ctx[j].Addr != nil && file.Ctx[j].Offset == file.Ctx[j-1].Offset+1 {
			j++
		}
		if block, ok := renderWindow(file.Ctx[i:j], filterID, filename); ok {
			blocks = append(blocks, block)
		}
		i = j
	}
	return blocks
}

// contextForTraits gathers the rendered context windows for a set of full trait
// IDs within one file — a Traits-tab card aggregates several sub-traits, each of
// which may anchor its own window. Windows shared by more than one sub-trait are
// deduped, and the total is capped so one busy trait can't flood the card.
// Returns nil when the file carries no current-format context.
func contextForTraits(file *cleaveFile, ids []string) []contextBlock {
	if !hasRichContext(file) {
		return nil
	}
	const maxBlocks = 6
	seen := make(map[string]bool)
	var out []contextBlock
	for _, id := range ids {
		for _, block := range buildContextBlocks(file, id) {
			if len(out) >= maxBlocks {
				return out
			}
			key := blockKey(block)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, block)
		}
	}
	return out
}

// blockKey identifies a window by its first and last row location, so the same
// window surfaced by two sub-traits collapses to one.
func blockKey(b contextBlock) string {
	if len(b.Rows) == 0 {
		return ""
	}
	return b.Rows[0].Loc + "-" + b.Rows[len(b.Rows)-1].Loc
}

// hasRichContext reports whether any window carries current-format per-line
// bytes (and thus can render the source/hex view).
func hasRichContext(file *cleaveFile) bool {
	for i := range file.Ctx {
		if file.Ctx[i].Data != nil {
			return true
		}
	}
	return false
}

// renderWindow renders one window (a run of source lines, or a single hex/text
// unit). It reports false when filtering to a trait the window never mentions.
func renderWindow(windows []contextWindow, filterID, filename string) (contextBlock, bool) {
	if filterID != "" && !windowsMatchTrait(windows, filterID) {
		return contextBlock{}, false
	}
	if windows[0].Hex {
		return renderHexWindow(&windows[0], filterID), true
	}
	return renderSourceWindow(windows, filterID, filename), true
}

func windowsMatchTrait(windows []contextWindow, filterID string) bool {
	for w := range windows {
		for _, n := range windows[w].Notes {
			if n.ID == filterID {
				return true
			}
		}
	}
	return false
}

// renderSourceWindow renders a run of source lines: each line numbered, its
// code syntax-highlighted, and its matched span(s) lit by severity. Lit notes
// are restricted to filterID when set; filename selects the chroma lexer.
func renderSourceWindow(windows []contextWindow, filterID, filename string) contextBlock {
	block := contextBlock{}
	for w := range windows {
		if len(block.Rows) >= maxContextRows {
			break
		}
		win := &windows[w]
		base := win.Offset
		if win.Addr != nil {
			base = *win.Addr
		}
		spans, crit := spansForRow(win.Notes, base, len(win.Data), filterID)
		block.Rows = append(block.Rows, contextRow{
			Loc:  strconv.FormatInt(win.Offset, 10),
			Crit: crit,
			Segs: highlightedSegs(string(win.Data), spans, filename),
		})
	}
	return block
}

// highlightedSegs lexes a source line with chroma and overlays the match spans,
// so each run carries both its syntax class and (when matched) its severity. It
// falls back to a plain match-only split when no lexer matches the filename.
//
// Chroma can emit slightly more or fewer bytes than the input line — most
// lexers append a trailing newline — so token offsets are clamped to the line's
// own length and any unlexed remainder is rendered plain. Trusting the token
// lengths verbatim panicked on every such line (slice out of range).
func highlightedSegs(text string, spans []rowSpan, filename string) []contextSeg {
	tokens := highlightEvidence(text, filename)
	if len(tokens) == 0 {
		return splitSpans(text, spans)
	}
	var segs []contextSeg
	pos := 0
	for _, tok := range tokens {
		if pos >= len(text) {
			break
		}
		end := min(pos+len(tok.Text), len(text))
		segs = appendSpanSegs(segs, text, spans, pos, end, tok.Class)
		pos = end
	}
	// Chroma reproduced fewer bytes than the line: render the tail uncolored
	// but still match-lit, so no content is dropped.
	if pos < len(text) {
		segs = appendSpanSegs(segs, text, spans, pos, len(text), "")
	}
	return segs
}

// appendSpanSegs splits text[start:end) into runs at each change in match
// severity, tagging every run with class, and appends them to segs. Callers
// guarantee 0 <= start <= end <= len(text).
func appendSpanSegs(segs []contextSeg, text string, spans []rowSpan, start, end int, class string) []contextSeg {
	for i := start; i < end; {
		sev := spanSeverityAt(spans, i)
		j := i
		for j < end && spanSeverityAt(spans, j) == sev {
			j++
		}
		segs = append(segs, contextSeg{Text: text[i:j], Crit: sev, Class: class})
		i = j
	}
	return segs
}

// renderHexWindow renders one hex unit as `hexStride`-byte rows with the matched
// bytes lit. The unit's bytes begin at win.Offset.
func renderHexWindow(win *contextWindow, filterID string) contextBlock {
	block := contextBlock{Hex: true}
	for start := 0; start < len(win.Data); start += hexStride {
		if len(block.Rows) >= maxContextRows {
			break
		}
		row := win.Data[start:min(start+hexStride, len(win.Data))]
		rowBase := win.Offset + int64(start)
		spans, crit := spansForRow(win.Notes, rowBase, len(row), filterID)
		hexCells := make([]contextSeg, len(row))
		asciiCells := make([]contextSeg, len(row))
		for k, b := range row {
			sev := spanSeverityAt(spans, k)
			hexCells[k] = contextSeg{Text: fmt.Sprintf("%02x", b), Crit: sev}
			asciiCells[k] = contextSeg{Text: printableByte(b), Crit: sev}
		}
		block.Rows = append(block.Rows, contextRow{
			Loc:   fmt.Sprintf("0x%x", rowBase),
			Crit:  crit,
			Segs:  hexCells,
			ASCII: asciiCells,
		})
	}
	return block
}

// rowSpan is a matched byte range within a row's content [Start, End) at the
// given severity.
type rowSpan struct {
	Crit  string
	Start int
	End   int
}

// spansForRow resolves the notes that intersect a row whose content starts at
// byte offset base and is n bytes long, into row-relative spans. filterID, when
// set, keeps only that trait's notes. The second return is the strongest
// severity class touching the row (for the gutter), empty when none do.
func spansForRow(notes []contextNote, base int64, n int, filterID string) (spans []rowSpan, crit string) {
	topCrit := -1
	for _, note := range notes {
		if filterID != "" && note.ID != filterID {
			continue
		}
		length := note.Size
		if length <= 0 {
			length = 1
		}
		start := int(note.Offset - base)
		end := start + length
		if end <= 0 || start >= n {
			continue
		}
		start = max(start, 0)
		end = min(end, n)
		sev := critIntToString(note.Crit)
		spans = append(spans, rowSpan{Start: start, End: end, Crit: sev})
		if note.Crit > topCrit {
			topCrit = note.Crit
			crit = sev
		}
	}
	return spans, crit
}

// spanSeverityAt returns the severity class of the span covering byte index k,
// or empty when none does. Used per-cell by the hex renderer.
func spanSeverityAt(spans []rowSpan, k int) string {
	for _, s := range spans {
		if k >= s.Start && k < s.End {
			return s.Crit
		}
	}
	return ""
}

// splitSpans cuts text into alternating plain and highlighted runs at the span
// boundaries. Overlapping or out-of-order spans are normalized by walking the
// text once and asking which span (if any) covers each rune boundary.
func splitSpans(text string, spans []rowSpan) []contextSeg {
	if len(spans) == 0 {
		return []contextSeg{{Text: text}}
	}
	var segs []contextSeg
	var b strings.Builder
	cur := ""
	flush := func() {
		if b.Len() > 0 {
			segs = append(segs, contextSeg{Text: b.String(), Crit: cur})
			b.Reset()
		}
	}
	for i := range len(text) {
		sev := spanSeverityAt(spans, i)
		if sev != cur {
			flush()
			cur = sev
		}
		b.WriteByte(text[i])
	}
	flush()
	return segs
}

// printableByte renders one byte for the hex view's ascii gutter: the character
// itself when printable ASCII, a dot otherwise — the hex-editor convention.
func printableByte(b byte) string {
	if b >= 0x20 && b < 0x7f {
		return string(rune(b))
	}
	return "."
}
