package main

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
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
// holds the hex row's printable gutter. Annos are the trailing trait
// annotations for matches that begin on this row (File view only).
type contextRow struct {
	Loc   string
	Crit  string
	Segs  []contextSeg
	ASCII []contextSeg
	Annos []rowAnno
	// Lead/Trail mark a source line clipped to a window around its match — the
	// template renders a leading/trailing ellipsis so a long minified line stays
	// focused on the match instead of burying the annotation off-screen.
	Lead  bool
	Trail bool
}

// rowAnno is one trailing annotation on a context row: a trait's description in
// its severity color, shown once on the line where its match begins — cleave's
// inline `// desc` comment, brought to the web.
type rowAnno struct {
	Desc string
	Crit string
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

// isBinaryType reports whether a file type is rendered in hex (binary) rather
// than as source text.
func isBinaryType(fileType string) bool {
	switch fileType {
	case "elf", "pe", "macho", "java_class", "python_bytecode", "beam":
		return true
	}
	return false
}

// groupCtxWindows splits a file's `ctx` into render groups: contiguous source
// lines (matching line numbers) merge into one group; binary file types and
// minified text slices (no Addr) each stand alone. Entries with no decoded
// bytes (legacy windows) are skipped. Each returned slice is a sub-slice of
// file.Ctx in file order.
func groupCtxWindows(ctx []contextWindow, fileType string) [][]contextWindow {
	var groups [][]contextWindow
	for i := 0; i < len(ctx); {
		if ctx[i].Data == nil {
			i++
			continue
		}
		if isBinaryType(fileType) || ctx[i].Addr == nil {
			groups = append(groups, ctx[i:i+1])
			i++
			continue
		}
		j := i + 1
		for j < len(ctx) && ctx[j].Data != nil && !isBinaryType(fileType) &&
			ctx[j].Addr != nil && ctx[j].Offset == ctx[j-1].Offset+1 {
			j++
		}
		groups = append(groups, ctx[i:j])
		i = j
	}
	return groups
}

// buildContextBlocks renders a file's `ctx` windows. When filterID is non-empty
// only windows carrying a note for that trait are kept and only that trait's
// spans are lit; an empty filterID keeps every window and lights every note.
// Returns nil when the file has no current-format context, so callers fall back
// to the legacy inline-evidence path.
func buildContextBlocks(file *cleaveFile, filterID string) []contextBlock {
	if !hasRichContext(file) {
		return nil
	}
	filename := extractBasename(file.Path)
	findingsByID := nativeFindings(file)
	var blocks []contextBlock
	for _, g := range groupCtxWindows(file.Ctx, file.FileType) {
		if block, ok := renderWindow(g, filterID, filename, file.FileType, findingsByID, nil); ok {
			blocks = append(blocks, block)
		}
	}
	return blocks
}

// ctxNoteRef is one trait whose notes fall inside a context window: its full id,
// the strongest severity it carries there, and a description when the note (or
// caller) supplies one.
type ctxNoteRef struct {
	ID   string
	Desc string
	Crit int
}

// labeledWindow is a rendered context window plus the traits annotating it — the
// content-centric unit the File tab renders: show the content once, label it
// with every trait whose note lands inside.
type labeledWindow struct {
	Notes []ctxNoteRef
	Block contextBlock
	Start int64 // first window offset, for file-order placement
	Crit  int   // strongest note severity in the window
}

// labeledWindows renders a file's context windows once each, every note lit, and
// pairs each with the distinct traits whose notes fall inside it (severity-desc).
// Windows that carry no note are dropped — pure surrounding context belongs to a
// neighboring matched window, not on its own. Returns nil without rich context.
func labeledWindows(file *cleaveFile) []labeledWindow {
	if !hasRichContext(file) {
		return nil
	}
	filename := extractBasename(file.Path)
	findingsByID := nativeFindings(file)
	// Written descriptions are capped to the file's strongest few traits so the
	// context trait column stays scannable — every trait still highlights its
	// span (that path is separate), only the top ones carry a note.
	descByID := topDescByID(findingsByID, maxAnnotatedTraits)
	var out []labeledWindow
	for _, g := range groupCtxWindows(file.Ctx, file.FileType) {
		notes := windowNotes(g, findingsByID)
		if len(notes) == 0 {
			continue
		}
		block, ok := renderWindow(g, "", filename, file.FileType, findingsByID, descByID)
		if !ok {
			continue
		}
		out = append(out, labeledWindow{Notes: notes, Block: block, Start: g[0].Offset, Crit: notes[0].Crit})
	}
	return out
}

// maxAnnotatedTraits caps how many of a file's traits carry a written
// description in the context trait column. Every matched trait still highlights
// its span; only the strongest few get a note, so a busy file's column stays
// scannable instead of repeating a description down every line.
const maxAnnotatedTraits = 5

// topDescByID returns descriptions for the strongest n findings — by severity,
// then confidence, then id for a stable order — and drops the rest. The dropped
// traits still highlight; they just carry no written note.
func topDescByID(findings map[string]*finding, n int) map[string]string {
	type ranked struct {
		id, desc string
		crit     int
		conf     float64
	}
	items := make([]ranked, 0, len(findings))
	for id, f := range findings {
		// No-Desc traits still count toward the top-N — rowAnnos falls back to
		// the short trait id for their label, so they must be in the set.
		items = append(items, ranked{id: id, desc: f.Desc, crit: f.Crit, conf: f.Conf})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].crit != items[j].crit {
			return items[i].crit > items[j].crit
		}
		if items[i].conf != items[j].conf {
			return items[i].conf > items[j].conf
		}
		return items[i].id < items[j].id
	})
	if len(items) > n {
		items = items[:n]
	}
	out := make(map[string]string, len(items))
	for _, it := range items {
		out[it.id] = it.desc
	}
	return out
}

// windowNotes collects the distinct traits annotating a window group by
// intersecting each finding's Spans against the group's byte ranges, keeping
// the strongest severity and description per trait, ordered severity-desc then
// id-asc for a stable, scannable header.
func windowNotes(group []contextWindow, findings map[string]*finding) []ctxNoteRef {
	byID := make(map[string]*ctxNoteRef)
	var order []string
	for id, f := range findings {
		for w := range group {
			win := &group[w]
			base := win.Offset
			if win.Addr != nil {
				base = *win.Addr
			}
			n := len(win.Data)
			for _, sp := range f.Spans {
				off, length := sp[0], sp[1]
				if length <= 0 {
					length = 1
				}
				if off < base+int64(n) && off+length > base {
					// This finding intersects this window.
					ref, ok := byID[id]
					if !ok {
						order = append(order, id)
						byID[id] = &ctxNoteRef{ID: id, Desc: f.Desc, Crit: f.Crit}
					} else {
						if f.Crit > ref.Crit {
							ref.Crit = f.Crit
						}
						if ref.Desc == "" {
							ref.Desc = f.Desc
						}
					}
					break // one span match is enough to include this finding
				}
			}
		}
	}
	refs := make([]ctxNoteRef, 0, len(order))
	for _, id := range order {
		refs = append(refs, *byID[id])
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Crit != refs[j].Crit {
			return refs[i].Crit > refs[j].Crit
		}
		return refs[i].ID < refs[j].ID
	})
	return refs
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

// nativeFindings indexes the findings native to a file by ID. A finding with a
// non-empty From is a rollup inherited from one or more embedded members; its
// spans are relative to those members' bytes, not this file's, so intersecting
// them against this file's own context windows lights spurious matches. For an
// archive container — whose ctx is only a short header sample of the compressed
// stream — that surfaces a member's trait (e.g. an Arabic-script note from an
// inner test fixture) annotating the container's gzip header. Keeping only
// native findings confines a window's annotations to traits that actually fired
// on its bytes; inherited findings are attributed to their member elsewhere.
func nativeFindings(file *cleaveFile) map[string]*finding {
	// A packed archive container has no meaningful byte view of its own — its
	// bytes are compressed/packed member data — so no trait is windowed against
	// them; each trait is attributed to the member it fired in (the Traits tab
	// and the top-trait trail). Binary-content containers (elf/pe/macho with a
	// genuine own-byte view, e.g. an installer with an appended archive) keep
	// windowing their own code.
	if file.Container && !isBinaryType(file.FileType) {
		return nil
	}
	byID := make(map[string]*finding, len(file.Findings))
	for i := range file.Findings {
		if len(file.Findings[i].From) > 0 {
			continue
		}
		if isOffsetZeroNoise(&file.Findings[i]) {
			continue
		}
		byID[file.Findings[i].ID] = &file.Findings[i]
	}
	return byID
}

// minSuspiciousCrit is the criticality at and above which a finding is taken
// seriously enough to survive the offset-0 filter — "suspicious" (4) per
// critIntToString.
const minSuspiciousCrit = 4

// isOffsetZeroNoise reports whether a finding is a likely false positive anchored
// at byte 0: a sub-suspicious trait whose every span begins at offset 0. Format
// markers and whole-file metrics (e.g. a "JavaScript built bundle marker" on a
// zip's "PK" header) match at offset 0 on almost any container, so below the
// suspicious bar they are dropped from the content view rather than lighting the
// first row of every archive. A finding with no spans is not offset-anchored and
// is never filtered here.
func isOffsetZeroNoise(f *finding) bool {
	if f.Crit >= minSuspiciousCrit || len(f.Spans) == 0 {
		return false
	}
	for _, sp := range f.Spans {
		if sp[0] != 0 {
			return false
		}
	}
	return true
}

// markContainers flags every file whose own bytes are packed member data (an
// archive/compressed container), so nativeFindings never windows a trait against
// those bytes. A file is a container when some file names it as parent via a
// *containment* pid edge — an extracted archive member — or, for reports
// predating `pid` or whose members were omitted, when its own type is a known
// archive/compressed format. A "fetched" dependency or a "registry" sidecar also
// carries a pid, but it names the file that *declared* it, not a container, so
// those edges are excluded — otherwise a PKGBUILD that fetched a tarball would be
// marked a container and lose its own findings. The signals are unioned and
// neither is a false positive, so together they survive messy `!!`/`!` paths and
// truncated file lists.
func markContainers(files []cleaveFile) {
	idToIdx := make(map[int]int, len(files))
	for i := range files {
		idToIdx[files[i].ID] = i
	}
	for i := range files {
		if p := files[i].Parent; p != nil && containmentRel(files[i].Rel) {
			if j, ok := idToIdx[*p]; ok {
				files[j].Container = true
			}
		}
		if isContainerType(files[i].FileType) {
			files[i].Container = true
		}
	}
}

// containmentRel reports whether a child's pid edge means its parent physically
// packs it. Fetched and registry edges point at a declaring/described file, not a
// packed container; every other edge (an archive member, an unpacked layer) does.
func containmentRel(rel string) bool {
	return rel != "fetched" && rel != "registry"
}

// isContainerType reports whether a file type's own bytes are packed/compressed
// member data rather than the file's own content — the fallback signal used when
// the structural `pid` edge is absent. Covers the archive families cleave
// extracts (composite_rules/types.rs) plus the standalone-compression formats.
func isContainerType(fileType string) bool {
	switch fileType {
	case "archive", "zip", "7z", "rar", "cab", "chm", "ar", "cpio", "iso", "img", "dmg", "msi",
		"tar", "tgz", "tar.gz", "tar.bz2", "tar.xz",
		"gz", "gzip", "bz2", "bzip2", "xz", "zst", "zstd", "lz4",
		"npm", "nupkg", "crate", "conda", "egg", "gem", "whl", "python_sdist", "sdist",
		"deb", "rpm", "apk", "apk_android", "apk_alpine", "pkg_macos", "pkg_freebsd", "pkg_arch",
		"jar", "war", "ear", "asar", "ipa", "crx", "xpi", "vsix":
		return true
	}
	return false
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
// descByID, when non-nil, enables trailing trait annotations (the File view);
// the Traits-tab expansion passes nil since its card already names the trait.
func renderWindow(
	windows []contextWindow, filterID, filename, fileType string,
	findingsByID map[string]*finding, descByID map[string]string,
) (contextBlock, bool) {
	if filterID != "" && !windowsMatchTrait(windows, filterID, findingsByID) {
		return contextBlock{}, false
	}
	annotated := map[string]bool{} // a trait annotates once per window, on its first line
	if isBinaryType(fileType) {
		return renderHexWindow(&windows[0], filterID, findingsByID, descByID, annotated), true
	}
	return renderSourceWindow(windows, filterID, filename, findingsByID, descByID, annotated), true
}

// rowAnnos returns the single trailing annotation for a row — cleave's rule: one
// comment per line, the strongest match that begins within [base, base+n), even
// though every match on the line stays highlighted. A trait annotates at most
// once per window (tracked in annotated), so a match spanning rows or repeating
// doesn't echo. desc falls back finding-desc → short id. Returns nil when
// descByID is nil (annotations disabled) or no fresh match begins on the row.
func rowAnnos(findings map[string]*finding, base int64, n int, descByID map[string]string, annotated map[string]bool) []rowAnno {
	if descByID == nil {
		return nil
	}
	var bestID string
	bestCrit := -1
	for id, f := range findings {
		if annotated[id] {
			continue
		}
		if _, ok := descByID[id]; !ok {
			continue // outside the top-N annotate set — highlighted, but no note
		}
		for _, sp := range f.Spans {
			off := sp[0] - base
			if off < 0 || off >= int64(n) {
				continue // span doesn't begin on this row
			}
			if f.Crit > bestCrit {
				bestCrit = f.Crit
				bestID = id
			}
			break
		}
	}
	if bestID == "" {
		return nil
	}
	annotated[bestID] = true
	f := findings[bestID]
	desc := f.Desc
	if desc == "" {
		desc = descByID[bestID]
	}
	if desc == "" {
		desc = traitDisplayID(bestID)
	}
	return []rowAnno{{Desc: desc, Crit: critIntToString(f.Crit)}}
}

// windowsMatchTrait checks if the finding with ID==filterID has any span
// intersecting any window's byte range.
func windowsMatchTrait(windows []contextWindow, filterID string, findings map[string]*finding) bool {
	f, ok := findings[filterID]
	if !ok {
		return false
	}
	for w := range windows {
		win := &windows[w]
		base := win.Offset
		if win.Addr != nil {
			base = *win.Addr
		}
		n := len(win.Data)
		for _, sp := range f.Spans {
			off, length := sp[0], sp[1]
			if length <= 0 {
				length = 1
			}
			if off < base+int64(n) && off+length > base {
				return true
			}
		}
	}
	return false
}

// renderSourceWindow renders a run of source lines: each line numbered, its
// code syntax-highlighted, and its matched span(s) lit by severity. Lit notes
// are restricted to filterID when set; filename selects the chroma lexer.
func renderSourceWindow(
	windows []contextWindow, filterID, filename string,
	findingsByID map[string]*finding, descByID map[string]string, annotated map[string]bool,
) contextBlock {
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
		spans, crit := spansForRow(findingsByID, base, len(win.Data), filterID)
		// Clip a long line to a window around its match so the highlighted span
		// (and the trailing annotation) stay in view; short lines pass through.
		clip := clipSourceLine(string(win.Data), primaryMatchCol(findingsByID, base, len(win.Data), filterID))
		spans = shiftSpans(spans, clip.Off, len(clip.Text))
		block.Rows = append(block.Rows, contextRow{
			Loc:   strconv.FormatInt(win.Offset, 10),
			Crit:  crit,
			Segs:  highlightedSegs(clip.Text, spans, filename),
			Annos: rowAnnos(findingsByID, base, len(win.Data), descByID, annotated),
			Lead:  clip.Lead,
			Trail: clip.Trail,
		})
	}
	return block
}

// maxSrcCols caps how much of a source line is shown. The code column wraps, so
// a long line is fully visible; only a pathologically long (minified) line
// beyond this clips to a window around the match. srcLeadCols is the minimum
// lead kept before the match so it isn't flush against the left ellipsis.
const (
	maxSrcCols  = 2000
	srcLeadCols = 28
)

// clippedLine is a source line bounded to maxSrcCols: Text is the view, Off the
// byte it starts at, and Lead/Trail report whether content was elided on each
// side (the template renders an ellipsis).
type clippedLine struct {
	Text  string
	Off   int
	Lead  bool
	Trail bool
}

// clipSourceLine returns a view of text bounded to maxSrcCols. When the line is
// longer it clips to a window holding the match (matchCol, a byte index, or -1
// for a context line with none), keeping ≥srcLeadCols of lead where possible.
// Clip points snap to rune boundaries so multibyte characters are never split.
func clipSourceLine(text string, matchCol int) clippedLine {
	if len(text) <= maxSrcCols {
		return clippedLine{Text: text}
	}
	w0 := 0
	if matchCol >= 0 {
		w0 = max(matchCol-srcLeadCols, 0)
	}
	w1 := w0 + maxSrcCols
	if w1 >= len(text) {
		w1 = len(text)
		w0 = max(len(text)-maxSrcCols, 0)
	}
	for w0 > 0 && !utf8.RuneStart(text[w0]) {
		w0--
	}
	for w1 < len(text) && !utf8.RuneStart(text[w1]) {
		w1++
	}
	return clippedLine{Text: text[w0:w1], Off: w0, Lead: w0 > 0, Trail: w1 < len(text)}
}

// primaryMatchCol returns the byte index, within a line of length n starting at
// base, of the strongest span start within [base, base+n) — the anchor the clip
// centers on. Returns -1 when no (matching) finding begins on this row.
func primaryMatchCol(findings map[string]*finding, base int64, n int, filterID string) int {
	best, bestCrit := -1, -1
	for id, f := range findings {
		if filterID != "" && id != filterID {
			continue
		}
		for _, sp := range f.Spans {
			off := int(sp[0] - base)
			if off < 0 || off >= n {
				continue
			}
			if f.Crit > bestCrit {
				bestCrit, best = f.Crit, off
			}
		}
	}
	return best
}

// shiftSpans rebases match spans onto a clipped line: each span moves left by
// off and is clamped to [0, n); spans fully outside the window drop out.
func shiftSpans(spans []rowSpan, off, n int) []rowSpan {
	if off == 0 && len(spans) == 0 {
		return spans
	}
	out := make([]rowSpan, 0, len(spans))
	for _, s := range spans {
		st, en := s.Start-off, s.End-off
		if en <= 0 || st >= n {
			continue
		}
		out = append(out, rowSpan{Crit: s.Crit, Start: max(st, 0), End: min(en, n)})
	}
	return out
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
func renderHexWindow(
	win *contextWindow, filterID string,
	findingsByID map[string]*finding, descByID map[string]string, annotated map[string]bool,
) contextBlock {
	block := contextBlock{Hex: true}
	for start := 0; start < len(win.Data); start += hexStride {
		if len(block.Rows) >= maxContextRows {
			break
		}
		row := win.Data[start:min(start+hexStride, len(win.Data))]
		rowBase := win.Offset + int64(start)
		spans, crit := spansForRow(findingsByID, rowBase, len(row), filterID)
		// Always emit hexStride cells, padding a short final row with blanks
		// ("  " = the width of a hex pair, " " for ascii). Every hex window then
		// has an identical, fully-populated grid, so the offset / hex / ascii
		// columns line up within a window and across files.
		hexCells := make([]contextSeg, hexStride)
		asciiCells := make([]contextSeg, hexStride)
		for k := range hexStride {
			if k >= len(row) {
				hexCells[k] = contextSeg{Text: "  "}
				asciiCells[k] = contextSeg{Text: " "}
				continue
			}
			b := row[k]
			sev := spanSeverityAt(spans, k)
			hexCells[k] = contextSeg{Text: fmt.Sprintf("%02x", b), Crit: sev}
			asciiCells[k] = contextSeg{Text: printableByte(b), Crit: sev}
		}
		block.Rows = append(block.Rows, contextRow{
			Loc:   fmt.Sprintf("0x%x", rowBase),
			Crit:  crit,
			Segs:  hexCells,
			ASCII: asciiCells,
			Annos: rowAnnos(findingsByID, rowBase, len(row), descByID, annotated),
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

// spansForRow resolves the finding spans that intersect a row whose content
// starts at byte offset base and is n bytes long, into row-relative spans.
// filterID, when set, keeps only that finding's spans. The second return is
// the strongest severity class touching the row (for the gutter), empty when
// none do.
func spansForRow(findings map[string]*finding, base int64, n int, filterID string) (spans []rowSpan, crit string) {
	topCrit := -1
	for id, f := range findings {
		if filterID != "" && id != filterID {
			continue
		}
		for _, sp := range f.Spans {
			off, length := sp[0], sp[1]
			if length <= 0 {
				length = 1
			}
			start := int(off - base)
			end := start + int(length)
			if end <= 0 || start >= n {
				continue
			}
			start = max(start, 0)
			end = min(end, n)
			sev := critIntToString(f.Crit)
			spans = append(spans, rowSpan{Start: start, End: end, Crit: sev})
			if f.Crit > topCrit {
				topCrit = f.Crit
				crit = sev
			}
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
