package main

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
)

// The Content tab is the default view. It mirrors cleave's content-centric
// shape: per file, each context window is shown once, headed by the traits
// whose notes fall inside it, with every match lit in its severity color. A
// trait is either highlighted inside a window or it does not appear — cleave
// dedups overlapping matches to the strongest, so weaker/unlocated traits have
// no window and are dropped here too.
//
// Files are ordered by criticality. A cross-file composite has no local window
// (its evidence lives in the members it fired on); its name is folded inline
// into the primary member's source, and it surfaces whole in the top-traits
// headline with a clickable member trail. Inherited findings render in their
// origin member, not on the container. There are no standalone composite cards.
//
// Only files carrying current-format context drive this view; legacy reports
// return nil and the page keeps the Traits tab as its default.

// minFileCrit is the criticality floor for cross-file composites listed without
// a window: notable and above. (Window traits are shown whenever cleave kept a
// note for them, which already encodes its own threshold.)
const minFileCrit = 3

// minContentCrit is the criticality floor for rendering an archive member's
// content (hex/source context) at all. Members whose top trait is below baseline
// (component/filtered) are noise inside a large archive, so their content view is
// skipped entirely. The top-level file the user navigated to (depth 0) is always
// shown regardless.
const minContentCrit = 2

// maxWindowsPerFile caps the context windows shown for a single file — its
// strongest, in file order. maxFilesShown caps how many files render at all;
// the rest (lower criticality) are omitted with a note, so a large archive
// stays legible instead of rendering hundreds of windows.
const (
	maxWindowsPerFile = 5
	maxFilesShown     = 5
)

// maxMemberFetch bounds how many archive members the detail page pulls from
// hopper. Above maxFilesShown to leave room for the members a cross-file
// composite points at, which render regardless of their own criticality, but
// nowhere near unbounded: every member fetched is a row read, a JSON parse and
// a slice of envelope that the caps above may never render.
const maxMemberFetch = 12

// maxEvidenceBlocks caps the whole page, not just one file. Five regions is
// what a reader actually reads; a five-file archive allowed five each turned
// the evidence list into a scroll. The five kept are the highest-scoring
// across every file (windowScore), so a strong region in the third member
// outranks a weak one in the first.
const maxEvidenceBlocks = 5

// windowScore ranks a region for both the per-file cap and the page-wide one:
// whether it backs a headline trait dominates, then whether it is one of our
// own traits rather than an imported vendor signature, then severity. Ordering
// by a single number keeps the two caps agreeing on what "strongest" means.
func windowScore(lw *labeledWindow, wanted map[string]bool) int {
	head := lw.headNote(wanted)
	rank := 0
	if wanted[head.ID] {
		rank += 2
	}
	if !traitIsVendor(head.ID) {
		rank++
	}
	return rank*8 + lw.Crit
}

// contentOmitted counts what the file cap dropped from the Content tab: how many
// files, and how many results (context windows + composite findings) those files
// held — both surfaced in the "results limited" note.
type contentOmitted struct {
	Files   int
	Results int
}

// fileView is one file's section in the Content tab.
type fileView struct {
	Path     string
	Filename string
	FileType string
	SHA256   string
	Anchor   string // in-page link target, "file-<sha>"
	Crit     string // severity class of the file's strongest finding
	Windows  []fileWindow
	// Solo is true when this is the only file on the page, so its regions drop
	// the filename from their location line — the hero already carries it.
	Solo bool
}

// fileWindow is one rendered context window. Its traits are labeled inline on
// the rows their matches begin on (see rowAnno), so no separate header is kept.
// Blocks always holds exactly one block (a slice so the shared ctxblocks
// template renders it).
type fileWindow struct {
	// Title names the region by its strongest finding; Crit is that
	// finding's severity class; Range is the lines the region covers.
	Title  string
	Crit   string
	Range  string
	Blocks []contextBlock
}

// compositeLink points a cross-file composite at one member it drew from. Anchor
// is set only when that member has its own rendered section, so links never
// dangle.
type compositeLink struct {
	Label  string
	Anchor string
	Loc    string
}

// fileData is one file's windows while the caps are still being applied: the
// evidence list is chosen across files, so the per-file sets have to outlive
// the loop that builds them.
type fileData struct {
	file    *cleaveFile
	lws     []labeledWindow
	maxCrit int
}

// capEvidenceBlocks trims the whole page to maxEvidenceBlocks regions, keeping
// the highest-scoring across every file and leaving each file's survivors in
// file order. Returns how many it dropped, for the "results limited" note.
func capEvidenceBlocks(datas []fileData, wanted map[string]bool) int {
	total := 0
	for d := range datas {
		total += len(datas[d].lws)
	}

	type ref struct{ file, win, score int }
	if total <= maxEvidenceBlocks {
		return 0
	}
	refs := make([]ref, 0, total)
	for d := range datas {
		for w := range datas[d].lws {
			refs = append(refs, ref{d, w, windowScore(&datas[d].lws[w], wanted)})
		}
	}
	slices.SortStableFunc(refs, func(a, b ref) int { return cmp.Compare(b.score, a.score) })
	keep := make([]map[int]bool, len(datas))
	for _, r := range refs[:maxEvidenceBlocks] {
		if keep[r.file] == nil {
			keep[r.file] = make(map[int]bool)
		}
		keep[r.file][r.win] = true
	}
	for d := range datas {
		kept := make([]labeledWindow, 0, len(keep[d]))
		for w := range datas[d].lws {
			if keep[d][w] {
				kept = append(kept, datas[d].lws[w])
			}
		}
		datas[d].lws = kept
	}
	return total - maxEvidenceBlocks
}

// buildFileViews assembles the Content tab from cleave's per-file context and
// findings. The second return reports what the maxFilesShown cap dropped, for
// the "results limited" note. Returns nil when no file carries current-format
// context.
func buildFileViews(files []cleaveFile) ([]fileView, []topTrait, contentOmitted) {
	rich := false
	for i := range files {
		if hasRichContext(&files[i]) {
			rich = true
			break
		}
	}
	if !rich {
		return nil, nil, contentOmitted{}
	}

	idToFile := make(map[int]*cleaveFile, len(files))
	for i := range files {
		idToFile[files[i].ID] = &files[i]
	}

	forced, inject := compositeLegs(files)

	// Pick the headline traits up front and force-render the files they point at,
	// so every top-trait location resolves to a real, clickable section instead of
	// dangling past the file cap.
	tcands := headlineTraits(files)
	for _, c := range tcands {
		for _, id := range traitTargetIDs(c.f, c.host) {
			if c.crit > forced[id] {
				forced[id] = c.crit
			}
		}
	}

	var datas []fileData

	for i := range files {
		file := &files[i]

		fd := fileData{file: file}
		for _, lw := range labeledWindows(file) {
			fd.lws = append(fd.lws, lw)
			if lw.Crit > fd.maxCrit {
				fd.maxCrit = lw.Crit
			}
		}

		// Composites are folded into the source view, not shown as separate cards:
		// a composite's primary leg carries the composite name inline on the row at
		// its first source location (the other legs keep the native trait that
		// fired there). Cross-file composites surface as a whole in the top-traits
		// headline (with a member trail), so there are no bare composite cards.
		// No span landed in any window, so nothing got labeled. When the file
		// carries a suspicious finding of its own, its windows are still the
		// bytes cleave chose to show, so show them rather than dropping the
		// file's evidence entirely (unlabeledWindows decides).
		if len(fd.lws) == 0 {
			for _, lw := range unlabeledWindows(file) {
				fd.lws = append(fd.lws, lw)
				if lw.Crit > fd.maxCrit {
					fd.maxCrit = lw.Crit
				}
			}
		}
		for _, a := range inject[file.ID] {
			attachComposite(fd.lws, a)
		}

		// Inside-archive members below the content-criticality floor are noise;
		// skip building their content view entirely. The top-level file (depth 0)
		// is what the user navigated to, so it always renders. A member that a
		// cross-file composite drew from is evidence for that composite, so it
		// renders regardless of its own crit and sorts up to the composite's, so
		// its window survives the file cap and the composite's trail links land.
		lowCrit := file.Depth > 0 && maxCritInFile(file) < minContentCrit
		if c, ok := forced[file.ID]; ok {
			lowCrit = false
			if c > fd.maxCrit {
				fd.maxCrit = c
			}
		}
		if !lowCrit && len(fd.lws) > 0 {
			datas = append(datas, fd)
		}
	}
	if len(datas) == 0 {
		return nil, nil, contentOmitted{}
	}

	slices.SortStableFunc(datas, func(a, b fileData) int { return cmp.Compare(b.maxCrit, a.maxCrit) })

	// Show the top maxFilesShown files (by criticality); the rest are omitted
	// with a note tallying the files and the results (windows + composites) they
	// held. Cap each shown file to its strongest maxWindowsPerFile windows.
	// Record which files render first so composite member links only point at
	// sections that exist.
	var omitted contentOmitted
	if len(datas) > maxFilesShown {
		for _, fd := range datas[maxFilesShown:] {
			omitted.Files++
			omitted.Results += len(fd.lws)
		}
		datas = datas[:maxFilesShown]
	}
	wanted := headlineAtomics(tcands)
	for d := range datas {
		datas[d].lws = capWindows(datas[d].lws, wanted)
	}
	omitted.Results += capEvidenceBlocks(datas, wanted)
	datas = slices.DeleteFunc(datas, func(fd fileData) bool { return len(fd.lws) == 0 })
	// Recorded after both caps: a composite's member trail must only link files
	// that still have a section to land on.
	rendered := make(map[string]bool, len(datas))
	for d := range datas {
		rendered[datas[d].file.SHA256] = true
	}

	views := make([]fileView, 0, len(datas))
	for d := range datas {
		fd := &datas[d]
		view := fileView{
			Path:     displayPath(fd.file.Path),
			Filename: extractBasename(fd.file.Path),
			FileType: fd.file.FileType,
			SHA256:   fd.file.SHA256,
			Anchor:   "file-" + fd.file.SHA256,
			Crit:     critIntToString(fd.maxCrit),
		}
		for _, lw := range fd.lws {
			w := fileWindow{Blocks: []contextBlock{foldContext(lw.Block)}, Range: windowRange(lw.Block)}
			if head := lw.headNote(wanted); head.ID != "" {
				w.Title = head.Desc
				if w.Title == "" {
					w.Title = traitChipID(head.ID)
				}
				w.Crit = critIntToString(head.Crit)
			}
			view.Windows = append(view.Windows, w)
		}
		views = append(views, view)
	}
	if len(views) == 1 {
		views[0].Solo = true
	}
	top := make([]topTrait, len(tcands))
	for i, c := range tcands {
		top[i] = topTrait{
			Desc:    c.desc,
			Crit:    critIntToString(c.crit),
			Sources: traitSources(c.f, c.host, idToFile, rendered),
		}
	}
	return views, top, omitted
}

// topTrait is one entry in the Content tab's headline: a most-significant trait,
// shown as its description plus a clickable "filename:loc" trail (Sources). Every
// entry — atomic, single-leg, or cross-file composite — carries the location so
// it reads the same and its navigability is obvious.
type topTrait struct {
	Desc    string
	Crit    string // severity class for coloring
	Sources []compositeLink
}

// topCand is a selected headline trait before its links are resolved against the
// finally-rendered file set. buildFileViews force-renders each candidate's target
// files (traitTargetIDs) so the resolved links land.
type topCand struct {
	f    *finding
	host *cleaveFile
	desc string
	crit int
}

// maxTopTraits caps the headline. Three keeps it a glanceable summary, not a
// second findings list.
const maxTopTraits = 3

// headlineTraits picks the sample's most significant traits — highest
// crit×confidence, suspicious or above — across every file, atomic and composite
// alike, deduped by trait ID and capped at maxTopTraits. Offset-0 noise is
// excluded, matching the content view. Links are resolved later (traitSources).
func headlineTraits(files []cleaveFile) []topCand {
	type scored struct {
		topCand

		score float64
	}
	best := make(map[string]scored)
	for i := range files {
		for j := range files[i].Findings {
			f := &files[i].Findings[j]
			if f.Crit < minSuspiciousCrit || isOffsetZeroNoise(f) {
				continue
			}
			score := float64(f.Crit) * f.Conf
			if e, ok := best[f.ID]; ok && e.score >= score {
				continue
			}
			desc := f.Desc
			if desc == "" {
				desc = traitDisplayID(f.ID)
			}
			best[f.ID] = scored{topCand{f: f, host: &files[i], desc: desc, crit: f.Crit}, score}
		}
	}
	all := make([]scored, 0, len(best))
	for _, s := range best {
		all = append(all, s)
	}
	slices.SortStableFunc(all, func(a, b scored) int {
		return cmp.Or(cmp.Compare(b.score, a.score), cmp.Compare(a.desc, b.desc))
	})
	if len(all) > maxTopTraits {
		all = all[:maxTopTraits]
	}
	out := make([]topCand, len(all))
	for i, s := range all {
		out[i] = s.topCand
	}
	return out
}

// traitTargetIDs lists the file IDs a top trait points at — every leg of a
// composite/inherited finding, or the host for a native one — so buildFileViews
// can force-render them and keep the headline's links live.
func traitTargetIDs(f *finding, host *cleaveFile) []int {
	if len(f.From) > 0 {
		ids := make([]int, 0, len(f.From))
		for _, s := range f.From {
			ids = append(ids, s.File)
		}
		return ids
	}
	return []int{host.ID}
}

// traitSources renders a top trait's "filename:loc" trail: every leg of a
// composite/inherited finding, or the host file for a native one. A leg links to
// its section when that file rendered (force-rendering the targets keeps these
// live); otherwise the location shows as plain text.
func traitSources(f *finding, host *cleaveFile, idToFile map[int]*cleaveFile, rendered map[string]bool) []compositeLink {
	if len(f.From) > 0 {
		return compositeLinks(f.From, idToFile, rendered)
	}
	link := compositeLink{Label: extractBasename(host.Path)}
	if rendered[host.SHA256] {
		link.Anchor = "file-" + host.SHA256
	}
	if len(f.Spans) > 0 {
		link.Loc = "0x" + strconv.FormatInt(f.Spans[0][0], 16)
	}
	return []compositeLink{link}
}

// anchorAnno is a composite annotation to attach inline on its primary member:
// the composite's description, placed on the row at its first leg's location.
type anchorAnno struct {
	src  compactSource
	desc string
	crit int
}

// compositeLegs scans every file for cross-file composites (multi-member From at
// notable+) and returns, keyed by member file ID, the data the Content tab needs
// to show a composite's members. forced maps a leg's file to the strongest
// composite crit referencing it, so the member renders even below the content
// floor and sorts up to its composite. inject maps a composite's primary leg
// (From[0]) to the annotation that names the composite on that member's window;
// the other legs keep the native trait that fired there.
func compositeLegs(files []cleaveFile) (forced map[int]int, inject map[int][]anchorAnno) {
	forced = map[int]int{}
	inject = map[int][]anchorAnno{}
	for i := range files {
		for j := range files[i].Findings {
			f := &files[i].Findings[j]
			if len(f.From) <= 1 || f.Crit < minFileCrit {
				continue
			}
			for _, s := range f.From {
				if c, ok := forced[s.File]; !ok || f.Crit > c {
					forced[s.File] = f.Crit
				}
			}
			desc := f.Desc
			if desc == "" {
				desc = traitDisplayID(f.ID)
			}
			first := f.From[0]
			inject[first.File] = append(inject[first.File], anchorAnno{src: first, desc: desc, crit: f.Crit})
		}
	}
	return forced, inject
}

// attachComposite annotates the window row at the leg's location with the
// composite's description, so a composite's primary member carries the composite
// name inline. Per cleave's one-comment-per-line rule it replaces the row's
// native annotation. It is a no-op when the location falls outside every
// rendered window — the composite still shows on the container with a link here.
func attachComposite(lws []labeledWindow, a anchorAnno) {
	for w := range lws {
		rows := lws[w].Block.Rows
		for r := range rows {
			if legAtRow(a.src, &rows[r]) {
				rows[r].Annos = []rowAnno{{Desc: a.desc, Crit: critIntToString(a.crit)}}
				return
			}
		}
	}
}

// legAtRow reports whether a composite leg's location falls on a context row: a
// source leg matches by line number, a binary leg by the hex row's byte range.
func legAtRow(s compactSource, row *contextRow) bool {
	switch {
	case s.Line != nil:
		return row.Loc == strconv.FormatInt(*s.Line, 10)
	case s.Offset != nil:
		base, err := strconv.ParseInt(strings.TrimPrefix(row.Loc, "0x"), 16, 64)
		if err != nil {
			return false
		}
		return *s.Offset >= base && *s.Offset < base+hexStride
	}
	return false
}

// capWindows keeps a file's strongest maxWindowsPerFile windows but renders them
// in file order, so the most important context survives the cap while the view
// still reads top-to-bottom by offset.
func capWindows(lws []labeledWindow, wanted map[string]bool) []labeledWindow {
	// One region per behaviour. A composite that fired on eight scattered
	// matches used to produce eight regions carrying one identical sentence;
	// the reader learns nothing from the second. Keep the strongest window for
	// each heading and let the rest go.
	kept := make([]labeledWindow, 0, len(lws))
	best := make(map[string]int, len(lws))
	for i := range lws {
		head := lws[i].headNote(wanted)
		at, seen := best[head.ID]
		if !seen {
			best[head.ID] = len(kept)
			kept = append(kept, lws[i])
			continue
		}
		if lws[i].Crit > kept[at].Crit {
			kept[at] = lws[i]
		}
	}
	// Show the evidence for the verdict, not every window in the file. When any
	// region backs one of the headline traits, those are the regions worth a
	// reader's time and the rest are a second findings list in disguise.
	backing := make([]labeledWindow, 0, len(kept))
	for i := range kept {
		if wanted[kept[i].headNote(wanted).ID] {
			backing = append(backing, kept[i])
		}
	}
	if len(backing) > 0 {
		kept = backing
	}
	lws = kept
	if len(lws) <= maxWindowsPerFile {
		slices.SortStableFunc(lws, func(a, b labeledWindow) int { return cmp.Compare(a.Start, b.Start) })
		return lws
	}
	// Rank what survives by whether it backs a headline trait, then by
	// severity, so the regions shown are the evidence for the verdict above.
	slices.SortStableFunc(lws, func(a, b labeledWindow) int {
		return cmp.Compare(windowScore(&b, wanted), windowScore(&a, wanted))
	})
	lws = lws[:maxWindowsPerFile]
	slices.SortStableFunc(lws, func(a, b labeledWindow) int { return cmp.Compare(a.Start, b.Start) })
	return lws
}

// traitIsVendor reports whether a trait is an imported third-party signature
// rather than one of our own behaviour rules. A vendor rule is an attribution —
// "SigBase thinks this is Cobalt Strike" — and its match is a string set, not a
// behaviour, so it makes weak evidence and a poor region heading. It stays
// eligible (on some samples it is all there is) but yields to a first-party
// trait wherever one covers the same bytes.
func traitIsVendor(id string) bool { return strings.HasPrefix(id, "third_party/") }

// headNote picks the note a region is titled by: the strongest atomic backing a
// headline trait, else the strongest atomic, else whatever is left. Composites
// are demoted on purpose — the verdict and the badges already name them, and
// what a reader needs beside the bytes is which matcher hit them.
func (lw *labeledWindow) headNote(wanted map[string]bool) ctxNoteRef {
	// Notes arrive strongest-first, so the first match in each tier is the
	// strongest of that tier. Preference runs: our own trait backing a headline
	// finding, our own trait, a vendor signature backing a headline finding,
	// any vendor signature — then, only if nothing atomic landed here, the
	// composite that did.
	var tier [4]*ctxNoteRef
	for i := range lw.Notes {
		n := &lw.Notes[i]
		if !n.Atomic {
			continue
		}
		slot := 0
		if traitIsVendor(n.ID) {
			slot = 2
		}
		if !wanted[n.ID] {
			slot++
		}
		if tier[slot] == nil {
			tier[slot] = n
		}
	}
	for _, n := range tier {
		if n != nil {
			return *n
		}
	}
	if len(lw.Notes) > 0 {
		return lw.Notes[0]
	}
	return ctxNoteRef{}
}

// headlineAtomics names the matchers the headline traits rest on: a composite
// contributes the traits it used (transitively, since a composite may be built
// from composites), an atomic contributes itself. Uses indexes the host file's
// own findings, so resolution never leaves that file.
func headlineAtomics(cands []topCand) map[string]bool {
	want := make(map[string]bool, len(cands)*4)
	var walk func(f *finding, host *cleaveFile, depth int)
	walk = func(f *finding, host *cleaveFile, depth int) {
		if len(f.Uses) == 0 || depth > 4 {
			want[f.ID] = true
			return
		}
		for _, j := range f.Uses {
			if j < 0 || j >= len(host.Findings) {
				continue // a stale index names a finding this report does not carry
			}
			walk(&host.Findings[j], host, depth+1)
		}
	}
	for i := range cands {
		walk(cands[i].f, cands[i].host, 0)
	}
	return want
}

// contentLocCh returns the widest Loc string for source line numbers and for
// hex offsets separately, across every rendered context row. The Content tab
// applies each as the loc-column width for its kind, so columns align within and
// between files of the same kind without a hex offset bloating source gutters.
func contentLocCh(views []fileView) (src, hex int) {
	for i := range views {
		for _, w := range views[i].Windows {
			for _, b := range w.Blocks {
				n := &src
				if b.Hex {
					n = &hex
				}
				for _, r := range b.Rows {
					if len(r.Loc) > *n {
						*n = len(r.Loc)
					}
				}
			}
		}
	}
	return src, hex
}

// compositeLinks resolves a composite's member sources into display rows,
// linking to a member's section when it is itself rendered.
func compositeLinks(sources []compactSource, idToFile map[int]*cleaveFile, rendered map[string]bool) []compositeLink {
	if len(sources) == 0 {
		return nil
	}
	links := make([]compositeLink, 0, len(sources))
	for _, s := range sources {
		member, ok := idToFile[s.File]
		if !ok {
			continue
		}
		link := compositeLink{Label: extractBasename(member.Path), Loc: sourceLoc(s)}
		if rendered[member.SHA256] {
			link.Anchor = "file-" + member.SHA256
		}
		links = append(links, link)
	}
	return links
}

// sourceLoc formats a composite source's anchor for the "file:loc" trail: a
// 1-based line when known, else a hex byte offset, else empty.
func sourceLoc(s compactSource) string {
	switch {
	case s.Line != nil:
		return strconv.FormatInt(*s.Line, 10)
	case s.Offset != nil:
		return "0x" + strconv.FormatInt(*s.Offset, 16)
	default:
		return ""
	}
}

// traitDisplayID drops the top-level category prefix from a full trait ID for
// display, matching the Traits tab (e.g. "objectives/execution/eval" ->
// "execution/eval"). The leading segment is the category, shown elsewhere.
func traitDisplayID(id string) string {
	if _, rest, found := strings.Cut(id, "/"); found {
		return rest
	}
	return id
}
