package main

import (
	"sort"
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
// (its evidence lives in the members it fired on); it shows as a labeled entry
// with a linkable member trail. Inherited findings (Src set) render in their
// origin member, not on the container.
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
	maxWindowsPerFile = 12
	maxFilesShown     = 10
)

// contentOmitted counts what the file cap dropped from the Content tab: how many
// files, and how many results (context windows + composite findings) those files
// held — both surfaced in the "results limited" note.
type contentOmitted struct {
	Files   int
	Results int
}

// fileView is one file's section in the Content tab.
type fileView struct {
	Path       string
	Filename   string
	FileType   string
	SHA256     string
	Anchor     string // in-page link target, "file-<sha>"
	Crit       string // severity class of the file's strongest finding
	Composites []compositeFinding
	Windows    []fileWindow
}

// fileWindow is one rendered context window. Its traits are labeled inline on
// the rows their matches begin on (see rowAnno), so no separate header is kept.
// Blocks always holds exactly one block (a slice so the shared ctxblocks
// template renders it).
type fileWindow struct {
	Blocks []contextBlock
}

// compositeFinding is a cross-file conclusion with no window of its own: it
// shows its member trail instead.
type compositeFinding struct {
	ID      string
	Desc    string
	Crit    string
	Sources []compositeLink
}

// compositeLink points a cross-file composite at one member it drew from. Anchor
// is set only when that member has its own rendered section, so links never
// dangle.
type compositeLink struct {
	Label  string
	Anchor string
	Loc    string
}

// buildFileViews assembles the Content tab from cleave's per-file context and
// findings. The second return reports what the maxFilesShown cap dropped, for
// the "results limited" note. Returns nil when no file carries current-format
// context.
func buildFileViews(files []cleaveFile) ([]fileView, contentOmitted) {
	rich := false
	for i := range files {
		if hasRichContext(&files[i]) {
			rich = true
			break
		}
	}
	if !rich {
		return nil, contentOmitted{}
	}

	idToFile := make(map[int]*cleaveFile, len(files))
	for i := range files {
		idToFile[files[i].ID] = &files[i]
	}

	type fileData struct {
		file       *cleaveFile
		lws        []labeledWindow
		composites []*finding
		maxCrit    int
	}
	var datas []fileData

	for i := range files {
		file := &files[i]

		shown := make(map[string]bool)
		fd := fileData{file: file}
		for _, lw := range labeledWindows(file) {
			for _, n := range lw.Notes {
				shown[n.ID] = true // covered by a window; skip as a bare composite
			}
			fd.lws = append(fd.lws, lw)
			if lw.Crit > fd.maxCrit {
				fd.maxCrit = lw.Crit
			}
		}

		// Cross-file composites native to this file that didn't anchor a local
		// window: list them with their member trail.
		for j := range file.Findings {
			f := &file.Findings[j]
			if len(f.From) <= 1 || f.Crit < minFileCrit || shown[f.ID] {
				continue
			}
			fd.composites = append(fd.composites, f)
			if f.Crit > fd.maxCrit {
				fd.maxCrit = f.Crit
			}
		}
		sort.SliceStable(fd.composites, func(a, b int) bool {
			return fd.composites[a].Crit > fd.composites[b].Crit
		})

		// Inside-archive members below the content-criticality floor are noise;
		// skip building their content view entirely. The top-level file (depth 0)
		// is what the user navigated to, so it always renders.
		lowCrit := file.Depth > 0 && maxCritInFile(file) < minContentCrit
		if !lowCrit && (len(fd.lws) > 0 || len(fd.composites) > 0) {
			datas = append(datas, fd)
		}
	}
	if len(datas) == 0 {
		return nil, contentOmitted{}
	}

	sort.SliceStable(datas, func(a, b int) bool { return datas[a].maxCrit > datas[b].maxCrit })

	// Show the top maxFilesShown files (by criticality); the rest are omitted
	// with a note tallying the files and the results (windows + composites) they
	// held. Cap each shown file to its strongest maxWindowsPerFile windows.
	// Record which files render first so composite member links only point at
	// sections that exist.
	var omitted contentOmitted
	if len(datas) > maxFilesShown {
		for _, fd := range datas[maxFilesShown:] {
			omitted.Files++
			omitted.Results += len(fd.lws) + len(fd.composites)
		}
		datas = datas[:maxFilesShown]
	}
	rendered := make(map[string]bool)
	for d := range datas {
		datas[d].lws = capWindows(datas[d].lws)
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
			view.Windows = append(view.Windows, fileWindow{Blocks: []contextBlock{lw.Block}})
		}
		for _, f := range fd.composites {
			view.Composites = append(view.Composites, compositeFinding{
				ID:      traitDisplayID(f.ID),
				Desc:    f.Desc,
				Crit:    critIntToString(f.Crit),
				Sources: compositeLinks(f.From, idToFile, rendered),
			})
		}
		views = append(views, view)
	}
	return views, omitted
}

// capWindows keeps a file's strongest maxWindowsPerFile windows but renders them
// in file order, so the most important context survives the cap while the view
// still reads top-to-bottom by offset.
func capWindows(lws []labeledWindow) []labeledWindow {
	if len(lws) <= maxWindowsPerFile {
		return lws
	}
	sort.SliceStable(lws, func(i, j int) bool { return lws[i].Crit > lws[j].Crit })
	lws = lws[:maxWindowsPerFile]
	sort.SliceStable(lws, func(i, j int) bool { return lws[i].Start < lws[j].Start })
	return lws
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
