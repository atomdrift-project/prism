package main

import (
	"sort"
	"strconv"
	"strings"
)

// The File tab is the default view: one section per file, ordered by
// criticality, each showing the top findings aimed at that file with their
// source/hex context. It mirrors cleave's multi-file rendering:
//
//   - A finding with Src set was inherited from an embedded member; it renders
//     in that member's section, not on the container. We therefore show only
//     native findings (Src == nil) on each file.
//   - A cross-file composite is native to the container and carries Sources —
//     the members it fired on. We show those as a linkable trail instead of a
//     byte window, since the composite has no single location of its own.
//
// Only files with current-format context drive this view; legacy reports return
// no views and the page keeps the Traits tab as its default.

// minFileCrit is the criticality floor for the File tab: notable and above. The
// lower component/baseline tiers are cleave's scaffolding, surfaced in the
// exhaustive Traits tab but not in this curated top-findings view.
const minFileCrit = 3

// maxFileFindings caps how many findings the File tab shows across all files —
// the "top dozen" the user asked for, mirroring cleave's top-N output cap.
const maxFileFindings = 12

// fileView is one file's section in the File tab.
type fileView struct {
	Path     string
	Filename string
	FileType string
	SHA256   string
	Anchor   string // in-page link target, "file-<sha>"
	Crit     string // severity class of the file's strongest shown finding
	Findings []fileFinding
}

// fileFinding is one trait shown in a file section, with its rendered context
// (atomic/file-aimed traits) or its composite member trail (cross-file).
type fileFinding struct {
	ID      string
	Desc    string
	Crit    string
	Context []contextBlock
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

// buildFileViews assembles the File tab from cleave's per-file findings and
// context. Returns nil when no file carries current-format context, so the
// caller falls back to the Traits-tab default.
func buildFileViews(files []cleaveFile) []fileView {
	rich := false
	for i := range files {
		if hasRichContext(&files[i]) {
			rich = true
			break
		}
	}
	if !rich {
		return nil
	}

	idToFile := make(map[int]*cleaveFile, len(files))
	for i := range files {
		idToFile[files[i].ID] = &files[i]
	}

	type candidate struct {
		file  *cleaveFile
		f     *finding
		score float64
	}
	var cands []candidate
	for i := range files {
		file := &files[i]
		for j := range file.Findings {
			f := &file.Findings[j]
			if f.Src != nil { // inherited — rendered in its origin member
				continue
			}
			if f.Crit < minFileCrit || f.Conf < minTraitConfidence {
				continue
			}
			cands = append(cands, candidate{file: file, f: f, score: float64(f.Crit) * f.Conf})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		if cands[i].f.Crit != cands[j].f.Crit {
			return cands[i].f.Crit > cands[j].f.Crit
		}
		return cands[i].f.ID < cands[j].f.ID
	})
	if len(cands) > maxFileFindings {
		cands = cands[:maxFileFindings]
	}

	// Group the kept findings under their file, preserving the score order so
	// the strongest file's section leads (criticality order).
	order := make([]*cleaveFile, 0)
	grouped := make(map[*cleaveFile][]*finding)
	rendered := make(map[string]bool)
	for i := range cands {
		c := &cands[i]
		if _, seen := grouped[c.file]; !seen {
			order = append(order, c.file)
			rendered[c.file.SHA256] = true
		}
		grouped[c.file] = append(grouped[c.file], c.f)
	}

	views := make([]fileView, 0, len(order))
	for _, file := range order {
		view := fileView{
			Path:     displayPath(file.Path),
			Filename: extractBasename(file.Path),
			FileType: file.FileType,
			SHA256:   file.SHA256,
			Anchor:   "file-" + file.SHA256,
		}
		for _, f := range grouped[file] {
			if view.Crit == "" {
				view.Crit = critIntToString(f.Crit)
			}
			view.Findings = append(view.Findings, fileFinding{
				ID:      traitDisplayID(f.ID),
				Desc:    f.Desc,
				Crit:    critIntToString(f.Crit),
				Context: buildContextBlocks(file, f.ID),
				Sources: compositeLinks(f.Sources, idToFile, rendered),
			})
		}
		views = append(views, view)
	}
	return views
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

// sourceLoc formats a composite source's anchor: a 1-based line when known,
// else a hex byte offset, else empty.
func sourceLoc(s compactSource) string {
	switch {
	case s.Line != nil:
		return "line " + strconv.FormatInt(*s.Line, 10)
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
