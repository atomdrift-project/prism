package main

import (
	"cmp"
	"slices"
	"strings"
)

// maxFlaggedDeps bounds how many dependency chips the panel renders. A crafted
// sample can declare an unbounded number of hostile references; the panel exists
// to explain the verdict at a glance, so it shows the worst few and points the
// remainder at the Structure tab rather than growing without limit.
const maxFlaggedDeps = 24

// flaggedDep is one fetched dependency whose own scan classified suspicious or
// hostile — the sample reached out for it, and what came back was bad. It is a
// pure display object: the chip's text, the record it links to, and nothing the
// analysis itself owns.
type flaggedDep struct {
	// Label is the chip text: "npm: zaboodle v1.49" for a declared package,
	// "x.y.z/x.exe" for a bare URL reference. Capped for display; Locator
	// keeps the whole thing.
	Label string
	// Locator is the full PURL/URL the dependency was declared at, shown as
	// the chip's tooltip. Attacker-authored, so it is never used for layout.
	Locator string
	// Kind is the fetched payload's sniffed type ("pe", "shell"), rendered as
	// a small tag beside the label. Empty for a package chip, where the
	// ecosystem already names what it is.
	Kind   string
	SHA256 string
	// Href is the dependency's own record, empty when its sha is missing or
	// malformed — the chip then renders as a plain span, same as an
	// unlinkable evidence chip on the feed.
	Href  string
	Crit  string // "hostile" / "suspicious"
	critN int
}

// flaggedDeps selects the fetched dependencies worth surfacing above the tabs:
// children pulled over the network whose own verdict came back suspicious or
// hostile, worst first. Benign dependencies are deliberately absent — the panel
// answers "why is this sample elevated", not "what does it reference" (the
// Structure tab does that). Sidecars are skipped: a registry record about a
// dependency is provenance, not the payload. Returns the capped chips and how
// many were dropped, so the panel can say so instead of silently truncating.
func flaggedDeps(files []cleaveFile) (flagged []flaggedDep, dropped int) {
	declared := declaredLocators(files)

	var deps []flaggedDep
	seen := make(map[string]bool, len(files))
	for i := range files {
		f := &files[i]
		if f.Rel != "fetched" || f.Role == "sidecar" {
			continue
		}
		crit, ok := classificationClass(f.Classification)
		if !ok || crit < 1 {
			continue // benign, or a file the ml pass never scored
		}
		locator := declared[f.ID]
		if locator == "" {
			locator = f.Via
		}
		if locator == "" {
			continue // nothing to name it by; the Structure tab still lists it
		}
		// Dedup on identity: the same payload reached twice (two manifests,
		// one tarball) is one dependency, not two chips.
		key := f.SHA256
		if !validSHA256(key) {
			key = locator
		}
		if seen[key] {
			continue
		}
		seen[key] = true

		dep := flaggedDep{
			Locator: locator,
			SHA256:  f.SHA256,
			Crit:    f.Classification,
			critN:   crit,
		}
		if eco, name, version, isPURL := purlCoords(locator); isPURL {
			dep.Label = eco + ": " + name
			if version != "" {
				dep.Label += " v" + version
			}
		} else {
			dep.Label = urlCoords(locator)
			if f.FileType != "" && f.FileType != "unknown" {
				dep.Kind = f.FileType
			}
		}
		dep.Label = truncateRunes(dep.Label, 60)
		if validSHA256(f.SHA256) {
			dep.Href = "/file/" + f.SHA256
		}
		deps = append(deps, dep)
	}

	slices.SortStableFunc(deps, func(a, b flaggedDep) int {
		return cmp.Or(cmp.Compare(b.critN, a.critN), cmp.Compare(a.Label, b.Label))
	})
	if len(deps) > maxFlaggedDeps {
		return deps[:maxFlaggedDeps], len(deps) - maxFlaggedDeps
	}
	return deps, 0
}

// declaredLocators maps each resolved file id to the locator its referrer
// declared it at, preferring a PURL over a raw URL. A fetched file's Via is the
// URL the fetch actually went to (a registry tarball URL); the manifest's PURL
// is what a reader recognizes, so the chip names the dependency the way the
// sample asked for it.
func declaredLocators(files []cleaveFile) map[int]string {
	declared := make(map[int]string)
	for i := range files {
		for _, ref := range files[i].Refs {
			if ref.TargetFile == nil || ref.To == "" {
				continue
			}
			id := *ref.TargetFile
			// First locator wins, except that a PURL always displaces a URL.
			if cur, ok := declared[id]; ok && (isPURL(cur) || !isPURL(ref.To)) {
				continue
			}
			declared[id] = ref.To
		}
	}
	return declared
}

// isPURL reports whether a locator is a package URL rather than a plain URL.
func isPURL(locator string) bool {
	return strings.HasPrefix(locator, "pkg:")
}
