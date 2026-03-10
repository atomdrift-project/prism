package main

import (
	"math"
	"path/filepath"
	"sort"
	"strings"
)

// Element represents a periodic table element.
type Element struct {
	Symbol string
	Name   string
	Number int
}

// Severity levels for coloring atoms.
type Severity int

const (
	SeverityNeutral Severity = iota
	SeverityNotable
	SeveritySuspicious
	SeverityHostile
)

func (s Severity) String() string {
	switch s {
	case SeverityHostile:
		return "hostile"
	case SeveritySuspicious:
		return "suspicious"
	case SeverityNotable:
		return "notable"
	default:
		return "neutral"
	}
}

func (s Severity) Color() string {
	switch s {
	case SeverityHostile:
		return "#ef4444"
	case SeveritySuspicious:
		return "#eab308"
	case SeverityNotable:
		return "#3b82f6"
	default:
		return "#9ca3af"
	}
}

// Periodic table elements used for category mapping.
var (
	Oxygen       = Element{Number: 8, Symbol: "O", Name: "Oxygen"}          // Objectives
	Hydrogen     = Element{Number: 1, Symbol: "H", Name: "Hydrogen"}        // Micro-behaviors
	Mendelevium  = Element{Number: 101, Symbol: "Md", Name: "Mendelevium"}  // Metadata
	Potassium    = Element{Number: 19, Symbol: "K", Name: "Potassium"}      // Well-known
	Thorium      = Element{Number: 90, Symbol: "Th", Name: "Thorium"}       // Third-party
	Carbon       = Element{Number: 6, Symbol: "C", Name: "Carbon"}          // Command & Control
	Aluminum     = Element{Number: 13, Symbol: "Al", Name: "Aluminum"}      // Anti-analysis
	Arsenic      = Element{Number: 33, Symbol: "As", Name: "Arsenic"}       // Anti-static
	Cobalt       = Element{Number: 27, Symbol: "Co", Name: "Cobalt"}        // Collection
	Calcium      = Element{Number: 20, Symbol: "Ca", Name: "Calcium"}       // Credential-access
	Dysprosium   = Element{Number: 66, Symbol: "Dy", Name: "Dysprosium"}    // Discovery
	Xenon        = Element{Number: 54, Symbol: "Xe", Name: "Xenon"}         // Execution
	Europium     = Element{Number: 63, Symbol: "Eu", Name: "Europium"}      // Exfiltration
	Iodine       = Element{Number: 53, Symbol: "I", Name: "Iodine"}         // Impact
	Lanthanum    = Element{Number: 57, Symbol: "La", Name: "Lanthanum"}     // Lateral-movement
	Phosphorus   = Element{Number: 15, Symbol: "P", Name: "Phosphorus"}     // Persistence
	Praseodymium = Element{Number: 59, Symbol: "Pr", Name: "Praseodymium"}  // Privilege-escalation
	Erbium       = Element{Number: 68, Symbol: "Er", Name: "Erbium"}        // Evasion
	Rubidium     = Element{Number: 37, Symbol: "Rb", Name: "Rubidium"}      // Resource-development
	Chromium     = Element{Number: 24, Symbol: "Cr", Name: "Chromium"}      // Crypto
	Curium       = Element{Number: 96, Symbol: "Cm", Name: "Curium"}        // Communications
	Fluorine     = Element{Number: 9, Symbol: "F", Name: "Fluorine"}        // Filesystem
	Polonium     = Element{Number: 84, Symbol: "Po", Name: "Polonium"}      // Process
	Osmium       = Element{Number: 76, Symbol: "Os", Name: "Osmium"}        // OS
	Dubnium      = Element{Number: 105, Symbol: "Db", Name: "Dubnium"}      // Data
	Holmium      = Element{Number: 67, Symbol: "Ho", Name: "Holmium"}       // Host
	Hafnium      = Element{Number: 72, Symbol: "Hf", Name: "Hafnium"}       // Hardware
	Neptunium    = Element{Number: 93, Symbol: "Np", Name: "Neptunium"}     // Network
	Darmstadtium = Element{Number: 110, Symbol: "Ds", Name: "Darmstadtium"} // Dylib
	Actinium     = Element{Number: 89, Symbol: "Ac", Name: "Actinium"}      // Anti-analysis (micro)
	Astatine     = Element{Number: 85, Symbol: "At", Name: "Astatine"}      // Anti-static (micro)
	Einsteinium  = Element{Number: 99, Symbol: "Es", Name: "Einsteinium"}   // Execution (micro)
	Gold         = Element{Number: 79, Symbol: "Au", Name: "Gold"}          // Quality
	Silver       = Element{Number: 47, Symbol: "Ag", Name: "Silver"}        // Format
	Platinum     = Element{Number: 78, Symbol: "Pt", Name: "Platinum"}      // Lang
)

var categoryElements = map[string]Element{
	// Top-level categories
	"objectives":      Oxygen,
	"micro-behaviors": Hydrogen,
	"metadata":        Mendelevium,
	"well-known":      Potassium,
	"third_party":     Thorium,

	// Objective subcategories
	"anti-analysis":        Aluminum,
	"anti-static":          Arsenic,
	"collection":           Cobalt,
	"command-and-control":  Carbon,
	"credential-access":    Calcium,
	"discovery":            Dysprosium,
	"execution":            Xenon,
	"exfiltration":         Europium,
	"impact":               Iodine,
	"lateral-movement":     Lanthanum,
	"persistence":          Phosphorus,
	"privilege-escalation": Praseodymium,
	"evasion":              Erbium,
	"resource-development": Rubidium,

	// Micro-behavior subcategories
	"crypto":         Chromium,
	"communications": Curium,
	"fs":             Fluorine,
	"process":        Polonium,
	"os":             Osmium,
	"data":           Dubnium,
	"host":           Holmium,
	"hardware":       Hafnium,
	"network":        Neptunium,
	"dylib":          Darmstadtium,

	// Metadata subcategories
	"quality": Gold,
	"format":  Silver,
	"lang":    Platinum,

	// Well-known
	"malware": Potassium,
}

// categoryToElement maps a category path segment to its element.
func categoryToElement(category string) (Element, bool) {
	e, ok := categoryElements[category]
	return e, ok
}

// MaleculeAtom represents an atom in the 3D visualization.
type MaleculeAtom struct {
	Severity string  `json:"severity"`
	Symbol   string  `json:"symbol"`
	Category string  `json:"category"`
	TraitID  string  `json:"trait_id,omitempty"`
	X        float64 `json:"x"`
	Y        float64 `json:"y"`
	Z        float64 `json:"z"`
	Radius   float64 `json:"radius"`
	ID       int     `json:"id"`
}

// MaleculeData contains the complete molecule data for 3D rendering.
type MaleculeData struct {
	Formula string         `json:"formula"`
	Atoms   []MaleculeAtom `json:"atoms"`
	Bonds   [][2]int       `json:"bonds"`
}

// FileMolecule represents a single file's molecule in a galaxy.
type FileMolecule struct {
	Path     string         `json:"path"`
	Formula  string         `json:"formula"`
	Risk     string         `json:"risk"`
	Findings []string       `json:"findings"` // Trait IDs for display on click
	Atoms    []MaleculeAtom `json:"atoms"`
	Bonds    [][2]int       `json:"bonds"`
	CenterX  float64        `json:"centerX"`
	CenterY  float64        `json:"centerY"`
	CenterZ  float64        `json:"centerZ"`
}

// GalaxyLink represents a dropper relationship between files.
type GalaxyLink struct {
	From int `json:"from"` // Index of source molecule
	To   int `json:"to"`   // Index of target molecule
}

// GalaxyData contains multiple molecules for archive visualization.
type GalaxyData struct {
	Molecules []FileMolecule `json:"molecules"`
	Links     []GalaxyLink   `json:"links"` // Dropper relationships
	IsGalaxy  bool           `json:"isGalaxy"`
}

// FindingForFormula is a simplified finding for formula generation.
type FindingForFormula struct {
	ID       string
	Severity Severity
}

// critToSeverity converts cleave's criticality string to Severity.
func critToSeverity(crit string) Severity {
	switch strings.ToLower(crit) {
	case "hostile":
		return SeverityHostile
	case "suspicious":
		return SeveritySuspicious
	case "notable":
		return SeverityNotable
	default:
		return SeverityNeutral
	}
}

// BuildMalecule creates a flat molecule graph from findings.
// The structure is: file center → L1 category nodes → L2 subcategory nodes → L3 nodes.
// Single-child chains are collapsed into their parent (e.g. well-known/malware/mirai
// becomes a single well-known atom). Only notable or higher severity is shown.
//
//nolint:maintidx // complex but necessary molecule layout algorithm
func BuildMalecule(findings []FindingForFormula, formula string) MaleculeData {
	mol := MaleculeData{Formula: formula}
	if len(findings) == 0 {
		return mol
	}

	type molNode struct {
		childIdx map[string]int
		key      string
		element  Element
		traitIDs []string
		children []*molNode
		severity Severity
	}

	newNode := func(key string, elem Element, sev Severity) *molNode {
		return &molNode{key: key, element: elem, severity: sev, childIdx: make(map[string]int)}
	}

	getOrAdd := func(parent *molNode, key string, elem Element, sev Severity) *molNode {
		if idx, ok := parent.childIdx[key]; ok {
			n := parent.children[idx]
			if sev > n.severity {
				n.severity = sev
			}
			return n
		}
		n := newNode(key, elem, sev)
		parent.childIdx[key] = len(parent.children)
		parent.children = append(parent.children, n)
		return n
	}

	// Build tree up to 3 levels deep, skipping below-notable findings.
	root := newNode("file", Element{Number: 0, Symbol: "", Name: "File"}, SeverityNeutral)

	for _, f := range findings {
		if f.Severity < SeverityNotable {
			continue
		}
		parts := strings.Split(f.ID, "/")
		if len(parts) < 2 {
			continue
		}
		l1Elem, _ := categoryToElement(parts[0])
		l1 := getOrAdd(root, parts[0], l1Elem, f.Severity)
		if len(parts) == 2 {
			l1.traitIDs = append(l1.traitIDs, f.ID)
			continue
		}
		l2Elem, _ := categoryToElement(parts[1])
		l2 := getOrAdd(l1, parts[1], l2Elem, f.Severity)
		if len(parts) == 3 {
			l2.traitIDs = append(l2.traitIDs, f.ID)
			continue
		}
		l3Elem, _ := categoryToElement(parts[2])
		l3 := getOrAdd(l2, parts[2], l3Elem, f.Severity)
		l3.traitIDs = append(l3.traitIDs, f.ID)
	}

	// Collapse: while a node has exactly one child, absorb it upward.
	// This collapses single-path chains (e.g. well-known→malware→mirai) into
	// a single node at the top level.
	var collapse func(n *molNode)
	collapse = func(n *molNode) {
		for _, child := range n.children {
			collapse(child)
		}
		for len(n.children) == 1 {
			child := n.children[0]
			n.traitIDs = append(n.traitIDs, child.traitIDs...)
			if child.severity > n.severity {
				n.severity = child.severity
			}
			n.children = child.children
		}
	}
	collapse(root)

	if len(root.children) == 0 {
		return mol
	}

	// Sort children: severity desc then key asc, for deterministic layout.
	var sortTree func(n *molNode)
	sortTree = func(n *molNode) {
		sort.Slice(n.children, func(i, j int) bool {
			if n.children[i].severity != n.children[j].severity {
				return n.children[i].severity > n.children[j].severity
			}
			return n.children[i].key < n.children[j].key
		})
		for _, child := range n.children {
			sortTree(child)
		}
	}
	sortTree(root)

	// Radial layout: file at center, L1 evenly around it, deeper levels
	// extend outward from their parents. All z=0 (flat diagram).
	type vec2 struct{ x, y float64 }
	nodePos := make(map[*molNode]vec2)
	nodePos[root] = vec2{0, 0}

	const r1, r2, r3 = 3.2, 1.8, 1.4

	numL1 := len(root.children)
	for i, l1 := range root.children {
		angle := 2*math.Pi*float64(i)/float64(numL1) - math.Pi/2
		nodePos[l1] = vec2{r1 * math.Cos(angle), r1 * math.Sin(angle)}
	}

	// spreadChildren places a node's children in an arc extending outward
	// from the root, centered on the parent's radial direction.
	spreadChildren := func(parent *molNode, childRadius, maxArc float64) {
		if len(parent.children) == 0 {
			return
		}
		pp := nodePos[parent]
		outAngle := math.Atan2(pp.y, pp.x)
		n := len(parent.children)
		arc := math.Min(maxArc, math.Pi*0.85)
		for j, child := range parent.children {
			var angle float64
			if n == 1 {
				angle = outAngle
			} else {
				angle = outAngle - arc/2 + arc*float64(j)/float64(n-1)
			}
			nodePos[child] = vec2{
				pp.x + childRadius*math.Cos(angle),
				pp.y + childRadius*math.Sin(angle),
			}
		}
	}

	arcL2 := math.Min(2*math.Pi/float64(numL1)*0.75, math.Pi)
	for _, l1 := range root.children {
		spreadChildren(l1, r2, arcL2)
		numL2 := math.Max(1, float64(len(l1.children)))
		for _, l2 := range l1.children {
			spreadChildren(l2, r3, arcL2/numL2)
		}
	}

	// BFS to build atoms list and parent→child bonds.
	type qItem struct {
		node      *molNode
		parentIdx int
	}
	queue := []qItem{{root, -1}}
	nodeAtomIdx := make(map[*molNode]int)
	var atoms []MaleculeAtom
	var bonds [][2]int

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		n := item.node

		p := nodePos[n]
		atomIdx := len(atoms)
		nodeAtomIdx[n] = atomIdx

		atomRadius := 0.35
		switch {
		case n == root:
			atomRadius = 0.45
		case n.severity == SeverityHostile:
			atomRadius = 0.5
		case n.severity >= SeveritySuspicious:
			atomRadius = 0.42
		default:
		}
		sev := n.severity.String()
		if n == root {
			sev = "neutral"
		}

		atoms = append(atoms, MaleculeAtom{
			ID:       atomIdx,
			X:        p.x,
			Y:        p.y,
			Z:        0,
			Radius:   atomRadius,
			Severity: sev,
			Symbol:   n.element.Symbol,
			Category: n.key,
			TraitID:  strings.Join(n.traitIDs, ", "),
		})

		if item.parentIdx >= 0 {
			bonds = append(bonds, [2]int{item.parentIdx, atomIdx})
		}

		for _, child := range n.children {
			queue = append(queue, qItem{child, atomIdx})
		}
	}
	_ = nodeAtomIdx

	mol.Atoms = atoms
	mol.Bonds = bonds
	return mol
}

// FileFindings represents findings for a single file in an archive.
type FileFindings struct {
	Path     string
	Risk     string
	Formula  string // Formula from cleave
	Findings []FindingForFormula
	Strings  []string // Extracted strings for dropper detection
}

// BuildGalaxy creates a galaxy of molecules from multiple files.
//
//nolint:gocognit,maintidx // complex galaxy layout algorithm
func BuildGalaxy(files []FileFindings) GalaxyData {
	if len(files) <= 1 {
		// Single file or empty - not a galaxy
		return GalaxyData{IsGalaxy: false}
	}

	// Check if we have archive contents (paths with "!!")
	// If so, filter out the archive container itself
	hasArchiveContents := false
	for _, file := range files {
		if strings.Contains(file.Path, "!!") {
			hasArchiveContents = true
			break
		}
	}

	if hasArchiveContents {
		filtered := make([]FileFindings, 0, len(files))
		for _, file := range files {
			if strings.Contains(file.Path, "!!") {
				filtered = append(filtered, file)
			}
		}
		files = filtered
	}

	if len(files) <= 1 {
		return GalaxyData{IsGalaxy: false}
	}

	galaxy := GalaxyData{
		IsGalaxy:  true,
		Molecules: make([]FileMolecule, 0, len(files)),
	}

	// Build basename to index map for dropper detection
	basenameToIdx := make(map[string]int)
	for i, file := range files {
		// Extract basename from "archive!!path/file.ext" format
		path := file.Path
		if strings.Contains(path, "!!") {
			parts := strings.Split(path, "!!")
			path = parts[len(parts)-1]
		}
		base := filepath.Base(path)
		basenameToIdx[base] = i
	}

	// First pass: detect dropper relationships to build dependency graph
	// droppedBy[i] = list of file indices that drop file i
	droppedBy := make(map[int][]int)
	// drops[i] = list of file indices that file i drops
	drops := make(map[int][]int)

	for i, file := range files {
		for _, s := range file.Strings {
			for basename, targetIdx := range basenameToIdx {
				if targetIdx == i {
					continue
				}
				if strings.Contains(s, basename) {
					droppedBy[targetIdx] = append(droppedBy[targetIdx], i)
					drops[i] = append(drops[i], targetIdx)
				}
			}
		}
	}

	// Calculate depth for each file (0 = root dropper, 1 = first stage, etc.)
	depth := make(map[int]int)
	var calcDepth func(idx int, visited map[int]bool) int
	calcDepth = func(idx int, visited map[int]bool) int {
		if d, ok := depth[idx]; ok {
			return d
		}
		if visited[idx] {
			return 0 // Cycle detected
		}
		visited[idx] = true

		parents := droppedBy[idx]
		if len(parents) == 0 {
			depth[idx] = 0
			return 0
		}

		maxParentDepth := 0
		for _, p := range parents {
			pd := calcDepth(p, visited)
			if pd > maxParentDepth {
				maxParentDepth = pd
			}
		}
		depth[idx] = maxParentDepth + 1
		return depth[idx]
	}

	for i := range files {
		calcDepth(i, make(map[int]bool))
	}

	// Group files by depth level
	levels := make(map[int][]int)
	maxDepth := 0
	for i := range files {
		if len(files[i].Findings) == 0 {
			continue
		}
		d := depth[i]
		levels[d] = append(levels[d], i)
		if d > maxDepth {
			maxDepth = d
		}
	}

	// Sort files within each level by risk (hostile first) for consistent ordering
	riskOrder := map[string]int{"hostile": 0, "suspicious": 1, "notable": 2, "": 3}
	for d := range levels {
		sort.Slice(levels[d], func(i, j int) bool {
			ri := riskOrder[files[levels[d][i]].Risk]
			rj := riskOrder[files[levels[d][j]].Risk]
			if ri != rj {
				return ri < rj
			}
			return files[levels[d][i]].Path < files[levels[d][j]].Path
		})
	}

	// Layout: hierarchical with droppers on left, payloads flowing right
	// X increases as depth increases (left to right flow)
	// Y spreads files vertically within each level
	const levelSpacing = 14.0 // Horizontal distance between levels
	const nodeSpacing = 10.0  // Vertical distance between nodes

	fileToMolIdx := make(map[int]int)

	for d := 0; d <= maxDepth; d++ {
		filesAtLevel := levels[d]
		if len(filesAtLevel) == 0 {
			continue
		}

		levelHeight := float64(len(filesAtLevel)-1) * nodeSpacing
		startY := levelHeight / 2.0
		centerX := float64(d) * levelSpacing
		centerZ := 0.0

		for j, fileIdx := range filesAtLevel {
			file := files[fileIdx]
			molIdx := len(galaxy.Molecules)
			fileToMolIdx[fileIdx] = molIdx

			centerY := startY - float64(j)*nodeSpacing

			mol := BuildMalecule(file.Findings, file.Formula)

			for k := range mol.Atoms {
				mol.Atoms[k].X += centerX
				mol.Atoms[k].Y += centerY
				mol.Atoms[k].Z += centerZ
			}

			var traitIDs []string
			for _, f := range file.Findings {
				traitIDs = append(traitIDs, f.ID)
			}

			galaxy.Molecules = append(galaxy.Molecules, FileMolecule{
				Path:     file.Path,
				Formula:  mol.Formula,
				Risk:     file.Risk,
				Findings: traitIDs,
				Atoms:    mol.Atoms,
				Bonds:    mol.Bonds,
				CenterX:  centerX,
				CenterY:  centerY,
				CenterZ:  centerZ,
			})
		}
	}

	// Build links from the drops map
	seen := make(map[[2]int]bool)
	for fromFileIdx, toFileIdxs := range drops {
		fromMolIdx, ok := fileToMolIdx[fromFileIdx]
		if !ok {
			continue
		}
		for _, toFileIdx := range toFileIdxs {
			toMolIdx, ok := fileToMolIdx[toFileIdx]
			if !ok {
				continue
			}
			link := [2]int{fromMolIdx, toMolIdx}
			if !seen[link] {
				seen[link] = true
				galaxy.Links = append(galaxy.Links, GalaxyLink{
					From: fromMolIdx,
					To:   toMolIdx,
				})
			}
		}
	}

	return galaxy
}
