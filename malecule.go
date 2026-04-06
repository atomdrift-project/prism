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
//
// Mnemonic guide for security engineers reading formulas:
//
// Top-level: O(bjectives) H(micro-behaviors) Md(metadata) K(nown) Th(ird-party)
//
// Objectives:  Al(anti-analysis) As(anti-static) C(2/c&c) Ca(credential-access)
//   Co(llection) Dy(discoverY) Er(vasion) Eu(xfiltration) I(mpact) La(teral)
//   P(ersistence) Pr(ivilege) S(upply-chain) Xe(xecution)
//
// Micro-behaviors: Cm(comms) Cr(ypto) Db(data) Ds(dylib/shared) F(ilesystem)
//   Hf(hardware) Ho(st) Mg(memory) N(etwork) Os(operating-system) Po(process)
//   Ti(me) U(I)
//
// Metadata: Ar(ch) Bi(nary) Bk(build) Cf(config) He(hardening) In(import)
//   Li(brary) Pa(ckage) Pd(ocument) Pt(lang) Rh(ights/entitlements) Si(gned)
//   V(endor) + deeper: Ag(format) Au(quality) B(undle) Ce(compiler) Ne(archive)
var (
	// Top-level categories
	Oxygen      = Element{Number: 8, Symbol: "O", Name: "Oxygen"}         // Objectives
	Hydrogen    = Element{Number: 1, Symbol: "H", Name: "Hydrogen"}       // Micro-behaviors
	Mendelevium = Element{Number: 101, Symbol: "Md", Name: "Mendelevium"} // Metadata
	Potassium   = Element{Number: 19, Symbol: "K", Name: "Potassium"}     // Well-known (K for Known)
	Thorium     = Element{Number: 90, Symbol: "Th", Name: "Thorium"}      // Third-party

	// Objective subcategories
	Aluminum     = Element{Number: 13, Symbol: "Al", Name: "Aluminum"}     // Anti-analysis
	Arsenic      = Element{Number: 33, Symbol: "As", Name: "Arsenic"}      // Anti-static
	Carbon       = Element{Number: 6, Symbol: "C", Name: "Carbon"}         // Command & Control (C2)
	Cobalt       = Element{Number: 27, Symbol: "Co", Name: "Cobalt"}       // Collection
	Calcium      = Element{Number: 20, Symbol: "Ca", Name: "Calcium"}      // Credential-access
	Dysprosium   = Element{Number: 66, Symbol: "Dy", Name: "Dysprosium"}   // Discovery
	Erbium       = Element{Number: 68, Symbol: "Er", Name: "Erbium"}       // Evasion
	Europium     = Element{Number: 63, Symbol: "Eu", Name: "Europium"}     // Exfiltration
	Iodine       = Element{Number: 53, Symbol: "I", Name: "Iodine"}        // Impact
	Lanthanum    = Element{Number: 57, Symbol: "La", Name: "Lanthanum"}    // Lateral-movement
	Phosphorus   = Element{Number: 15, Symbol: "P", Name: "Phosphorus"}    // Persistence
	Praseodymium = Element{Number: 59, Symbol: "Pr", Name: "Praseodymium"} // Privilege-escalation
	Sulfur       = Element{Number: 16, Symbol: "S", Name: "Sulfur"}        // Supply-chain
	Xenon        = Element{Number: 54, Symbol: "Xe", Name: "Xenon"}        // Execution

	// Micro-behavior subcategories
	Curium       = Element{Number: 96, Symbol: "Cm", Name: "Curium"}       // Communications
	Chromium     = Element{Number: 24, Symbol: "Cr", Name: "Chromium"}     // Crypto
	Dubnium      = Element{Number: 105, Symbol: "Db", Name: "Dubnium"}     // Data
	Darmstadtium = Element{Number: 110, Symbol: "Ds", Name: "Darmstadtium"} // Dylib
	Fluorine     = Element{Number: 9, Symbol: "F", Name: "Fluorine"}       // Filesystem
	Hafnium      = Element{Number: 72, Symbol: "Hf", Name: "Hafnium"}      // Hardware
	Holmium      = Element{Number: 67, Symbol: "Ho", Name: "Holmium"}      // Host
	Magnesium    = Element{Number: 12, Symbol: "Mg", Name: "Magnesium"}    // Memory
	Nitrogen     = Element{Number: 7, Symbol: "N", Name: "Nitrogen"}       // Network
	Osmium       = Element{Number: 76, Symbol: "Os", Name: "Osmium"}       // OS
	Polonium     = Element{Number: 84, Symbol: "Po", Name: "Polonium"}     // Process
	Titanium     = Element{Number: 22, Symbol: "Ti", Name: "Titanium"}     // Time
	Uranium      = Element{Number: 92, Symbol: "U", Name: "Uranium"}       // UI

	// Metadata subcategories (top-level under metadata/)
	Argon       = Element{Number: 18, Symbol: "Ar", Name: "Argon"}       // Arch (Ar for ARchitecture)
	Bismuth     = Element{Number: 83, Symbol: "Bi", Name: "Bismuth"}     // Binary
	Berkelium   = Element{Number: 97, Symbol: "Bk", Name: "Berkelium"}   // Build
	Californium = Element{Number: 98, Symbol: "Cf", Name: "Californium"} // Config
	Palladium   = Element{Number: 46, Symbol: "Pd", Name: "Palladium"}   // Document (Pd for PDF/Doc)
	Rhodium     = Element{Number: 45, Symbol: "Rh", Name: "Rhodium"}     // Entitlements (Rh for Rights)
	Helium      = Element{Number: 2, Symbol: "He", Name: "Helium"}       // Hardening
	Indium      = Element{Number: 49, Symbol: "In", Name: "Indium"}      // Import
	Platinum    = Element{Number: 78, Symbol: "Pt", Name: "Platinum"}    // Lang
	Lithium     = Element{Number: 3, Symbol: "Li", Name: "Lithium"}      // Library

	Protactinium = Element{Number: 91, Symbol: "Pa", Name: "Protactinium"} // Package
	Silicon      = Element{Number: 14, Symbol: "Si", Name: "Silicon"}      // Signed
	Vanadium     = Element{Number: 23, Symbol: "V", Name: "Vanadium"}      // Vendor

	// Metadata deeper-segment matches (3rd+ level)
	Gold   = Element{Number: 79, Symbol: "Au", Name: "Gold"}   // Quality (gold standard)
	Silver = Element{Number: 47, Symbol: "Ag", Name: "Silver"} // Format
	Boron  = Element{Number: 5, Symbol: "B", Name: "Boron"}    // Bundle
	Cerium = Element{Number: 58, Symbol: "Ce", Name: "Cerium"} // Compiler
	Neon   = Element{Number: 10, Symbol: "Ne", Name: "Neon"}   // Archive

	// Well-known subcategories
	Tellurium = Element{Number: 52, Symbol: "Te", Name: "Tellurium"} // Tools
)

var categoryElements = map[string]Element{
	// Top-level categories
	"objectives":      Oxygen,
	"micro-behaviors": Hydrogen,
	"metadata":        Mendelevium,
	"well-known":      Potassium,
	"third_party":     Thorium,
	"third-party":     Thorium,

	// Objective subcategories
	"anti-analysis":        Aluminum,
	"anti-static":          Arsenic,
	"collection":           Cobalt,
	"command-and-control":  Carbon,
	"credential-access":    Calcium,
	"discovery":            Dysprosium,
	"evasion":              Erbium,
	"execution":            Xenon,
	"exfiltration":         Europium,
	"impact":               Iodine,
	"lateral-movement":     Lanthanum,
	"persistence":          Phosphorus,
	"privilege-escalation": Praseodymium,
	"supply-chain":         Sulfur,

	// Micro-behavior subcategories
	"communications": Curium,
	"crypto":         Chromium,
	"data":           Dubnium,
	"dylib":          Darmstadtium,
	"fs":             Fluorine,
	"hardware":       Hafnium,
	"host":           Holmium,
	"mem":            Magnesium,
	"network":        Nitrogen,
	"os":             Osmium,
	"process":        Polonium,
	"time":           Titanium,
	"ui":             Uranium,

	// Metadata subcategories (top-level under metadata/)
	"arch":      Argon,
	"binary":    Bismuth,
	"build":     Berkelium,
	"document":  Palladium,
	// NOTE: "file" deliberately omitted — collides with micro-behaviors/fs/file path segments.
	"hardening": Helium,
	"import":    Indium,
	"lang":      Platinum,
	"library":   Lithium,
	"package":   Protactinium,
	"signed":    Silicon,
	"vendor":    Vanadium,

	// Metadata deeper-segment matches (3rd+ level)
	"archive":      Neon,
	"bundle":       Boron,
	"compiler":     Cerium,
	"config":       Californium,
	"entitlements": Rhodium,
	"format":       Silver,
	"quality":      Gold,

	// Well-known subcategories
	"malware": Potassium,
	"tools":   Tellurium,
}

// categoryToElement maps a category path segment to its element.
func categoryToElement(category string) (Element, bool) {
	e, ok := categoryElements[category]
	return e, ok
}

// MaleculeAtom represents an atom in the 3D visualization.
type MaleculeAtom struct {
	Severity  string    `json:"severity"`
	Symbol    string    `json:"symbol"`
	Category  string    `json:"category"`
	TraitID   string    `json:"trait_id,omitempty"`
	X         float64   `json:"x"`
	Y         float64   `json:"y"`
	Z         float64   `json:"z"`
	Radius    float64   `json:"radius"`
	ID        int       `json:"id"`
	Ring      bool      `json:"ring,omitempty"`
	ClusterOf int       `json:"cluster_of,omitempty"` // parent atom ID for buckyball satellite atoms
	ClusterDx float64   `json:"cdx,omitempty"`        // offset from parent (preserved across layouts)
	ClusterDy float64   `json:"cdy,omitempty"`
	ClusterDz float64   `json:"cdz,omitempty"`
}

// TraitDetail holds display information for a trait, keyed by trait ID.
type TraitDetail struct {
	Desc     string   `json:"desc"`
	Crit     string   `json:"crit"`
	Evidence []string `json:"evidence,omitempty"`
}

// MaleculeData contains the complete molecule data for 3D rendering.
type MaleculeData struct {
	Filename string                  `json:"filename,omitempty"`
	FileType string                  `json:"fileType,omitempty"`
	Formula  string                  `json:"formula"`
	Atoms    []MaleculeAtom          `json:"atoms"`
	Bonds    [][2]int                `json:"bonds"`
	Traits   map[string]*TraitDetail `json:"traits,omitempty"`
}

// FileMolecule represents a single file's molecule in a galaxy.
type FileMolecule struct {
	Path           string         `json:"path"`
	Formula        string         `json:"formula"`
	Risk           string         `json:"risk"`
	Classification string         `json:"classification,omitempty"` // litmus ML classification
	Findings       []string       `json:"findings"`                // Trait IDs for display on click
	Atoms          []MaleculeAtom `json:"atoms"`
	Bonds          [][2]int       `json:"bonds"`
	CenterX        float64        `json:"centerX"`
	CenterY        float64        `json:"centerY"`
	CenterZ        float64        `json:"centerZ"`
	Probability    float64        `json:"probability,omitempty"` // litmus ML probability
}

// GalaxyLink represents a dropper relationship between files.
type GalaxyLink struct {
	From int `json:"from"` // Index of source molecule
	To   int `json:"to"`   // Index of target molecule
}

// GalaxyData contains multiple molecules for archive visualization.
type GalaxyData struct {
	Molecules []FileMolecule          `json:"molecules"`
	Links     []GalaxyLink            `json:"links"`  // Dropper relationships
	IsGalaxy  bool                    `json:"isGalaxy"`
	Traits    map[string]*TraitDetail `json:"traits,omitempty"`
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

// critIntToSeverity maps v4 criticality ordinal to Severity.
func critIntToSeverity(crit int) Severity {
	switch crit {
	case 5:
		return SeverityHostile
	case 4:
		return SeveritySuspicious
	case 3:
		return SeverityNotable
	default:
		return SeverityNeutral
	}
}

// critIntToString maps v4 criticality ordinal to display string.
func critIntToString(crit int) string {
	switch crit {
	case 5:
		return "hostile"
	case 4:
		return "suspicious"
	case 3:
		return "notable"
	case 2:
		return "baseline"
	case 1:
		return "component"
	default:
		return "filtered"
	}
}

// BuildMalecule creates a flat molecule graph from findings.
// The structure is: file center → L1 category nodes → L2 subcategory nodes → L3 nodes.
// Single-child chains are collapsed into their parent (e.g. well-known/malware/mirai
// becomes a single well-known atom). Only notable or higher severity is shown.
//
//nolint:maintidx,gocognit,revive // complex but necessary molecule layout algorithm
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

	// Build tree up to 3 levels deep. Only notable or higher severity is shown —
	// baseline/composite traits are excluded until cleave exposes dependency data.
	root := newNode("file", Element{Symbol: "C", Name: "File", Number: 0}, SeverityNeutral)

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

	// Hexagonal ring layout: L1 category nodes form the inner ring (like an aromatic
	// ring in caffeine), connected to each other. L2/L3 branch outward from the ring.
	// Fallback: if no notable traits at all, return a single neutral C atom.
	if len(root.children) == 0 {
		mol.Atoms = []MaleculeAtom{{
			ID: 0, Severity: "neutral", Symbol: "C", Category: "file",
			X: 0, Y: 0, Z: 0, Radius: 0.45,
		}}
		return mol
	}

	// rRing: radius of the inner ring. r2/r3: distance from parent to child.
	const rRing, r2, r3 = 1.8, 3.2, 2.2

	type vec2 struct{ x, y float64 }
	nodePos := make(map[*molNode]vec2)

	numL1 := len(root.children)
	for i, l1 := range root.children {
		angle := 2*math.Pi*float64(i)/float64(numL1) - math.Pi/2
		nodePos[l1] = vec2{rRing * math.Cos(angle), rRing * math.Sin(angle)}
	}

	// spreadChildren fans a node's children outward from the center.
	// The arc grows with the number of children (arcPerChild minimum per slot)
	// up to maxArc, so more children always get more room rather than less.
	spreadChildren := func(parent *molNode, childRadius, arcPerChild, maxArc float64) {
		n := len(parent.children)
		if n == 0 {
			return
		}
		pp := nodePos[parent]
		outAngle := math.Atan2(pp.y, pp.x)
		arc := math.Min(arcPerChild*float64(n), maxArc)
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

	sectorArc := 2 * math.Pi / float64(numL1) * 0.88
	for _, l1 := range root.children {
		spreadChildren(l1, r2, math.Pi/4, sectorArc)
		for _, l2 := range l1.children {
			spreadChildren(l2, r3, math.Pi*40/180, math.Min(sectorArc, math.Pi*0.6))
		}
	}

	// atomSeverity: intermediate nodes (have children but no direct traits) are neutral,
	// since they are structural groupings rather than specific threat indicators.
	atomSeverity := func(n *molNode) Severity {
		if len(n.traitIDs) == 0 && len(n.children) > 0 {
			return SeverityNeutral
		}
		return n.severity
	}

	// BFS from L1 ring nodes (no central file atom).
	type qItem struct {
		node      *molNode
		parentIdx int
		isL1      bool
	}
	queue := make([]qItem, 0, numL1)
	for _, l1 := range root.children {
		queue = append(queue, qItem{l1, -1, true})
	}

	var atoms []MaleculeAtom
	var bonds [][2]int
	l1AtomIndices := make([]int, 0, numL1)

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		n := item.node
		p := nodePos[n]
		atomIdx := len(atoms)

		if item.isL1 {
			l1AtomIndices = append(l1AtomIndices, atomIdx)
		}

		// Ring atoms with no direct traits are neutral (structural groupings).
		// Ring atoms that absorbed findings via collapse keep their severity.
		sev := atomSeverity(n)
		if item.isL1 && len(n.traitIDs) == 0 {
			sev = SeverityNeutral
		}

		atomRadius := 0.22
		if item.isL1 && sev == SeverityNeutral {
			atomRadius = 0.32 // structural ring atom
		} else {
			switch {
			case sev == SeverityHostile:
				atomRadius = 0.5
			case sev >= SeveritySuspicious:
				atomRadius = 0.42
			case sev >= SeverityNotable:
				atomRadius = 0.35
			case item.isL1:
				atomRadius = 0.32
			default:
				// atomRadius stays at 0.22
			}
		}

		// If a non-ring node has multiple trait IDs, emit a tight buckyball
		// cluster of overlapping atoms instead of one merged atom.
		if !item.isL1 && len(n.traitIDs) > 1 {
			// Buckyball cluster: satellites on an icosahedral shell around a small center.
			// Cap visible satellites at 12 (one full icosahedron).
			const maxSatellites = 12

			// Satellite sphere size and shell radius — overlapping for a solid cluster.
			satRadius := atomRadius * 0.55
			shellR := satRadius * 1.4

			// Center atom slightly larger than satellites.
			centerRadius := atomRadius * 0.7
			atoms = append(atoms, MaleculeAtom{
				ID:       atomIdx,
				X:        p.x,
				Y:        p.y,
				Z:        0,
				Radius:   centerRadius,
				Severity: sev.String(),
				Symbol:   n.element.Symbol,
				Category: n.key,
				TraitID: func() string {
					overflow := []string{n.traitIDs[0]}
					if len(n.traitIDs)-1 > maxSatellites {
						overflow = append(overflow, n.traitIDs[maxSatellites+1:]...)
					}
					return strings.Join(overflow, ", ")
				}(),
			})
			if item.parentIdx >= 0 {
				bonds = append(bonds, [2]int{item.parentIdx, atomIdx})
			}
			// 12 vertices of an icosahedron, normalized to unit sphere.
			phi := (1 + math.Sqrt(5)) / 2
			icoVerts := [][3]float64{
				{0, 1, phi}, {0, -1, phi}, {0, 1, -phi}, {0, -1, -phi},
				{1, phi, 0}, {-1, phi, 0}, {1, -phi, 0}, {-1, -phi, 0},
				{phi, 0, 1}, {-phi, 0, 1}, {phi, 0, -1}, {-phi, 0, -1},
			}
			for vi := range icoVerts {
				mag := math.Sqrt(icoVerts[vi][0]*icoVerts[vi][0] + icoVerts[vi][1]*icoVerts[vi][1] + icoVerts[vi][2]*icoVerts[vi][2])
				icoVerts[vi][0] /= mag
				icoVerts[vi][1] /= mag
				icoVerts[vi][2] /= mag
			}
			satCount := len(n.traitIDs) - 1
			if satCount > maxSatellites {
				satCount = maxSatellites
			}
			for ci := 0; ci < satCount; ci++ {
				shell := ci / len(icoVerts)
				vi := ci % len(icoVerts)
				r := shellR * (1.0 + float64(shell)*0.5)
				dx := r * icoVerts[vi][0]
				dy := r * icoVerts[vi][1]
				dz := r * icoVerts[vi][2]
				cIdx := len(atoms)
				atoms = append(atoms, MaleculeAtom{
					ID:        cIdx,
					X:         p.x + dx,
					Y:         p.y + dy,
					Z:         dz,
					Radius:    satRadius,
					Severity:  sev.String(),
					Symbol:    n.element.Symbol,
					Category:  n.key,
					TraitID:   n.traitIDs[ci+1],
					ClusterOf: atomIdx + 1, // +1 so 0 means "not a cluster atom" (omitempty)
					ClusterDx: dx,
					ClusterDy: dy,
					ClusterDz: dz,
				})
				bonds = append(bonds, [2]int{atomIdx, cIdx})
			}
		} else {
			atoms = append(atoms, MaleculeAtom{
				ID:       atomIdx,
				X:        p.x,
				Y:        p.y,
				Z:        0,
				Radius:   atomRadius,
				Severity: sev.String(),
				Symbol:   n.element.Symbol,
				Category: n.key,
				TraitID:  strings.Join(n.traitIDs, ", "),
				Ring:     item.isL1,
			})

			if item.parentIdx >= 0 {
				bonds = append(bonds, [2]int{item.parentIdx, atomIdx})
			}
		}

		for _, child := range n.children {
			queue = append(queue, qItem{child, atomIdx, false})
		}
	}

	// Trait ref atoms: composite findings (notable+) reference underlying simple traits
	// via trait_refs. Each unique ref becomes ONE atom regardless of how many composites
	// reference it; all referencing composites get a bond to that single atom.
	//
	// Build traitID→atomIdx so we can find composite atoms and detect refs that are
	// already present as notable+ findings in the molecule.
	traitIDToAtomIdx := make(map[string]int, len(atoms))
	for i, a := range atoms {
		for tid := range strings.SplitSeq(a.TraitID, ", ") {
			if tid != "" {
				traitIDToAtomIdx[tid] = i
			}
		}
	}

	// refComposites maps each unique ref ID to the list of composite atom indices
	// that depend on it. Order of first appearance determines primary composite
	// (used for positioning when the ref is new).
	type refEntry struct {
		composites []int // atom indices of composites that reference this ref
	}
	// TraitRefs removed in v4 — composite bond pool is empty.
	refPool := make(map[string]*refEntry)

	if len(refPool) > 0 {
		// Group refs by primary composite for arc positioning.
		type refPos struct {
			entry *refEntry
			id    string
		}
		compositeRefs := make(map[int][]refPos)
		for ref, re := range refPool {
			primary := re.composites[0]
			compositeRefs[primary] = append(compositeRefs[primary], refPos{entry: re, id: ref})
		}

		// refAtomIdx maps ref ID → atom index (for refs already in the molecule).
		refAtomIdx := make(map[string]int)
		for ref := range refPool {
			if idx, ok := traitIDToAtomIdx[ref]; ok {
				refAtomIdx[ref] = idx
			}
		}

		// For each primary composite, fan its new ref atoms outward.
		for primaryIdx, refs := range compositeRefs {
			// Sort for determinism.
			sort.Slice(refs, func(i, j int) bool { return refs[i].id < refs[j].id })

			// Count refs that need new atoms (not already in molecule).
			newRefs := refs[:0:0]
			for _, rp := range refs {
				if _, exists := refAtomIdx[rp.id]; !exists {
					newRefs = append(newRefs, rp)
				}
			}

			if len(newRefs) > 0 {
				cx := atoms[primaryIdx].X
				cy := atoms[primaryIdx].Y
				outAngle := math.Atan2(cy, cx)
				const refRadius = 1.2
				const arcPerRef = math.Pi * 25 / 180
				arc := math.Min(arcPerRef*float64(len(newRefs)), math.Pi*0.5)

				for j, rp := range newRefs {
					var angle float64
					if len(newRefs) == 1 {
						angle = outAngle
					} else {
						angle = outAngle - arc/2 + arc*float64(j)/float64(len(newRefs)-1)
					}
					refParts := strings.Split(rp.id, "/")
					refElem, _ := categoryToElement(refParts[len(refParts)-1])
					idx := len(atoms)
					atoms = append(atoms, MaleculeAtom{
						ID:       idx,
						X:        cx + refRadius*math.Cos(angle),
						Y:        cy + refRadius*math.Sin(angle),
						Z:        0,
						Radius:   0.22,
						Severity: "neutral",
						Symbol:   refElem.Symbol,
						Category: rp.id,
						TraitID:  rp.id,
					})
					refAtomIdx[rp.id] = idx
				}
			}
		}

		// Bond every composite to its ref atoms (shared refs get bonds from all composites).
		for ref, re := range refPool {
			idx, ok := refAtomIdx[ref]
			if !ok {
				continue
			}
			for _, ci := range re.composites {
				bonds = append(bonds, [2]int{ci, idx})
			}
		}
	}

	// Close the ring: connect each L1 atom to its neighbor, forming the aromatic ring.
	for i, idx := range l1AtomIndices {
		next := l1AtomIndices[(i+1)%len(l1AtomIndices)]
		bonds = append(bonds, [2]int{idx, next})
	}

	mol.Atoms = atoms
	mol.Bonds = bonds
	return mol
}

// FileFindings represents findings for a single file in an archive.
type FileFindings struct {
	Path           string
	Risk           string
	Classification string  // litmus ML classification
	Formula        string  // Formula from cleave
	Findings       []FindingForFormula
	Strings        []string  // Extracted strings for dropper detection
	Probability    float64 // litmus ML probability
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

	// Determine which files are interesting enough to display.
	// For small archives (≤16 files) show everything with notable+ findings.
	// For large archives, focus on suspicious+ files and anything linked to them.
	fileMaxSev := make([]Severity, len(files))
	for i, file := range files {
		for _, f := range file.Findings {
			if f.Severity > fileMaxSev[i] {
				fileMaxSev[i] = f.Severity
			}
		}
	}

	include := make([]bool, len(files))
	notableCount := 0
	for i := range files {
		if fileMaxSev[i] >= SeverityNotable {
			notableCount++
		}
	}

	if notableCount <= 8 {
		// Small archive: show all files with notable+ findings.
		for i := range files {
			include[i] = fileMaxSev[i] >= SeverityNotable
		}
	} else {
		// Large archive: seed with suspicious+ files, then include
		// anything directly linked (dropper or dropped) to them.
		for i := range files {
			include[i] = fileMaxSev[i] >= SeveritySuspicious
		}
		for i := range files {
			if !include[i] {
				continue
			}
			for _, j := range drops[i] {
				include[j] = include[j] || fileMaxSev[j] >= SeverityNotable
			}
			for _, j := range droppedBy[i] {
				include[j] = include[j] || fileMaxSev[j] >= SeverityNotable
			}
		}
	}

	// Group included files by depth level.
	levels := make(map[int][]int)
	maxDepth := 0
	for i := range files {
		if !include[i] {
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
				Path:           file.Path,
				Formula:        mol.Formula,
				Risk:           file.Risk,
				Classification: file.Classification,
				Probability:    file.Probability,
				Findings:       traitIDs,
				Atoms:          mol.Atoms,
				Bonds:          mol.Bonds,
				CenterX:        centerX,
				CenterY:        centerY,
				CenterZ:        centerZ,
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
