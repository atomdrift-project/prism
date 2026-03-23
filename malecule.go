package main

import (
	"math"
	"path/filepath"
	"slices"
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
	Sulfur        = Element{Number: 16, Symbol: "S", Name: "Sulfur"}          // Supply-chain (S for Supply)
	Magnesium     = Element{Number: 12, Symbol: "Mg", Name: "Magnesium"}     // Mem (Mg for Memory)
	Titanium      = Element{Number: 22, Symbol: "Ti", Name: "Titanium"}      // Time (Ti for Time)
	Uranium       = Element{Number: 92, Symbol: "U", Name: "Uranium"}        // UI (U for UI)
	Bismuth       = Element{Number: 83, Symbol: "Bi", Name: "Bismuth"}       // Binary (Bi for Binary)
	Protactinium  = Element{Number: 91, Symbol: "Pa", Name: "Protactinium"}  // Package (Pa for Package)
	Silicon       = Element{Number: 14, Symbol: "Si", Name: "Silicon"}       // Signed (Si for Signed)
	Vanadium      = Element{Number: 23, Symbol: "V", Name: "Vanadium"}       // Vendor (V for Vendor)
	Lithium       = Element{Number: 3, Symbol: "Li", Name: "Lithium"}        // Library (Li for Library)
	Argon         = Element{Number: 18, Symbol: "Ar", Name: "Argon"}         // Archive (Ar for Archive)
	Berkelium     = Element{Number: 97, Symbol: "Bk", Name: "Berkelium"}     // Builder (Bk for Build)
	Boron         = Element{Number: 5, Symbol: "B", Name: "Boron"}           // Bundle (B for Bundle)
	Cerium        = Element{Number: 58, Symbol: "Ce", Name: "Cerium"}        // Compiler (Ce for Compile)
	Californium   = Element{Number: 98, Symbol: "Cf", Name: "Californium"}   // Config (Cf for Config)
	Germanium     = Element{Number: 32, Symbol: "Ge", Name: "Germanium"}     // Dev
	Rhodium       = Element{Number: 45, Symbol: "Rh", Name: "Rhodium"}       // Entitlements (Rh for Rights)
	Iron          = Element{Number: 26, Symbol: "Fe", Name: "Iron"}          // File (Fe for File)
	Helium        = Element{Number: 2, Symbol: "He", Name: "Helium"}         // Hardening (He for Hardening)
	Indium        = Element{Number: 49, Symbol: "In", Name: "Indium"}        // Import (In for Import)
	Americium     = Element{Number: 95, Symbol: "Am", Name: "Americium"}     // Analytics (Am for Analytics)
	Neon          = Element{Number: 10, Symbol: "Ne", Name: "Neon"}          // Arch
	Tellurium     = Element{Number: 52, Symbol: "Te", Name: "Tellurium"}     // Tools (Te for Tools)
	Terbium       = Element{Number: 65, Symbol: "Tb", Name: "Terbium"}       // Encoded-payload
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
	"supply-chain":         Sulfur,

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
	"mem":            Magnesium,
	"time":           Titanium,
	"ui":             Uranium,

	// Metadata subcategories
	"quality":         Gold,
	"format":          Silver,
	"lang":            Platinum,
	"binary":          Bismuth,
	"package":         Protactinium,
	"signed":          Silicon,
	"vendor":          Vanadium,
	"library":         Lithium,
	"archive":         Argon,
	"builder":         Berkelium,
	"bundle":          Boron,
	"compiler":        Cerium,
	"config":          Californium,
	"dev":             Germanium,
	"entitlements":    Rhodium,
	// NOTE: "file" deliberately omitted — collides with micro-behaviors/fs/file path segments.
	"hardening":       Helium,
	"import":          Indium,
	"analytics":       Americium,
	"arch":            Neon,
	"encoded-payload": Terbium,

	// Well-known
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
	Severity string  `json:"severity"`
	Symbol   string  `json:"symbol"`
	Category string  `json:"category"`
	TraitID  string  `json:"trait_id,omitempty"`
	X        float64 `json:"x"`
	Y        float64 `json:"y"`
	Z        float64 `json:"z"`
	Radius   float64 `json:"radius"`
	ID       int     `json:"id"`
	Ring     bool    `json:"ring,omitempty"`
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
	ID        string
	TraitRefs []string
	Severity  Severity
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
	refPool := make(map[string]*refEntry)
	for _, f := range findings {
		if f.Severity < SeverityNotable || len(f.TraitRefs) == 0 {
			continue
		}
		ci, ok := traitIDToAtomIdx[f.ID]
		if !ok {
			continue
		}
		for _, ref := range f.TraitRefs {
			if refPool[ref] == nil {
				refPool[ref] = &refEntry{}
			}
			re := refPool[ref]
			seen := slices.Contains(re.composites, ci)
			if !seen {
				re.composites = append(re.composites, ci)
			}
		}
	}

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
