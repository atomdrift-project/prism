package main

import (
	"math"
	"path/filepath"
	"sort"
	"strings"
)

// Element represents a periodic table element.
type Element struct {
	Number int
	Symbol string
	Name   string
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
	Oxygen       = Element{8, "O", "Oxygen"}          // Objectives
	Hydrogen     = Element{1, "H", "Hydrogen"}        // Micro-behaviors
	Mendelevium  = Element{101, "Md", "Mendelevium"}  // Metadata
	Potassium    = Element{19, "K", "Potassium"}      // Well-known
	Thorium      = Element{90, "Th", "Thorium"}       // Third-party
	Carbon       = Element{6, "C", "Carbon"}          // Command & Control
	Aluminum     = Element{13, "Al", "Aluminum"}      // Anti-analysis
	Arsenic      = Element{33, "As", "Arsenic"}       // Anti-static
	Cobalt       = Element{27, "Co", "Cobalt"}        // Collection
	Calcium      = Element{20, "Ca", "Calcium"}       // Credential-access
	Dysprosium   = Element{66, "Dy", "Dysprosium"}    // Discovery
	Xenon        = Element{54, "Xe", "Xenon"}         // Execution
	Europium     = Element{63, "Eu", "Europium"}      // Exfiltration
	Iodine       = Element{53, "I", "Iodine"}         // Impact
	Lanthanum    = Element{57, "La", "Lanthanum"}     // Lateral-movement
	Phosphorus   = Element{15, "P", "Phosphorus"}     // Persistence
	Praseodymium = Element{59, "Pr", "Praseodymium"}  // Privilege-escalation
	Erbium       = Element{68, "Er", "Erbium"}        // Evasion
	Rubidium     = Element{37, "Rb", "Rubidium"}      // Resource-development
	Chromium     = Element{24, "Cr", "Chromium"}      // Crypto
	Curium       = Element{96, "Cm", "Curium"}        // Communications
	Fluorine     = Element{9, "F", "Fluorine"}        // Filesystem
	Polonium     = Element{84, "Po", "Polonium"}      // Process
	Osmium       = Element{76, "Os", "Osmium"}        // OS
	Dubnium      = Element{105, "Db", "Dubnium"}      // Data
	Holmium      = Element{67, "Ho", "Holmium"}       // Host
	Hafnium      = Element{72, "Hf", "Hafnium"}       // Hardware
	Neptunium    = Element{93, "Np", "Neptunium"}     // Network
	Darmstadtium = Element{110, "Ds", "Darmstadtium"} // Dylib
	Actinium     = Element{89, "Ac", "Actinium"}      // Anti-analysis (micro)
	Astatine     = Element{85, "At", "Astatine"}      // Anti-static (micro)
	Einsteinium  = Element{99, "Es", "Einsteinium"}   // Execution (micro)
	Gold         = Element{79, "Au", "Gold"}          // Quality
	Silver       = Element{47, "Ag", "Silver"}        // Format
	Platinum     = Element{78, "Pt", "Platinum"}      // Lang
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
	ID       int     `json:"id"`
	X        float64 `json:"x"`
	Y        float64 `json:"y"`
	Z        float64 `json:"z"`
	Radius   float64 `json:"radius"`
	Severity string  `json:"severity"`
	Symbol   string  `json:"symbol"`
	Category string  `json:"category"`
	TraitID  string  `json:"trait_id,omitempty"`
}

// MaleculeData contains the complete molecule data for 3D rendering.
type MaleculeData struct {
	Atoms   []MaleculeAtom `json:"atoms"`
	Bonds   [][2]int       `json:"bonds"`
	Formula string         `json:"formula"`
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
	IsGalaxy  bool           `json:"isGalaxy"`
	Molecules []FileMolecule `json:"molecules"`
	Links     []GalaxyLink   `json:"links"` // Dropper relationships
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

// BuildMalecule creates a 3D molecule structure from findings.
func BuildMalecule(findings []FindingForFormula, formula string) MaleculeData {
	mol := MaleculeData{
		Formula: formula,
	}

	if len(findings) == 0 {
		return mol
	}

	// Group findings by top-level and subcategory
	type atomInfo struct {
		category string
		severity Severity
		element  Element
		traitIDs []string
	}

	atomMap := make(map[string]*atomInfo)

	for _, f := range findings {
		parts := strings.Split(f.ID, "/")
		if len(parts) < 2 {
			continue
		}

		topLevel := parts[0]
		var subCat string
		var elem Element

		// Find subcategory element
		for i := len(parts) - 1; i >= 1; i-- {
			if e, ok := categoryToElement(parts[i]); ok {
				subCat = parts[i]
				elem = e
				break
			}
		}

		if subCat == "" {
			continue
		}

		key := topLevel + "/" + subCat
		if ai, exists := atomMap[key]; exists {
			ai.traitIDs = append(ai.traitIDs, f.ID)
			if f.Severity > ai.severity {
				ai.severity = f.Severity
			}
		} else {
			atomMap[key] = &atomInfo{
				category: key,
				severity: f.Severity,
				element:  elem,
				traitIDs: []string{f.ID},
			}
		}
	}

	// Convert to atoms with 3D positions using spherical layout
	var atoms []MaleculeAtom
	idx := 0

	// Sort keys for deterministic order
	var keys []string
	for k := range atomMap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ai, aj := atomMap[keys[i]], atomMap[keys[j]]
		if ai.severity != aj.severity {
			return ai.severity > aj.severity
		}
		return keys[i] < keys[j]
	})

	n := float64(len(keys))
	goldenAngle := math.Pi * (3.0 - math.Sqrt(5.0))
	radius := 3.0

	for i, key := range keys {
		ai := atomMap[key]

		// Fibonacci sphere distribution
		y := 1.0 - (float64(i)+0.5)/n*2.0
		r := math.Sqrt(1.0 - y*y)
		theta := goldenAngle * float64(i)

		x := r * math.Cos(theta) * radius
		z := r * math.Sin(theta) * radius
		y = y * radius

		atomRadius := 0.4
		if ai.severity >= SeveritySuspicious {
			atomRadius = 0.5
		}
		if ai.severity == SeverityHostile {
			atomRadius = 0.6
		}

		atoms = append(atoms, MaleculeAtom{
			ID:       idx,
			X:        x,
			Y:        y,
			Z:        z,
			Radius:   atomRadius,
			Severity: ai.severity.String(),
			Symbol:   ai.element.Symbol,
			Category: ai.category,
			TraitID:  strings.Join(ai.traitIDs, ", "),
		})
		idx++
	}

	// Create bonds between atoms in same top-level category
	var bonds [][2]int
	for i := 0; i < len(atoms); i++ {
		topI := strings.Split(atoms[i].Category, "/")[0]
		for j := i + 1; j < len(atoms); j++ {
			topJ := strings.Split(atoms[j].Category, "/")[0]
			if topI == topJ {
				bonds = append(bonds, [2]int{i, j})
			}
		}
	}

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
