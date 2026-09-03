package main

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
//
//	Co(llection) Dy(discoverY) Er(vasion) Eu(xfiltration) I(mpact) La(teral)
//	P(ersistence) Pr(ivilege) S(upply-chain) Xe(xecution)
//
// Micro-behaviors: Cm(comms) Cr(ypto) Db(data) Ds(dylib/shared) F(ilesystem)
//
//	Hf(hardware) Ho(st) Mg(memory) N(etwork) Os(operating-system) Po(process)
//	Ti(me) U(I)
//
// Metadata: Ar(ch) Bi(nary) Bk(build) Cf(config) He(hardening) In(import)
//
//	Li(brary) Pa(ckage) Pd(ocument) Pt(lang) Rh(ights/entitlements) Si(gned)
//	V(endor) + deeper: Ag(format) Au(quality) B(undle) Ce(compiler) Ne(archive)
//
//nolint:godoclint // section-divider comments inside a var block; first identifier in each group can't sensibly be the lead word
var (
	// Section: top-level categories.
	Oxygen      = Element{Number: 8, Symbol: "O", Name: "Oxygen"}         // Objectives
	Hydrogen    = Element{Number: 1, Symbol: "H", Name: "Hydrogen"}       // Micro-behaviors
	Mendelevium = Element{Number: 101, Symbol: "Md", Name: "Mendelevium"} // Metadata
	Potassium   = Element{Number: 19, Symbol: "K", Name: "Potassium"}     // Well-known (K for Known)
	Thorium     = Element{Number: 90, Symbol: "Th", Name: "Thorium"}      // Third-party

	// Section: objective subcategories.
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

	// Section: micro-behavior subcategories.
	Curium       = Element{Number: 96, Symbol: "Cm", Name: "Curium"}        // Communications
	Chromium     = Element{Number: 24, Symbol: "Cr", Name: "Chromium"}      // Crypto
	Dubnium      = Element{Number: 105, Symbol: "Db", Name: "Dubnium"}      // Data
	Darmstadtium = Element{Number: 110, Symbol: "Ds", Name: "Darmstadtium"} // Dylib
	Fluorine     = Element{Number: 9, Symbol: "F", Name: "Fluorine"}        // Filesystem
	Hafnium      = Element{Number: 72, Symbol: "Hf", Name: "Hafnium"}       // Hardware
	Holmium      = Element{Number: 67, Symbol: "Ho", Name: "Holmium"}       // Host
	Magnesium    = Element{Number: 12, Symbol: "Mg", Name: "Magnesium"}     // Memory
	Nitrogen     = Element{Number: 7, Symbol: "N", Name: "Nitrogen"}        // Network
	Osmium       = Element{Number: 76, Symbol: "Os", Name: "Osmium"}        // OS
	Polonium     = Element{Number: 84, Symbol: "Po", Name: "Polonium"}      // Process
	Titanium     = Element{Number: 22, Symbol: "Ti", Name: "Titanium"}      // Time
	Uranium      = Element{Number: 92, Symbol: "U", Name: "Uranium"}        // UI

	// Section: metadata subcategories (top-level under metadata/).
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

	// Section: metadata deeper-segment matches (3rd+ level).
	Gold   = Element{Number: 79, Symbol: "Au", Name: "Gold"}   // Quality (gold standard)
	Silver = Element{Number: 47, Symbol: "Ag", Name: "Silver"} // Format
	Boron  = Element{Number: 5, Symbol: "B", Name: "Boron"}    // Bundle
	Cerium = Element{Number: 58, Symbol: "Ce", Name: "Cerium"} // Compiler
	Neon   = Element{Number: 10, Symbol: "Ne", Name: "Neon"}   // Archive

	// Section: well-known subcategories.
	Tellurium = Element{Number: 52, Symbol: "Te", Name: "Tellurium"} // Tools

	// Section: categories cleave's malecule crate names that this table lacked.
	// The symbols are the crate's; keeping a second, shorter list here is what
	// made unknown categories fall back to initials in the drawings.
	Bromine    = Element{Number: 35, Symbol: "Br", Name: "Bromine"}    // Browser extension
	Iridium    = Element{Number: 77, Symbol: "Ir", Name: "Iridium"}    // Image
	Promethium = Element{Number: 61, Symbol: "Pm", Name: "Promethium"} // Permission
	Rhenium    = Element{Number: 75, Symbol: "Re", Name: "Rhenium"}    // Registry
	Americium  = Element{Number: 95, Symbol: "Am", Name: "Americium"}  // App
	Lutetium   = Element{Number: 71, Symbol: "Lu", Name: "Lutetium"}   // Dual-use
	Gallium    = Element{Number: 31, Symbol: "Ga", Name: "Gallium"}    // Game
	Moscovium  = Element{Number: 115, Symbol: "Mc", Name: "Moscovium"} // Malware
	Neodymium  = Element{Number: 60, Symbol: "Nd", Name: "Neodymium"}  // Unwanted
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
	"arch":     Argon,
	"binary":   Bismuth,
	"build":    Berkelium,
	"document": Palladium,
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

	// Categories carried over from the crate's table.
	"lib":               Lithium,
	"tool":              Tellurium,
	"browser-extension": Bromine,
	"image":             Iridium,
	"permission":        Promethium,
	"registry":          Rhenium,
	"app":               Americium,
	"dual-use":          Lutetium,
	"game":              Gallium,
	"unwanted":          Neodymium,

	// Well-known subcategories
	"malware": Potassium,
	"tools":   Tellurium,
}

// categoryToElement maps a category path segment to its element.
func categoryToElement(category string) (Element, bool) {
	e, ok := categoryElements[category]
	return e, ok
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
