package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// TestScanLevelConstantsInSync guards the shared hostile cutoff between prism
// and scan. The suspicious ceiling is runtime-derived in scan, while prism has
// an independently configurable display ceiling, so only the fixed hostile
// cutoff is a cross-repo constant. There is no shared source of truth at build
// time (scan is Rust), so this reads scan's source directly.
//
// It only runs when the scan repo is checked out beside prism (the normal dev
// layout). In an isolated CI checkout with no sibling scan tree, it skips rather
// than fails: prism can't verify a contract against a repo it can't see.
func TestScanLevelConstantsInSync(t *testing.T) {
	const scanModel = "../scan/src/model.rs"
	_, err := os.Stat(scanModel)
	if os.IsNotExist(err) {
		abs, absErr := filepath.Abs(scanModel)
		if absErr != nil {
			abs = scanModel
		}
		t.Skipf("scan repo not checked out beside prism (%s); skipping cross-repo sync check", abs)
	}
	if err != nil {
		t.Fatalf("stat scan source %s: %v", scanModel, err)
	}

	// prism constant -> the scan constant it must equal.
	checks := []struct {
		name      string
		prism     int
		scanConst string
		file      string
	}{
		{"CriticalLevel", CriticalLevel, "DEFAULT_SEVERITY_LEVEL", scanModel},
	}
	for _, c := range checks {
		src, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatalf("read scan source %s: %v", c.file, err)
		}
		// Matches e.g. `pub const DEFAULT_SEVERITY_LEVEL: u16 = 25;`, ignoring
		// visibility and underscores in the literal.
		re := regexp.MustCompile(c.scanConst + `:\s*u16\s*=\s*([0-9_]+)`)
		m := re.FindSubmatch(src)
		if m == nil {
			t.Fatalf("could not find scan constant %s in %s — was it renamed? update this test and keep the cutoffs in sync", c.scanConst, c.file)
		}
		lit := regexp.MustCompile(`_`).ReplaceAllString(string(m[1]), "")
		want, err := strconv.Atoi(lit)
		if err != nil {
			t.Fatalf("scan %s = %q is not an integer: %v", c.scanConst, m[1], err)
		}
		if c.prism != want {
			t.Errorf("prism %s = %d but scan %s = %d — the verdict bands have drifted; reconcile both (and hopper/promoter/collimator)", c.name, c.prism, c.scanConst, want)
		}
	}
}
