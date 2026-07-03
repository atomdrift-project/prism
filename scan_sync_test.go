package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// TestScanLevelConstantsInSync guards the cross-repo contract that prism's
// verdict-band cutoffs match scan's. Both derive the same 0/1/2 class from an
// envelope's fired `lvl`, so if the two drift a sample can read hostile in scan
// and suspicious (or benign) in prism — and vice versa. There is no shared
// source of truth at build time (scan is Rust), so this reads scan's model.rs
// directly and fails when the numbers diverge.
//
// It only runs when the scan repo is checked out beside prism (the normal dev
// layout). In an isolated CI checkout with no sibling scan tree, it skips rather
// than fails: prism can't verify a contract against a repo it can't see.
func TestScanLevelConstantsInSync(t *testing.T) {
	const scanModel = "../scan/src/model.rs"
	src, err := os.ReadFile(scanModel)
	if err != nil {
		abs, absErr := filepath.Abs(scanModel)
		if absErr != nil {
			abs = scanModel
		}
		t.Skipf("scan repo not checked out beside prism (%s); skipping cross-repo sync check", abs)
	}

	// prism constant -> the scan constant it must equal.
	checks := []struct {
		name      string
		prism     int
		scanConst string
	}{
		{"CriticalLevel", CriticalLevel, "DEFAULT_SEVERITY_LEVEL"},
		{"SuspiciousCeiling", SuspiciousCeiling, "SUSPICIOUS_LEVEL_CEILING"},
	}
	for _, c := range checks {
		// Matches e.g. `pub const DEFAULT_SEVERITY_LEVEL: u16 = 25;`, ignoring
		// visibility and underscores in the literal.
		re := regexp.MustCompile(c.scanConst + `:\s*u16\s*=\s*([0-9_]+)`)
		m := re.FindSubmatch(src)
		if m == nil {
			t.Fatalf("could not find scan constant %s in %s — was it renamed? update this test and keep the cutoffs in sync", c.scanConst, scanModel)
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
