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

	"github.com/atomdrift-project/hopper"
)

func TestMain(m *testing.M) {
	// prepareResultData uses the package-level logger; main() normally sets it.
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	os.Exit(m.Run())
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
		nonce := nonceFor(r)
		if nonce == "" {
			t.Fatal("nonce missing from request context")
		}
		w.Header().Set("Content-Type", "text/html")
		if _, err := w.Write([]byte(`<script nonce="` + nonce + `" src="/static/upload.js"></script>`)); err != nil {
			t.Errorf("write: %v", err)
		}
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

// TestPrepareResultData_SingleFileArchive verifies that when a zipfile wraps
// exactly one inner file both the container and the inner file are rendered.
// Earlier code collapsed the container away, which dropped its FileType,
// Size, Probability, and findings on the floor when the inner file's data
// did not mirror the container.
func TestPrepareResultData_SingleFileArchive(t *testing.T) {
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
					{"i": "metadata/format/zip", "d": "ZIP archive", "l": 3, "c": 0.9},
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
					{"i": "objectives/payload/execute", "d": "executes payload", "l": 4, "c": 0.9},
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

	if !data.IsArchive {
		t.Error("IsArchive should be true so the aggregated archive Traits tab renders")
	}
	if data.FileType != "ZIP" {
		t.Errorf("FileType = %q, want ZIP (from the depth-0 container)", data.FileType)
	}
	if data.SizeBytes != 1024 {
		t.Errorf("SizeBytes = %d, want 1024 (from the depth-0 container)", data.SizeBytes)
	}
}

// TestPrepareResultData_MultiFileArchivePreserved verifies the collapse does
// not fire for archives with multiple inner files.
func TestPrepareResultData_MultiFileArchivePreserved(t *testing.T) {
	raw := map[string]any{
		"fs": []map[string]any{
			{
				"id": 1, "dp": 0, "path": "/tmp/bundle.zip", "type": "zip", "sha": "aaaa", "sz": 1024,
				"ts": []map[string]any{{"i": "metadata/format/zip", "d": "ZIP archive", "l": 3, "c": 0.9}},
			},
			{
				"id": 2, "dp": 1, "path": "/tmp/bundle.zip!!a.exe", "type": "pe", "sha": "bbbb", "sz": 2048,
				"ts": []map[string]any{{"i": "objectives/payload/execute", "d": "executes", "l": 4, "c": 0.9}},
			},
			{
				"id": 3, "dp": 1, "path": "/tmp/bundle.zip!!b.exe", "type": "pe", "sha": "cccc", "sz": 2048,
				"ts": []map[string]any{{"i": "objectives/payload/execute", "d": "executes", "l": 4, "c": 0.9}},
			},
		},
	}
	rawBytes, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal raw: %v", err)
	}
	ml := map[string]any{"class": 2, "prob": 0.9, "thresholds": []float64{0.65, 0.887}}
	mlBytes, err := json.Marshal(ml)
	if err != nil {
		t.Fatalf("marshal ml: %v", err)
	}
	envelope, err := json.Marshal(map[string]json.RawMessage{"ml": mlBytes, "raw": rawBytes})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	data := prepareResultData("bundle.zip", strings.Repeat("b", 64), &storedResult{RawLitmus: string(envelope)})

	if !data.IsArchive {
		t.Error("IsArchive should be true for multi-inner-file archive")
	}
	if len(data.FileFindings) < 2 {
		t.Errorf("FileFindings: got %d entries, want >=2 for multi-file archive", len(data.FileFindings))
	}
}
