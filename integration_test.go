//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// prismBase is set by TestMain and shared across all integration tests.
var prismBase string

func TestMain(m *testing.M) {
	litmusDir := "../litmus"
	if _, err := os.Stat(litmusDir); err != nil {
		fmt.Fprintln(os.Stderr, "skip: ../litmus directory not found")
		os.Exit(0)
	}

	// Build litmus; use --release so analysis runs at usable speed.
	fmt.Fprintln(os.Stderr, "building litmus --release ...")
	buildCmd := exec.Command("cargo", "build", "--release")
	buildCmd.Dir = litmusDir
	if out, err := buildCmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "skip: cargo build --release failed: %v\n%s\n", err, out)
		os.Exit(0)
	}
	litmusBin := filepath.Join(litmusDir, "target", "release", "litmus")

	// Build prism.
	fmt.Fprintln(os.Stderr, "building prism ...")
	prismBin := filepath.Join(os.TempDir(), "prism-integration-test")
	if out, err := exec.Command("go", "build", "-o", prismBin, ".").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: go build failed: %v\n%s\n", err, out)
		os.Exit(1)
	}
	defer os.Remove(prismBin)

	litmusAddr := fmt.Sprintf("127.0.0.1:%d", freePort())
	prismPort := freePort()

	// Start litmus.
	litmusCmd := exec.Command(litmusBin, "serve", "--bind", litmusAddr)
	litmusCmd.Stderr = os.Stderr
	if err := litmusCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: start litmus: %v\n", err)
		os.Exit(1)
	}

	if !waitReady(fmt.Sprintf("http://%s/_/health", litmusAddr), 30*time.Second) {
		fmt.Fprintln(os.Stderr, "skip: litmus did not become ready (models may not be installed)")
		litmusCmd.Process.Kill() //nolint:errcheck
		os.Exit(0)
	}

	// Start prism. Uploads now flow prism → hopper → worker rather than
	// prism → litmus, so this integration test needs the surrounding
	// hopper + worker setup configured separately (via HOPPER_DSN /
	// HOPPER_API_ADDR) before it'll exercise a real analysis path.
	_ = litmusAddr
	prismCmd := exec.Command(prismBin, "--no-cache")
	prismCmd.Env = append(os.Environ(),
		fmt.Sprintf("PORT=%d", prismPort),
		"GCS_BUCKET=",
	)
	prismCmd.Stderr = os.Stderr
	if err := prismCmd.Start(); err != nil {
		litmusCmd.Process.Kill() //nolint:errcheck
		fmt.Fprintf(os.Stderr, "FATAL: start prism: %v\n", err)
		os.Exit(1)
	}

	prismBase = fmt.Sprintf("http://127.0.0.1:%d", prismPort)
	if !waitReady(prismBase+"/_/health", 30*time.Second) {
		litmusCmd.Process.Kill() //nolint:errcheck
		prismCmd.Process.Kill()  //nolint:errcheck
		fmt.Fprintln(os.Stderr, "FATAL: prism did not become ready")
		os.Exit(1)
	}

	code := m.Run()
	// Kill children before os.Exit — deferred functions do not run after os.Exit,
	// and leaving them alive keeps their stderr pipe open, causing "I/O incomplete".
	litmusCmd.Process.Kill() //nolint:errcheck
	prismCmd.Process.Kill()  //nolint:errcheck
	os.Exit(code)
}

func TestIntegrationHostile(t *testing.T) {
	if _, err := os.Stat("testdata/midd.zip"); err != nil {
		t.Skipf("testdata/midd.zip not found")
	}
	assertClassification(t, "testdata/midd.zip", "midd.zip", "hostile")
}

func TestIntegrationBenign(t *testing.T) {
	assertClassification(t, "/bin/ls", "ls", "benign")
}

func TestIntegrationRustSource(t *testing.T) {
	const testFile = "testdata/ort_lib.rs"
	if _, err := os.Stat(testFile); err != nil {
		t.Skipf("testdata/ort_lib.rs not found")
	}

	sha, htmlBody := uploadFile(t, testFile, "lib.rs")
	page := string(htmlBody)

	// Should not show the "unsupported format" banner.
	if strings.Contains(page, "not yet supported") {
		t.Error("result page shows 'not yet supported' banner for Rust source file")
	}

	// Formula must be present (may be baseline for clean source).
	formula := extractDivContent(page, "formula")
	if formula == "" {
		t.Error("expected non-empty mal-ecule formula, got empty")
	}
	t.Logf("formula: %s", formula)

	// Strings tab must be populated.
	if strings.Contains(page, "No strings extracted") {
		t.Error("result page shows 'No strings extracted' for Rust source file")
	}

	// Symbols tab must be populated.
	if strings.Contains(page, "No symbols found") {
		t.Error("result page shows 'No symbols found' for Rust source file")
	}

	// Metrics tab: source files have no binary metrics; verify it degrades gracefully.
	if strings.Contains(page, "No metrics available") {
		t.Log("metrics: none (expected for source files)")
	}

	// Fetch the JSON report and check structured data.
	jsonResp, err := http.Get(prismBase + "/file/" + sha + ".json") //nolint:noctx
	if err != nil {
		t.Fatalf("GET /file/%s.json: %v", sha, err)
	}
	defer jsonResp.Body.Close()
	if jsonResp.StatusCode != http.StatusOK {
		t.Fatalf("JSON endpoint returned %d", jsonResp.StatusCode)
	}

	rawBody, err := io.ReadAll(jsonResp.Body)
	if err != nil {
		t.Fatalf("read JSON body: %v", err)
	}
	t.Logf("raw JSON:\n%s", rawBody)

	type symbolEntry struct {
		Symbol string `json:"symbol"`
		Name   string `json:"name"`
	}
	var report struct {
		Path           string `json:"path"`
		Classification string `json:"classification"`
		Formula        string `json:"formula"`
		FileType       string `json:"file_type"`
		Cleave         struct {
			Imports []symbolEntry `json:"imports"`
			Exports []symbolEntry `json:"exports"`
			Files   []struct {
				FileType string `json:"file_type"`
				Strings  []struct {
					Value string `json:"value"`
				} `json:"strings"`
				Imports []symbolEntry `json:"imports"`
				Exports []symbolEntry `json:"exports"`
				Metrics *struct{}     `json:"metrics"`
			} `json:"files"`
		} `json:"cleave"`
	}
	if err := json.Unmarshal(rawBody, &report); err != nil {
		t.Fatalf("decode JSON report: %v", err)
	}

	t.Logf("path: %s", report.Path)
	t.Logf("classification: %s", report.Classification)
	t.Logf("formula: %s", report.Formula)
	t.Logf("file_type: %s", report.FileType)
	t.Logf("cleave top-level imports: %d, exports: %d", len(report.Cleave.Imports), len(report.Cleave.Exports))

	if len(report.Cleave.Files) == 0 {
		t.Fatal("JSON report contains no files")
	}
	f := report.Cleave.Files[0]

	// Symbols may be at top-level of cleave or inside the file entry.
	allImports := append(f.Imports, report.Cleave.Imports...)
	allExports := append(f.Exports, report.Cleave.Exports...)

	t.Logf("file_type: %s", f.FileType)
	t.Logf("strings: %d", len(f.Strings))
	t.Logf("imports: %d (file), %d (top-level), exports: %d (file), %d (top-level)",
		len(f.Imports), len(report.Cleave.Imports), len(f.Exports), len(report.Cleave.Exports))

	if len(f.Strings) == 0 {
		t.Error("JSON report: no strings extracted from Rust source file")
	}
	if len(allImports)+len(allExports) == 0 {
		t.Error("JSON report: no symbols (imports or exports) found in Rust source file")
	}
	// Metrics are binary-only; source files are expected to have none.
	if f.Metrics != nil {
		t.Logf("metrics present (unexpected for source file)")
	} else {
		t.Log("metrics: none (expected for source files)")
	}
}

// assertClassification uploads a file to prism and asserts the result page
// contains the expected classification and a non-empty malecule formula.
func assertClassification(t *testing.T, filePath, filename, wantClass string) {
	t.Helper()
	_, body := uploadFile(t, filePath, filename)
	page := strings.ToLower(string(body))

	if !strings.Contains(page, wantClass) {
		t.Errorf("expected classification %q in result page", wantClass)
	}
	t.Logf("classification: %s", wantClass)

	formula := extractDivContent(string(body), "formula")
	if formula == "" || formula == "∅" {
		t.Errorf("expected non-empty malecule formula in div.formula, got %q", formula)
	}
	t.Logf("formula: %s", formula)
}

// uploadFile uploads a file to prism and returns the SHA256 from the redirect
// and the HTML body of the result page.
func uploadFile(t *testing.T, filePath, filename string) (sha string, body []byte) {
	t.Helper()

	// Fetch the index page to get a fresh CSRF token.
	indexResp, err := http.Get(prismBase + "/") //nolint:noctx
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	indexBody, err := io.ReadAll(indexResp.Body)
	indexResp.Body.Close()
	if err != nil {
		t.Fatalf("read index body: %v", err)
	}
	csrfToken := extractInputValue(string(indexBody), "csrf_token")
	if csrfToken == "" {
		t.Fatal("could not extract csrf_token from index page")
	}

	f, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("open %s: %v", filePath, err)
	}
	defer f.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("csrf_token", csrfToken); err != nil {
		t.Fatalf("write csrf_token field: %v", err)
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := io.Copy(fw, f); err != nil {
		t.Fatalf("copy file data: %v", err)
	}
	mw.Close()

	client := &http.Client{
		Timeout: 2 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Post(prismBase+"/upload", mw.FormDataContentType(), &buf)
	if err != nil {
		t.Fatalf("POST /upload: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected 303 from /upload, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "/file/") {
		t.Fatalf("unexpected redirect location: %q", loc)
	}
	sha = strings.TrimPrefix(loc, "/file/")

	resultResp, err := http.Get(prismBase + loc) //nolint:noctx
	if err != nil {
		t.Fatalf("GET %s: %v", loc, err)
	}
	defer resultResp.Body.Close()

	if resultResp.StatusCode != http.StatusOK {
		t.Fatalf("result page returned %d", resultResp.StatusCode)
	}
	body, err = io.ReadAll(resultResp.Body)
	if err != nil {
		t.Fatalf("read result body: %v", err)
	}
	return sha, body
}

// extractInputValue returns the value attribute of the first <input name="NAME"> element.
func extractInputValue(html, name string) string {
	needle := `name="` + name + `"`
	idx := strings.Index(html, needle)
	if idx == -1 {
		return ""
	}
	// Search backwards and forwards within the same tag for value="..."
	tagStart := strings.LastIndex(html[:idx], "<input")
	if tagStart == -1 {
		return ""
	}
	tagEnd := strings.Index(html[tagStart:], ">")
	if tagEnd == -1 {
		return ""
	}
	tag := html[tagStart : tagStart+tagEnd]
	const valAttr = `value="`
	vi := strings.Index(tag, valAttr)
	if vi == -1 {
		return ""
	}
	vi += len(valAttr)
	end := strings.Index(tag[vi:], `"`)
	if end == -1 {
		return ""
	}
	return tag[vi : vi+end]
}

// extractDivContent returns the text content of the first <div class="CLASS"> element.
func extractDivContent(html, class string) string {
	open := `<div class="` + class + `">`
	start := strings.Index(html, open)
	if start == -1 {
		return ""
	}
	start += len(open)
	end := strings.Index(html[start:], "</div>")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(html[start : start+end])
}

// freePort binds to :0 to let the OS pick an available port, then releases it.
func freePort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Sprintf("freePort: %v", err))
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// waitReady polls the given URL until it returns 200 or the timeout elapses.
func waitReady(url string, timeout time.Duration) bool {
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url) //nolint:noctx
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}
