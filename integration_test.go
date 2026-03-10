//go:build integration

package main

import (
	"bytes"
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

	if !waitReady(fmt.Sprintf("http://%s/health", litmusAddr), 30*time.Second) {
		fmt.Fprintln(os.Stderr, "skip: litmus did not become ready (models may not be installed)")
		litmusCmd.Process.Kill() //nolint:errcheck
		os.Exit(0)
	}

	// Start prism pointing at litmus.
	prismCmd := exec.Command(prismBin, "--no-cache", "--litmus-addr="+litmusAddr)
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
	if !waitReady(prismBase+"/health", 30*time.Second) {
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

// assertClassification uploads a file to prism and asserts the result page
// contains the expected classification and a non-empty malecule formula.
func assertClassification(t *testing.T, filePath, filename, wantClass string) {
	t.Helper()

	f, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("open %s: %v", filePath, err)
	}
	defer f.Close()

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
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

	resultResp, err := http.Get(prismBase + loc) //nolint:noctx
	if err != nil {
		t.Fatalf("GET %s: %v", loc, err)
	}
	defer resultResp.Body.Close()

	if resultResp.StatusCode != http.StatusOK {
		t.Fatalf("result page returned %d", resultResp.StatusCode)
	}
	body, err := io.ReadAll(resultResp.Body)
	if err != nil {
		t.Fatalf("read result body: %v", err)
	}
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
