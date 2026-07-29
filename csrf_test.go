package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCSRFKeyFromFile(t *testing.T) {
	const secret = "file-backed-csrf-secret-with-at-least-32-characters"
	path := filepath.Join(t.TempDir(), "csrf-key")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PRISM_CSRF_KEY", "environment-secret-with-at-least-32-characters")
	t.Setenv("PRISM_CSRF_KEY_FILE", path)

	if got, want := loadCSRFKey(), sha256.Sum256([]byte(secret)); got != want {
		t.Fatalf("loadCSRFKey() = %x, want file-derived %x", got, want)
	}
}
