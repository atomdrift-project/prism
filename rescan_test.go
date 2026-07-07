package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rescanTest points the hopper client at srv, runs one postRescanToHopper call
// against the given sha, and returns its error. Globals are restored on cleanup.
func rescanTest(t *testing.T, sha string, handler http.HandlerFunc) error {
	t.Helper()
	srv := httptest.NewServer(handler)
	defer srv.Close()

	oldAddr, oldClient := hopperAPIAddr, hopperClient
	hopperAPIAddr = srv.URL
	hopperClient = srv.Client()
	t.Cleanup(func() { hopperAPIAddr, hopperClient = oldAddr, oldClient })

	return postRescanToHopper(context.Background(), sha)
}

// TestPostRescanToHopper asserts prism POSTs to hopper's /api/rescan/{sha}
// endpoint and maps the response status the way the handler expects: 200 is
// success, 409 becomes errSampleNotEligible, and anything else is a generic
// error. The write goes over the API (not prism's read-only pool) so a replica
// deployment can still rescan.
func TestPostRescanToHopper(t *testing.T) {
	sha := strings.Repeat("a", 64)

	t.Run("queued", func(t *testing.T) {
		var gotPath, gotMethod string
		err := rescanTest(t, sha, func(w http.ResponseWriter, r *http.Request) {
			gotPath, gotMethod = r.URL.Path, r.Method
			w.Header().Set("Content-Type", "application/json")
			if _, err := w.Write([]byte(`{"status":"queued"}`)); err != nil {
				t.Errorf("write response: %v", err)
			}
		})
		if err != nil {
			t.Fatalf("postRescanToHopper: %v", err)
		}
		if want := "/api/rescan/" + sha; gotPath != want {
			t.Errorf("path = %q, want %q", gotPath, want)
		}
		if gotMethod != http.MethodPost {
			t.Errorf("method = %q, want POST", gotMethod)
		}
	})

	t.Run("not eligible", func(t *testing.T) {
		// 409 keeps the breaker closed (success fires for <500) so this stays
		// independent of breaker state across runs.
		err := rescanTest(t, sha, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"not eligible"}`, http.StatusConflict)
		})
		if !errors.Is(err, errSampleNotEligible) {
			t.Fatalf("postRescanToHopper = %v, want errSampleNotEligible", err)
		}
	})

	t.Run("other error", func(t *testing.T) {
		// 400 (also <500) surfaces as a generic error, not the eligibility
		// sentinel, and leaves the breaker closed.
		err := rescanTest(t, sha, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		})
		if err == nil || errors.Is(err, errSampleNotEligible) {
			t.Fatalf("postRescanToHopper = %v, want a generic non-eligibility error", err)
		}
	})
}
