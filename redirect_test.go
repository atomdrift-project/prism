package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedirectLegacyHost(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	handler := redirectLegacyHost(next)

	tests := []struct {
		name   string
		method string
		host   string
		target string
		status int
		want   string
	}{
		{"apex", "GET", "isotope13.ai", "/file/abc?tab=traits", http.StatusPermanentRedirect, "https://isotope13.io/file/abc?tab=traits"},
		{"mixed case with port", "GET", "Isotope13.AI:443", "/", http.StatusPermanentRedirect, "https://isotope13.io/"},
		{"www", "POST", "www.isotope13.ai", "/upload", http.StatusPermanentRedirect, "https://www.isotope13.io/upload"},
		{"lab", "GET", "lab.isotope13.ai", "/fallout", http.StatusPermanentRedirect, "https://lab.isotope13.io/fallout"},
		{"other subdomain passes through", "GET", "api.isotope13.ai", "/", http.StatusTeapot, ""},
		{"canonical passes through", "GET", "isotope13.io", "/", http.StatusTeapot, ""},
		{"lookalike passes through", "GET", "notisotope13.ai", "/", http.StatusTeapot, ""},
		{"localhost passes through", "GET", "localhost:8080", "/", http.StatusTeapot, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.target, http.NoBody)
			req.Host = tc.host
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.status {
				t.Errorf("status = %d, want %d", rec.Code, tc.status)
			}
			if got := rec.Header().Get("Location"); got != tc.want {
				t.Errorf("Location = %q, want %q", got, tc.want)
			}
		})
	}
}
