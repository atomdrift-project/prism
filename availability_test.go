package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestBackendHealthURL(t *testing.T) {
	tests := []struct {
		addr string
		path string
		want string
	}{
		{"hopper-api:8081", "/healthz", "http://hopper-api:8081/healthz"},
		{"https://example.test/base/", "/healthz", "https://example.test/base/healthz"},
		{"", "/healthz", ""},
		{"://bad", "/healthz", ""},
	}
	for _, tt := range tests {
		if got := backendHealthURL(tt.addr, tt.path); got != tt.want {
			t.Errorf("backendHealthURL(%q, %q) = %q, want %q", tt.addr, tt.path, got, tt.want)
		}
	}
}

func TestBackendAvailabilityIsShared(t *testing.T) {
	if backendProbeInterval != 15*time.Second {
		t.Fatalf("backendProbeInterval = %s, want 15s", backendProbeInterval)
	}

	var hopperCalls atomic.Int32
	hopper := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hopperCalls.Add(1)
		if r.URL.Path != "/healthz" {
			t.Errorf("hopper probe path = %q, want /healthz", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hopper.Close()

	var litmusCalls atomic.Int32
	litmus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		litmusCalls.Add(1)
		if r.URL.Path != "/_/health" {
			t.Errorf("litmus probe path = %q, want /_/health", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer litmus.Close()

	monitor := newBackendAvailabilityMonitor(hopper.URL, litmus.URL, &http.Client{Timeout: time.Second})
	monitor.refresh(context.Background())
	if !monitor.hopper.available() || !monitor.litmus.available() {
		t.Fatal("healthy probes were not published")
	}

	// UI and handler gates are atomic reads. Any amount of request traffic
	// between ticker refreshes must not generate another backend check.
	for range 1000 {
		_ = monitor.hopper.available()
		_ = monitor.litmus.available()
	}
	if got := hopperCalls.Load(); got != 1 {
		t.Errorf("hopper probes = %d, want 1", got)
	}
	if got := litmusCalls.Load(); got != 1 {
		t.Errorf("litmus probes = %d, want 1", got)
	}
}

func TestBackendAvailabilityRejectsUnhealthyStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	monitor := newBackendAvailabilityMonitor(server.URL, server.URL, &http.Client{Timeout: time.Second})
	monitor.refresh(context.Background())
	if monitor.hopper.available() || monitor.litmus.available() {
		t.Fatal("503 backend reported available")
	}
}

func TestFeatureAvailabilityRequirements(t *testing.T) {
	oldStatus := backendStatus
	backendStatus = newBackendAvailabilityMonitor("", "", &http.Client{Timeout: time.Second})
	t.Cleanup(func() { backendStatus = oldStatus })

	backendStatus.hopper.state.Store(int32(backendHealthy))
	if !hopperAPIAvailable() {
		t.Fatal("downloads should be available with a healthy hopper-api")
	}
	if uploadBackendsAvailable() {
		t.Fatal("uploads should require litmus as well as hopper-api")
	}

	backendStatus.litmus.state.Store(int32(backendHealthy))
	if !uploadBackendsAvailable() {
		t.Fatal("uploads should be available when both backends are healthy")
	}

	backendStatus.hopper.state.Store(int32(backendUnhealthy))
	if hopperAPIAvailable() || uploadBackendsAvailable() {
		t.Fatal("hopper-api outage should disable downloads and uploads")
	}
}
