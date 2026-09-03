package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/atomdrift-project/obs"
)

func TestReliabilityMetricsScrape(t *testing.T) {
	shutdown, err := obs.Init(context.Background(), obs.Config{ServiceName: "prism-test", DisableSlog: true})
	if err != nil {
		t.Fatalf("obs.Init: %v", err)
	}
	t.Cleanup(func() {
		if err := shutdown(context.Background()); err != nil {
			t.Logf("obs shutdown: %v", err)
		}
	})

	oldLogger := logger
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	t.Cleanup(func() { logger = oldLogger })

	oldStatus := backendStatus
	backendStatus = newBackendAvailabilityMonitor("", "", &http.Client{Timeout: time.Second})
	backendStatus.hopper.state.Store(int32(backendHealthy))
	backendStatus.litmus.state.Store(int32(backendUnhealthy))
	t.Cleanup(func() { backendStatus = oldStatus })

	statsLatest.Store(&indexStats{
		GeneratedAt: time.Now().UTC().Add(-30 * time.Second),
		Total:       1_234_567,
		RatePerMin:  12.5,
	})
	t.Cleanup(func() { statsLatest.Store(nil) })

	initDependencyMetrics()

	rec := httptest.NewRecorder()
	obs.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_/metrik", http.NoBody))
	body := rec.Body.String()
	for _, want := range []string{
		`prism_backend_up{dependency="hopper-api"`,
		`prism_backend_up{dependency="litmus"`,
		`prism_circuit_breaker_state{dependency="hopper-api"`,
		`prism_circuit_breaker_state{dependency="hopper-db"`,
		"prism_hopper_db_connected",
		"prism_index_samples",
		"prism_index_rate_per_min",
		"prism_index_age_seconds",
		"prism_fallout_entries",
		"prism_fallout_truncated",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape missing %q\n--- body ---\n%s", want, body)
		}
	}
	if !strings.Contains(body, "prism_index_samples{") ||
		(!strings.Contains(body, "1.234567e+06") && !strings.Contains(body, "1234567")) {
		t.Errorf("expected index samples total in scrape\n--- body ---\n%s", body)
	}
}
