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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func TestReliabilityMetricsScrape(t *testing.T) {
	// Scrape a local provider without starting the production OTLP exporters.
	registry := prometheus.NewRegistry()
	exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		t.Fatalf("prometheus exporter: %v", err)
	}
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exporter))
	oldProvider := otel.GetMeterProvider()
	oldRequests, oldDuration, oldClientRender := depRequests, depDuration, clientRenderDuration
	otel.SetMeterProvider(provider)
	t.Cleanup(func() {
		otel.SetMeterProvider(oldProvider)
		depRequests, depDuration, clientRenderDuration = oldRequests, oldDuration, oldClientRender
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := provider.Shutdown(ctx); err != nil {
			t.Errorf("metrics shutdown: %v", err)
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

	oldStats := statsLatest.Load()
	statsLatest.Store(&indexStats{
		GeneratedAt: time.Now().UTC().Add(-30 * time.Second),
		Total:       1_234_567,
	})
	t.Cleanup(func() { statsLatest.Store(oldStats) })

	initDependencyMetrics()

	rec := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/_/metrik", http.NoBody))
	body := rec.Body.String()
	for _, want := range []string{
		`prism_backend_up{dependency="hopper-api"`,
		`prism_backend_up{dependency="litmus"`,
		`prism_circuit_breaker_state{dependency="hopper-api"`,
		`prism_circuit_breaker_state{dependency="hopper-db"`,
		"prism_hopper_db_connected",
		"prism_index_samples",
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
