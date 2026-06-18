package main

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Tier-1 dependency telemetry. prism is a cache/render tier in front of
// hopper, so the signals that actually page are the health of its outbound
// dependencies — not its own request mix, which obs.Middleware already
// covers via otelhttp. These instruments add what HTTP-level metrics
// structurally cannot see: per-dependency latency, outcome, and circuit-
// breaker position.
//
// Naming follows the obs convention (dot-separated, service-scoped meter).
// The Prometheus exporter renders these as:
//
//	prism_dependency_requests_total{dependency,operation,outcome}
//	prism_dependency_duration_seconds{dependency,operation,outcome}
//	prism_circuit_breaker_state{dependency}
//
// All label values are bounded: dependency and operation are compile-time
// constants at each call site, and outcome is one of ok/error/rejected.
// Nothing user-controlled (sha256, IP, query text) is ever a label.
var (
	depRequests metric.Int64Counter
	depDuration metric.Float64Histogram
)

// depLatencyBucketsSec mirrors obs's shared latency policy so prism's
// dependency histograms stack cleanly against worker.job.duration on a
// shared dashboard without rescaling.
var depLatencyBucketsSec = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
}

// initDependencyMetrics registers the dependency instruments and the
// circuit-breaker state gauge. Call once from main after obs.Init has
// installed the real meter provider. Instrument-creation errors are logged
// and leave the instrument nil; recordDep then degrades to a no-op so a
// telemetry fault never breaks a request path.
func initDependencyMetrics() {
	m := otel.Meter("codeberg.org/atomdrift/prism")

	if c, err := m.Int64Counter(
		"prism.dependency.requests",
		metric.WithDescription("Outbound dependency calls by outcome (ok/error/rejected)."),
	); err == nil {
		depRequests = c
	} else {
		logger.Warn("dependency request counter unavailable", "error", err)
	}

	if h, err := m.Float64Histogram(
		"prism.dependency.duration",
		metric.WithDescription("Latency of outbound dependency calls."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(depLatencyBucketsSec...),
	); err == nil {
		depDuration = h
	} else {
		logger.Warn("dependency duration histogram unavailable", "error", err)
	}

	// Circuit-breaker position as an async gauge: 0=closed, 1=open,
	// 2=half-open (matching breakerState's iota order). breakerOpen is the
	// direct alert — it means prism is shedding load to this dependency now.
	state, err := m.Int64ObservableGauge(
		"prism.circuit_breaker.state",
		metric.WithDescription("Circuit-breaker position: 0=closed, 1=open, 2=half-open."),
	)
	if err != nil {
		logger.Warn("circuit breaker state gauge unavailable", "error", err)
		return
	}
	if _, err := m.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		for _, b := range []*breaker{apiBreaker, dbBreaker} {
			o.ObserveInt64(state, int64(b.currentState()),
				metric.WithAttributes(attribute.String("dependency", b.name)))
		}
		return nil
	}, state); err != nil {
		logger.Warn("circuit breaker state callback registration failed", "error", err)
	}
}

// recordDep increments the dependency request counter and, when start is
// non-zero, records the call's latency. Pass a zero start for a fast-fail
// (outcome "rejected") that never reached the dependency, so it counts the
// shed call without polluting the latency histogram. Safe before
// initDependencyMetrics: a nil instrument makes this a no-op.
func recordDep(ctx context.Context, dependency, operation, outcome string, start time.Time) {
	if depRequests == nil {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("dependency", dependency),
		attribute.String("operation", operation),
		attribute.String("outcome", outcome),
	)
	depRequests.Add(ctx, 1, attrs)
	if !start.IsZero() && depDuration != nil {
		depDuration.Record(ctx, time.Since(start).Seconds(), attrs)
	}
}
