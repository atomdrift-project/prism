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
// breaker position — plus the reliability gauges operators watch for
// "is the corpus growing / is fallout filling / is hopper down?".
//
// Naming follows the obs convention (dot-separated, service-scoped meter).
// The Prometheus exporter renders these as:
//
//	prism_dependency_requests_total{dependency,operation,outcome}
//	prism_dependency_duration_seconds{dependency,operation,outcome}
//	prism_circuit_breaker_state{dependency}
//	prism_backend_up{dependency}
//	prism_hopper_db_connected
//	prism_index_samples / prism_index_rate_per_minute / prism_index_age_seconds
//	prism_fallout_entries / prism_fallout_truncated
//
// All label values are bounded: dependency and operation are compile-time
// constants at each call site, and outcome is one of ok/error/rejected.
// Nothing user-controlled (sha256, IP, query text) is ever a label.
var (
	depRequests metric.Int64Counter
	depDuration metric.Float64Histogram
	// clientRenderDuration records browser-side detail-page render phases from
	// the molecule.js RUM beacon (handleFileRUM) — the wall-clock the user
	// actually experienced (TTFB, DOM-ready, Three.js molecule build, first
	// paint). The phase and size attributes are bounded; no sha or user data is
	// ever a label.
	clientRenderDuration metric.Float64Histogram
)

// depLatencyBucketsSec mirrors obs's shared latency policy so prism's
// dependency histograms stack cleanly against worker.job.duration on a
// shared dashboard without rescaling.
var depLatencyBucketsSec = []float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
}

// initDependencyMetrics registers the dependency instruments and the
// reliability gauges. Call once from main after obs.Init has installed the
// real meter provider. Instrument-creation errors are logged and leave the
// instrument nil; recordDep then degrades to a no-op so a telemetry fault
// never breaks a request path.
func initDependencyMetrics() {
	m := otel.Meter("github.com/atomdrift-project/prism")

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

	if h, err := m.Float64Histogram(
		"prism.page.client_render.duration",
		metric.WithDescription("Browser-side detail-page render phases reported by the RUM beacon."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(depLatencyBucketsSec...),
	); err == nil {
		clientRenderDuration = h
	} else {
		logger.Warn("client render histogram unavailable", "error", err)
	}

	registerReliabilityGauges(m)
}

// registerReliabilityGauges publishes the process-wide SRE signals that
// already live in memory (stats poll, backend probes, breakers, fallout
// snapshot). One callback gathers a consistent scrape; nothing on this path
// issues a new DB query beyond what the feed cache already holds.
func registerReliabilityGauges(m metric.Meter) {
	var firstErr error
	var all []metric.Observable
	track := func(name string, obs metric.Observable, err error) {
		if err != nil && firstErr == nil {
			firstErr = err
			logger.Warn("reliability gauge unavailable", "metric", name, "error", err)
		}
		if obs != nil {
			all = append(all, obs)
		}
	}
	igauge := func(name, desc, unit string) metric.Int64Observable {
		opts := []metric.Int64ObservableGaugeOption{metric.WithDescription(desc)}
		if unit != "" {
			opts = append(opts, metric.WithUnit(unit))
		}
		g, err := m.Int64ObservableGauge(name, opts...)
		track(name, g, err)
		return g
	}
	fgauge := func(name, desc, unit string) metric.Float64Observable {
		opts := []metric.Float64ObservableGaugeOption{metric.WithDescription(desc)}
		if unit != "" {
			opts = append(opts, metric.WithUnit(unit))
		}
		g, err := m.Float64ObservableGauge(name, opts...)
		track(name, g, err)
		return g
	}

	breakerState := igauge(
		"prism.circuit_breaker.state",
		"Circuit-breaker position: 0=closed, 1=open, 2=half-open.",
		"",
	)
	backendUp := igauge(
		"prism.backend.up",
		"1 when the process-wide liveness probe last saw this backend healthy, else 0.",
		"",
	)
	dbConnected := igauge(
		"prism.hopper_db.connected",
		"1 when prism holds a live hopper Postgres pool, else 0 (reconnect in progress).",
		"",
	)
	indexSamples := igauge(
		"prism.index.samples",
		"Exact rows in samples, same number as the masthead counter.",
		"{sample}",
	)
	indexRate := fgauge(
		"prism.index.rate",
		"Samples inserted per minute over the trailing stats window.",
		"{sample}/min",
	)
	indexAge := fgauge(
		"prism.index.age",
		"Seconds since the last successful index-stats poll. Rising while samples stay flat means the poller cannot reach hopper-db.",
		"s",
	)
	falloutEntries := igauge(
		"prism.fallout.entries",
		"Hostile catches in the fallout log's current week (same count as the nav badge). Zero while the week's snapshot is cold.",
		"{sample}",
	)
	falloutTruncated := igauge(
		"prism.fallout.truncated",
		"1 when the current week's snapshot stopped at its page cap — the week holds more catches than the log can show.",
		"",
	)
	if firstErr != nil || len(all) == 0 {
		return
	}

	if _, err := m.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		for _, b := range []*breaker{apiBreaker, dbBreaker} {
			o.ObserveInt64(breakerState, int64(b.currentState()),
				metric.WithAttributes(attribute.String("dependency", b.name)))
		}

		observeBackend := func(name string, up bool) {
			var v int64
			if up {
				v = 1
			}
			o.ObserveInt64(backendUp, v, metric.WithAttributes(attribute.String("dependency", name)))
		}
		if backendStatus != nil {
			observeBackend("hopper-api", backendStatus.hopper.available())
			observeBackend("litmus", backendStatus.litmus.available())
		} else {
			observeBackend("hopper-api", false)
			observeBackend("litmus", false)
		}

		var connected int64
		if hopperDB.Load() != nil {
			connected = 1
		}
		o.ObserveInt64(dbConnected, connected)

		if snap, ok := cachedIndexStats(); ok {
			o.ObserveInt64(indexSamples, snap.Total)
			o.ObserveFloat64(indexRate, snap.RatePerMin)
			o.ObserveFloat64(indexAge, time.Since(snap.GeneratedAt).Seconds())
		} else {
			o.ObserveInt64(indexSamples, 0)
			o.ObserveFloat64(indexRate, 0)
			o.ObserveFloat64(indexAge, -1) // never polled successfully
		}

		// UTC: the gauges have no reader whose zone to borrow, and the log's
		// week is only cut per-reader for display.
		o.ObserveInt64(falloutEntries, int64(weeklyHostileCount(ctx, time.UTC)))
		var trunc int64
		if snapshot, _, ok := falloutCurrentWeek(ctx, time.UTC); ok && snapshot.Truncated {
			trunc = 1
		}
		o.ObserveInt64(falloutTruncated, trunc)
		return nil
	}, all...); err != nil {
		logger.Warn("reliability gauges callback registration failed", "error", err)
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

// recordClientRender records one browser-side render phase (in seconds) under
// its phase and molecule-size buckets. A non-positive value is dropped so an
// unmeasured phase never lands as a zero sample. Safe before
// initDependencyMetrics: a nil instrument makes this a no-op.
func recordClientRender(ctx context.Context, phase, size string, seconds float64) {
	if clientRenderDuration == nil || seconds <= 0 {
		return
	}
	clientRenderDuration.Record(ctx, seconds, metric.WithAttributes(
		attribute.String("phase", phase),
		attribute.String("size", size),
	))
}
