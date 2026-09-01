package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// backendProbeInterval is deliberately process-wide: page renders only read
	// an atomic status bit, so traffic volume can never turn health monitoring
	// into extra load on hopper-api or litmus.
	backendProbeInterval = 15 * time.Second
	backendProbeTimeout  = 3 * time.Second
)

type backendProbeState int32

const (
	backendHealthy backendProbeState = iota + 1
	backendUnhealthy
)

type backendProbe struct {
	name  string
	url   string
	state atomic.Int32
}

type backendAvailabilityMonitor struct {
	client   *http.Client
	hopper   *backendProbe
	litmus   *backendProbe
	interval time.Duration
}

var backendStatus *backendAvailabilityMonitor

func newBackendAvailabilityMonitor(hopperAddr, litmusServer string, client *http.Client) *backendAvailabilityMonitor {
	if client == nil {
		client = &http.Client{
			Timeout:   backendProbeTimeout,
			Transport: backendTransport(),
		}
	}
	return &backendAvailabilityMonitor{
		client: client,
		hopper: &backendProbe{
			name: "hopper-api",
			url:  backendHealthURL(hopperAddr, "/healthz"),
		},
		litmus: &backendProbe{
			name: "litmus",
			url:  backendHealthURL(litmusServer, "/_/health"),
		},
		interval: backendProbeInterval,
	}
}

// backendHealthURL turns an operator-configured host[:port] or base URL into
// its liveness endpoint. Invalid/disabled addresses stay empty and therefore
// unavailable without making a network request.
func backendHealthURL(addr, healthPath string) string {
	base := strings.TrimSpace(addr)
	if base == "" {
		return ""
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return ""
	}
	u.Path = strings.TrimRight(u.Path, "/") + healthPath
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// refresh probes the two independent servers concurrently. It is called once
// before serving and then only by run's single ticker, so each server receives
// at most one liveness request per backendProbeInterval.
func (m *backendAvailabilityMonitor) refresh(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { m.hopper.refresh(ctx, m.client) })
	wg.Go(func() { m.litmus.refresh(ctx, m.client) })
	wg.Wait()
}

func (m *backendAvailabilityMonitor) run(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.refresh(ctx)
		}
	}
}

func (p *backendProbe) refresh(ctx context.Context, client *http.Client) {
	healthy := false
	if p.url != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, http.NoBody)
		if err == nil {
			start := time.Now()
			resp, doErr := client.Do(req)
			if doErr == nil {
				healthy = resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck // keep-alive drain
				_ = resp.Body.Close()                                       //nolint:errcheck // best-effort
				if healthy {
					recordDep(ctx, p.name, "health", "ok", start)
				} else {
					recordDep(ctx, p.name, "health", "error", start)
				}
			} else {
				recordDep(ctx, p.name, "health", "error", start)
			}
		}
	}
	if ctx.Err() != nil {
		return
	}

	next := backendUnhealthy
	if healthy {
		next = backendHealthy
	}
	previous := backendProbeState(p.state.Swap(int32(next)))
	if previous == next || logger == nil {
		return
	}
	switch {
	case healthy:
		logger.Info("backend available", "dependency", p.name, "url", p.url)
	case p.url == "":
		logger.Info("backend disabled", "dependency", p.name)
	default:
		logger.Warn("backend unavailable; dependent controls disabled", "dependency", p.name, "url", p.url)
	}
}

func (p *backendProbe) available() bool {
	return backendProbeState(p.state.Load()) == backendHealthy
}

// Unknown status fails closed for optional controls. Production installs and
// performs the first refresh before templates are parsed or the listener
// starts, so this nil case is limited to startup and focused tests.
func hopperAPIAvailable() bool {
	return backendStatus != nil && backendStatus.hopper.available()
}

func uploadBackendsAvailable() bool {
	return backendStatus != nil && backendStatus.hopper.available() && backendStatus.litmus.available()
}

// litmusAvailable reports whether the analysis server is up. Uploads need it
// paired with hopper-api (uploadBackendsAvailable); escalation needs the same
// pair for a different reason — hopper-api to fetch the sample, litmus to
// analyze it — so it asks for the two halves separately.
func litmusAvailable() bool {
	return backendStatus != nil && backendStatus.litmus.available()
}
