// Package main implements the prism malware analysis web service.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"cloud.google.com/go/storage"
	"github.com/codeGROOVE-dev/fido"
	"github.com/codeGROOVE-dev/fido/pkg/store/cloudrun"
	"github.com/codeGROOVE-dev/fido/pkg/store/null"
	"github.com/codeGROOVE-dev/retry"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// buildCommit is set via -ldflags at build time (see Makefile).
var buildCommit = "dev"

var (
	uploadTemplate    *template.Template
	resultTemplate    *template.Template
	errorTemplate     *template.Template
	formatsTemplate   *template.Template
	poweredByTemplate *template.Template
	gcsBucket         string
	litmusAddr        string       // Address of litmus server (e.g., "127.0.0.1:8080")
	litmusClient      *http.Client // HTTP client for litmus server
	gcsClient         *storage.Client
	cache             *fido.TieredCache[string, storedResult]
	logger            *slog.Logger
	publicMode        bool // true when --public flag is set; changes branding and shows data-sharing notice
)

// csrfKey is a random 32-byte key generated at startup for HMAC-signing CSRF tokens.
// Tokens are stateless: HMAC(timestamp) verified on POST. Key rotates on restart,
// which is fine — an in-flight form simply needs resubmission after a deploy.
var csrfKey = func() [32]byte {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		panic("csrf: failed to generate key: " + err.Error())
	}
	return k
}()

// csrfToken generates a signed, timestamped CSRF token.
func csrfToken() string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, csrfKey[:])
	mac.Write([]byte(ts))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return ts + "." + sig
}

// csrfValid checks that the token is well-formed, correctly signed, and not older than maxAge.
func csrfValid(token string, maxAge time.Duration) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	age := time.Since(time.Unix(ts, 0))
	if age < 0 || age > maxAge {
		return false
	}
	mac := hmac.New(sha256.New, csrfKey[:])
	mac.Write([]byte(parts[0]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(parts[1]), []byte(expected))
}

// uploadLimiter implements a per-IP token bucket rate limiter for the upload endpoint.
// Each IP gets a bucket that refills at 1 token per minute, with a burst of 5.
type uploadLimiter struct {
	buckets map[string]*bucket
	mu      sync.Mutex
}

type bucket struct {
	lastSeen time.Time
	tokens   float64
}

const (
	uploadBurst    = 5                // max uploads before throttling
	uploadRate     = 1.0 / 60.0       // tokens per second (1 per minute)
	bucketLifetime = 10 * time.Minute // evict idle entries
)

func newUploadLimiter() *uploadLimiter {
	ul := &uploadLimiter{buckets: make(map[string]*bucket)}
	go ul.reap()
	return ul
}

// allow checks whether the given IP may proceed with an upload.
func (ul *uploadLimiter) allow(ip string) bool {
	ul.mu.Lock()
	defer ul.mu.Unlock()

	now := time.Now()
	b, ok := ul.buckets[ip]
	if !ok {
		ul.buckets[ip] = &bucket{tokens: float64(uploadBurst) - 1, lastSeen: now}
		return true
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * uploadRate
	if b.tokens > float64(uploadBurst) {
		b.tokens = float64(uploadBurst)
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// reap periodically removes stale entries to prevent memory growth.
func (ul *uploadLimiter) reap() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		ul.mu.Lock()
		now := time.Now()
		for ip, b := range ul.buckets {
			if now.Sub(b.lastSeen) > bucketLifetime {
				delete(ul.buckets, ip)
			}
		}
		ul.mu.Unlock()
	}
}

var rateLimiter = newUploadLimiter()

// clientIP extracts the client IP from the request, preferring the rightmost
// entry in X-Forwarded-For (set by the nearest trusted proxy — Cloud Run LB
// or cloudflared) and falling back to RemoteAddr.
//
// The rightmost entry is used because it is added by the infrastructure proxy
// and cannot be spoofed by the client.  The leftmost entry is attacker-
// controlled: any client can send "X-Forwarded-For: fake" and the proxy
// appends the real IP, yielding "fake, real".
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Rightmost entry is added by the nearest trusted proxy.
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// FindingDisplay represents a single finding for table display.
type FindingDisplay struct {
	ID       string
	Crit     string
	Desc     string
	Evidence []string
}

// CategoryGroup groups findings by top-level category.
type CategoryGroup struct {
	Name     string // "Objectives", "Micro-behaviors", etc.
	Findings []FindingDisplay
}

// FileFindingsDisplay represents all findings for a single file.
type FileFindingsDisplay struct {
	Path           string
	Basename       string
	Risk           string
	Classification string  // litmus ML classification: "hostile", "suspicious", "benign"
	SHA256         string
	Formula        string
	FileType       string
	Probability    float64 // litmus ML probability [0.0, 1.0]
	Categories     []CategoryGroup
}

// FileStringsDisplay represents strings for a single file.
type FileStringsDisplay struct {
	Basename       string
	Risk           string
	Classification string
	SHA256         string
	Formula        string
	FileType       string
	Probability    float64
	Strings        []StringDisplay
	Sections       []StringSectionGroup // strings grouped by section (when section data available)
	HasSections    bool                 // true when at least one string has section info
}

type StringDisplay struct {
	Value   string
	Section string
	Offset  string
}

// StringSectionGroup groups strings by their binary section.
type StringSectionGroup struct {
	Section string
	Strings []StringDisplay
}

// FileSymbolsDisplay represents symbols for a single file.
type FileSymbolsDisplay struct {
	Basename       string
	Risk           string
	Classification string
	SHA256         string
	Formula        string
	FileType       string
	Probability    float64
	Imports        []SymbolDisplay
	Exports        []SymbolDisplay
}

type SymbolDisplay struct {
	Name    string
	Library string
}

// FileSectionsDisplay represents sections for a single file.
type FileSectionsDisplay struct {
	Basename       string
	Risk           string
	Classification string
	SHA256         string
	Formula        string
	FileType       string
	Probability    float64
	Sections       []SectionDisplay
}

type SectionDisplay struct {
	Name    string
	Offset  string
	Flags   string
	Entropy float64
	Size    int64
}

// MetricField is a single labelled metric value for display.
type metricField struct {
	Label string
	Value string
}

// MetricGroup is a named collection of metric fields for display.
type metricGroup struct {
	Name   string
	Fields []metricField
}

// FileMetricsDisplay represents metrics for a single file.
type FileMetricsDisplay struct {
	Basename       string
	Risk           string
	Classification string
	SHA256         string
	Formula        string
	FileType       string
	Probability    float64
	Groups         []metricGroup
}

type resultData struct {
	RiskLabel    string
	Size         string
	SHA256       string
	Verdict      string
	Formula      template.HTML
	FileType     string
	MoleculeJSON template.JS
	RiskLevel    string
	Filename     string
	Nonce        string
	SHA256Short  string
	FindingCount string
	Duration     string
	FileFindings []FileFindingsDisplay
	FileStrings  []FileStringsDisplay
	FileSymbols  []FileSymbolsDisplay
	FileSections []FileSectionsDisplay
	FileMetrics  []FileMetricsDisplay
	LimitedInfo  bool
	Probability  float64 // top-level litmus ML probability [0.0, 1.0]
	Layout        string  // molecule layout: "tetrahedral", "helix", "organic" (default: "tetrahedral")
	BuildCommit   string  // git commit short hash, set at build time
	SuspiciousT   float64 // litmus suspicious threshold
	HostileT      float64 // litmus hostile threshold
	TraitColWidth string // CSS width for trait ID column, computed from longest trait
	IsArchive     bool   // true when result contains multiple analyzed files
}

// storedResult is what we persist in fido/datastore.
type storedResult struct {
	Filename       string
	RawLitmus      string // raw JSON body from the litmus /analyze response
	Traits         string
	Strings        string
	Symbols        string
	Sections       string
	Metrics        string
	Classification string // "hostile", "suspicious", or "benign" from litmus
	Formula        string // top-level formula from litmus (e.g. "Os₂Np"), fallback when per-file formula is absent
	FileType       string // file type from litmus (e.g. "macho", "pe")
}

// cleaveReport is constructed from JSONL output (multiple lines).
type cleaveReport struct {
	Summary *cleaveSummary `json:"summary,omitempty"`
	Files   []cleaveFile   `json:"files"`
}

// cleaveFile represents a file entry in cleave output.
type cleaveFile struct {
	Type               string         `json:"type,omitempty"` // "file" for JSONL parsing
	Path               string         `json:"path"`
	FileType           string         `json:"file_type"`
	SHA256             string         `json:"sha256"`
	Risk               string         `json:"risk,omitempty"`
	Classification     string         `json:"-"` // litmus ML classification, injected from embedded_files
	Formula            string         `json:"formula,omitempty"`
	Counts             *findingCounts `json:"counts,omitempty"`
	Metrics            json.RawMessage `json:"metrics,omitempty"`
	Findings           []finding      `json:"findings,omitempty"`
	Strings            []stringInfo   `json:"strings,omitempty"`
	Imports            []symbolInfo   `json:"imports,omitempty"`
	Exports            []symbolInfo   `json:"exports,omitempty"`
	Sections           []sectionInfo  `json:"sections,omitempty"`
	Size               int64          `json:"size"`
	AnalysisDurationMs int64          `json:"analysis_duration_ms,omitempty"`
	Probability        float64        `json:"-"` // litmus ML probability, injected from embedded_files
	ID                 int            `json:"id"`
	Depth              int            `json:"depth"`
	// Summary fields (only present when Type == "summary")
	FilesAnalyzed int `json:"files_analyzed,omitempty"`
	Hostile       int `json:"hostile,omitempty"`
	Suspicious    int `json:"suspicious,omitempty"`
	Notable       int `json:"notable,omitempty"`
}

type stringInfo struct {
	Value    string `json:"value"`
	Offset   string `json:"offset,omitempty"`
	Section  string `json:"section,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

type symbolInfo struct {
	Symbol  string `json:"symbol"`
	Name    string `json:"name,omitempty"`
	Source  string `json:"source,omitempty"`
	Address string `json:"address,omitempty"`
	Type    string `json:"type,omitempty"`
	Library string `json:"library,omitempty"`
}

type sectionInfo struct {
	Address any     `json:"address,omitempty"`
	Offset  *uint64 `json:"offset,omitempty"`
	Name    string  `json:"name"`
	Flags   string  `json:"flags,omitempty"`
	Size    int64   `json:"size"`
	Entropy float64 `json:"entropy,omitempty"`
}


type findingCounts struct {
	Hostile    int `json:"hostile"`
	Suspicious int `json:"suspicious"`
	Notable    int `json:"notable"`
}

type finding struct {
	ID        string     `json:"id"`
	Desc      string     `json:"desc"`
	Crit      string     `json:"crit,omitempty"`
	Kind      string     `json:"kind,omitempty"`
	TraitRefs []string   `json:"trait_refs,omitempty"`
	Evidence  []evidence `json:"evidence,omitempty"`
	Conf      float64    `json:"conf"`
}

type evidence struct {
	Value string `json:"value"`
}

type cleaveSummary struct {
	FilesAnalyzed      int   `json:"files_analyzed"`
	Hostile            int   `json:"hostile"`
	Suspicious         int   `json:"suspicious"`
	Notable            int   `json:"notable"`
	AnalysisDurationMs int64 `json:"analysis_duration_ms"`
}

//nolint:maintidx // main is inherently complex: flag parsing, config, template init, server setup
func main() {
	// Initialize structured logger with JSON output for production
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	// Parse command-line flags
	var flushCache, noCache bool
	for i, arg := range os.Args[1:] {
		switch {
		case arg == "--flush" || arg == "-flush":
			flushCache = true
		case arg == "--no-cache" || arg == "-no-cache":
			noCache = true
		case arg == "--public" || arg == "-public":
			publicMode = true
		case strings.HasPrefix(arg, "--litmus-addr="):
			litmusAddr = strings.TrimPrefix(arg, "--litmus-addr=")
		case arg == "--litmus-addr" && i+1 < len(os.Args[1:]):
			litmusAddr = os.Args[i+2]
		default:
		}
	}

	logger.Info("prism starting",
		"go_version", runtime.Version(),
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
		"pid", os.Getpid(),
		"public_mode", publicMode,
	)

	ctx := context.Background()

	// Load configuration from environment
	if err := loadConfig(); err != nil {
		logger.Error("configuration error", "error", err)
		os.Exit(1)
	}

	// Initialize fido cache
	var cacheErr error
	if noCache {
		// Use null store for local development (no caching)
		logger.Info("cache disabled via --no-cache flag, using null store")
		nullStore := null.New[string, storedResult]()
		cache, cacheErr = fido.NewTiered(nullStore)
		if cacheErr != nil {
			logger.Error("failed to initialize fido tiered cache", "error", cacheErr)
			os.Exit(1)
		}
	} else {
		// Use Cloud Run auto-detection for production
		logger.Debug("initializing fido store", "cache_id", "prism")
		store, storeErr := cloudrun.New[string, storedResult](ctx, "prism")
		if storeErr != nil {
			logger.Error("failed to initialize fido store", "error", storeErr)
			os.Exit(1)
		}
		cache, cacheErr = fido.NewTiered(store)
		if cacheErr != nil {
			logger.Error("failed to initialize fido tiered cache", "error", cacheErr)
			os.Exit(1)
		}

		// Handle --flush command (only relevant when using real cache)
		if flushCache {
			logger.Info("flushing in-memory cache")
			if closeErr := cache.Close(); closeErr != nil {
				logger.Warn("error closing cache", "error", closeErr)
			}
			cache, cacheErr = fido.NewTiered(store)
			if cacheErr != nil {
				logger.Error("failed to reinitialize cache", "error", cacheErr)
				os.Exit(1)
			}
			logger.Info("in-memory cache flushed successfully")
			fmt.Println("In-memory cache cleared. Note: Persistent cache in datastore is not affected.")
			fmt.Println("For full cache clear, delete entries from your datastore.")
			os.Exit(0)
		}
	}

	// Parse templates. isPublic is available in all templates so base.html
	// can switch branding and banners without per-handler plumbing.
	funcs := template.FuncMap{
		"isPublic": func() bool { return publicMode },
		"mul":      func(a, b float64) float64 { return a * b },
		// bandGradient returns a CSS linear-gradient matching litmus's
		// two-block confidence indicator. Each classification band has its
		// own color ramp, and the two gradient stops represent left/right
		// block colors at the current band progress. Thresholds come from
		// the litmus response.
		"bandGradient": func(p, suspT, hostT float64) template.CSS {

			type rgb struct{ r, g, b float64 }
			mix := func(a, b rgb, t float64) rgb {
				return rgb{a.r + t*(b.r-a.r), a.g + t*(b.g-a.g), a.b + t*(b.b-a.b)}
			}
			css := func(c rgb) string {
				return fmt.Sprintf("rgb(%d,%d,%d)", int(c.r), int(c.g), int(c.b))
			}

			var t float64 // band progress [0, 1]
			var left, right rgb

			switch {
			case p >= hostT:
				t = (p - hostT) / (1.0 - hostT)
				if t > 1 {
					t = 1
				}
				// Hostile: orange-red → saturated red
				left = mix(rgb{255, 135, 40}, rgb{255, 50, 65}, t)
				right = mix(rgb{255, 95, 35}, rgb{255, 35, 35}, t)
			case p >= suspT:
				t = (p - suspT) / (hostT - suspT)
				// Suspicious: greenish-yellow → orange
				left = mix(rgb{170, 190, 45}, rgb{255, 180, 40}, t)
				right = mix(rgb{235, 220, 65}, rgb{255, 125, 20}, t)
			default:
				if suspT > 0 {
					t = p / suspT
				}
				// Benign: teal-green → yellow-green
				left = mix(rgb{25, 170, 120}, rgb{120, 190, 40}, t)
				right = mix(rgb{70, 215, 135}, rgb{195, 210, 60}, t)
			}

			return template.CSS(fmt.Sprintf(
				"linear-gradient(90deg, %s, %s)", css(left), css(right),
			))
		},
	}
	var tmplErr error
	uploadTemplate, tmplErr = template.New("upload.html").Funcs(funcs).ParseFS(templatesFS, "templates/base.html", "templates/upload.html")
	if tmplErr != nil {
		logger.Error("template loading failed", "error", tmplErr)
		os.Exit(1)
	}
	resultTemplate, tmplErr = template.New("result.html").Funcs(funcs).ParseFS(templatesFS, "templates/base.html", "templates/result.html")
	if tmplErr != nil {
		logger.Error("template loading failed", "error", tmplErr)
		os.Exit(1)
	}
	errorTemplate, tmplErr = template.New("error.html").Funcs(funcs).ParseFS(templatesFS, "templates/base.html", "templates/error.html")
	if tmplErr != nil {
		logger.Error("template loading failed", "error", tmplErr)
		os.Exit(1)
	}
	formatsTemplate, tmplErr = template.New("formats.html").Funcs(funcs).ParseFS(templatesFS, "templates/base.html", "templates/formats.html")
	if tmplErr != nil {
		logger.Error("template loading failed", "error", tmplErr)
		os.Exit(1)
	}
	poweredByTemplate, tmplErr = template.New("powered-by.html").Funcs(funcs).ParseFS(templatesFS, "templates/base.html", "templates/powered-by.html")
	if tmplErr != nil {
		logger.Error("template loading failed", "error", tmplErr)
		os.Exit(1)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := newMux()

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           requestLogger(securityHeaders(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      150 * time.Second, // 120s analysis + buffer
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown
	done := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		logger.Info("shutdown signal received", "signal", sig.String())

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}

		// Close GCS client if initialized
		if gcsClient != nil {
			if err := gcsClient.Close(); err != nil {
				logger.Error("failed to close GCS client", "error", err)
			}
		}

		if cache != nil {
			if err := cache.Close(); err != nil {
				logger.Error("failed to close fido cache", "error", err)
			}
		}

		close(done)
	}()

	logger.Info("server starting",
		"port", port,
		"litmus_addr", litmusAddr,
		"gcs_bucket", gcsBucket,
	)

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", server.Addr)
	if err != nil {
		logger.Error("listen failed", "addr", server.Addr, "error", err)
		os.Exit(1)
	}
	logger.Info("listening", "addr", server.Addr)

	if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	<-done
	logger.Info("server stopped")
}

func newMux() *http.ServeMux {
	mux := http.NewServeMux()
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // impossible: embedded FS is always valid
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServer(http.FS(staticContent)))))
	mux.HandleFunc("GET /{$}", handleIndex)
	mux.HandleFunc("POST /upload", handleUpload)
	mux.HandleFunc("GET /file/{sha256}", handleFile)
	mux.HandleFunc("GET /formats", handleFormats)
	mux.HandleFunc("GET /powered-by", handlePoweredBy)
	mux.HandleFunc("GET /_/health", handleHealth)
	mux.HandleFunc("POST /_/flush", handleFlush)
	return mux
}

// loadConfig loads configuration from environment variables.
func loadConfig() error {
	gcsBucket = os.Getenv("GCS_BUCKET")

	// LITMUS_ADDR from env (flag takes precedence)
	if litmusAddr == "" {
		litmusAddr = os.Getenv("LITMUS_ADDR")
	}
	if litmusAddr == "" {
		litmusAddr = "127.0.0.1:8081"
	}

	// Initialize HTTP client for litmus server
	litmusClient = &http.Client{
		Timeout: 150 * time.Second, // 120s analysis + buffer
	}

	logger.Debug("configuration loaded",
		"LITMUS_ADDR", litmusAddr,
		"GCS_BUCKET", gcsBucket,
		"PORT", os.Getenv("PORT"),
	)

	return nil
}

// statusRecorder wraps http.ResponseWriter to capture the status code and bytes written.
type statusRecorder struct {
	http.ResponseWriter

	status int
	bytes  int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(b []byte) (int, error) {
	n, err := sr.ResponseWriter.Write(b)
	sr.bytes += n
	return n, err
}

// requestLogger logs every HTTP request with method, path, status, and duration.
// Health checks are logged at Debug to avoid noise.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sr, r)
		duration := time.Since(start)

		// Health checks and static assets at debug to reduce noise.
		level := slog.LevelInfo
		if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/_/health" {
			level = slog.LevelDebug
		}
		logger.Log(r.Context(), level, "http request",
			"method", r.Method,
			"path", r.URL.RequestURI(),
			"status", sr.status,
			"duration_ms", duration.Milliseconds(),
			"bytes_in", r.ContentLength,
			"bytes_out", sr.bytes,
			"client_ip", clientIP(r),
			"host", r.Host,
			"proto", r.Proto,
			"referer", r.Referer(),
			"user_agent", r.UserAgent(),
		)
	})
}

// securityHeaders wraps a handler with standard security response headers.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")

		// Generate a per-request nonce for inline <style> blocks.
		var nonceBuf [16]byte
		if _, err := rand.Read(nonceBuf[:]); err != nil {
			logger.Error("failed to generate CSP nonce", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		nonce := base64.RawStdEncoding.EncodeToString(nonceBuf[:])

		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self'; "+
				"style-src 'self' 'nonce-"+nonce+"'; "+
				"font-src 'self'; "+
				"img-src 'self'; "+
				"connect-src 'self'; "+
				"frame-ancestors 'none'; "+
				"object-src 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'")

		// HSTS: safe for self-hosters behind any TLS termination.
		// Browsers ignore this header on plain HTTP, so no harm when running locally.
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

		// Stash nonce in context for templates.
		ctx := context.WithValue(r.Context(), nonceCtxKey{}, nonce)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type nonceCtxKey struct{}

func getNonce(r *http.Request) string {
	if v, ok := r.Context().Value(nonceCtxKey{}).(string); ok {
		return v
	}
	return ""
}

// cacheStatic adds immutable cache headers for embedded static assets.
// These are baked into the binary at build time and only change on redeploy.
func cacheStatic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
		next.ServeHTTP(w, r)
	})
}

type errorData struct {
	Nonce      string
	Icon       string
	Title      string
	Message    template.HTML
	Detail     string
	Action     string
	ShowBeaker bool
}

func renderError(w http.ResponseWriter, r *http.Request, status int, data errorData) {
	logger.Debug("rendering error page",
		"status", status,
		"title", data.Title,
		"path", r.URL.Path,
		"client_ip", clientIP(r),
	)
	data.Nonce = getNonce(r)
	if data.Action == "" {
		data.Action = "Try again"
	}
	if status >= 500 {
		data.ShowBeaker = true
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := errorTemplate.Execute(w, data); err != nil {
		logger.Error("error template execution failed", "error", err)
	}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		CSRFToken string
		Nonce     string
	}{
		CSRFToken: csrfToken(),
		Nonce:     getNonce(r),
	}
	if err := uploadTemplate.Execute(w, data); err != nil {
		logger.Error("template execution failed",
			"template", "upload",
			"error", err,
		)
	}
}

func handleFormats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct{ Nonce string }{Nonce: getNonce(r)}
	if err := formatsTemplate.Execute(w, data); err != nil {
		logger.Error("template execution failed",
			"template", "formats",
			"error", err,
		)
	}
}

func handlePoweredBy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct{ Nonce string }{Nonce: getNonce(r)}
	if err := poweredByTemplate.Execute(w, data); err != nil {
		logger.Error("template execution failed",
			"template", "powered-by",
			"error", err,
		)
	}
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK\n")); err != nil {
		logger.Debug("health check write failed", "error", err)
	}
}

func handleFlush(w http.ResponseWriter, r *http.Request) {
	n, err := cache.Flush(r.Context())
	if err != nil {
		logger.Error("cache flush failed", "error", err)
		http.Error(w, "flush failed", http.StatusInternalServerError)
		return
	}
	logger.Info("cache flushed via HTTP", "entries_removed", n)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "flushed %d entries\n", n)
}

// validSHA256 reports whether s is exactly 64 lowercase hex characters.
func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func handleFile(w http.ResponseWriter, r *http.Request) {
	requestStart := time.Now()
	sha := r.PathValue("sha256")
	ip := clientIP(r)

	// GET /file/{sha256} also matches /file/<hash>.json because the wildcard
	// captures the full path segment including any extension.
	if bare, ok := strings.CutSuffix(sha, ".json"); ok {
		serveFileJSON(w, r, bare, ip)
		return
	}

	if !validSHA256(sha) {
		logger.Warn("invalid SHA256 in file request",
			"input", sha,
			"client_ip", ip,
			"user_agent", r.UserAgent(),
		)
		renderError(w, r, http.StatusBadRequest, errorData{
			Icon:    "⚠",
			Title:   "Invalid hash",
			Message: "That doesn't look like a valid SHA256 hash.",
		})
		return
	}

	reqLogger := logger.With("sha256", sha, "client_ip", ip)
	reqLogger.Info("file request received")

	cacheHit, res, err := lookupResult(r.Context(), sha, reqLogger)
	if err != nil {
		reqLogger.Warn("failed to retrieve or regenerate result", "error", err)
		if strings.Contains(err.Error(), "not found") {
			renderError(w, r, http.StatusNotFound, errorData{
				Icon:    "🔍",
				Title:   "Result not found",
				Message: "This analysis result doesn't exist or has expired. Upload the file again to re-analyze it.",
				Action:  "Upload a file",
			})
		} else {
			renderError(w, r, http.StatusInternalServerError, errorData{
				Icon:    "⚠",
				Title:   "Something went wrong",
				Message: "We couldn't retrieve this result. Please try again.",
			})
		}
		return
	}

	reqLogger.Info("rendering result",
		"filename", res.Filename,
		"cache_hit", cacheHit,
		"duration_ms", time.Since(requestStart).Milliseconds(),
	)
	data := prepareResultData(res.Filename, sha, &res)
	data.Nonce = getNonce(r)
	data.BuildCommit = buildCommit
	switch r.URL.Query().Get("layout") {
	case "helix4", "helix5", "organic2", "organic4", "organic5", "flat":
		data.Layout = r.URL.Query().Get("layout")
	default:
		data.Layout = "organic2"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Build", buildCommit)
	w.Header().Set("X-Layout", data.Layout)
	if err := resultTemplate.Execute(w, data); err != nil {
		reqLogger.Error("template execution failed",
			"template", "result",
			"error", err,
		)
	}
}

// lookupResult retrieves a stored result from cache, falling back to GCS if configured.
// Returns (cacheHit, result, error).
func lookupResult(ctx context.Context, sha string, reqLogger *slog.Logger) (bool, storedResult, error) {
	cacheHit := true
	res, err := cache.Fetch(ctx, sha, func(lctx context.Context) (storedResult, error) {
		cacheHit = false
		if gcsBucket == "" || gcsClient == nil {
			reqLogger.Debug("cache miss, GCS not configured for fallback")
			return storedResult{}, errors.New("result not in cache and GCS not configured")
		}

		reqLogger.Info("cache miss, attempting fallback to GCS")

		it := gcsClient.Bucket(gcsBucket).Objects(lctx, &storage.Query{Prefix: sha + "/"})
		attrs, err := it.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				reqLogger.Debug("file not found in GCS", "prefix", sha+"/")
				return storedResult{}, errors.New("file not found in GCS")
			}
			reqLogger.Error("GCS list failed", "error", err)
			return storedResult{}, fmt.Errorf("GCS list failed: %w", err)
		}

		filename := filepath.Base(attrs.Name)
		reqLogger.Info("found file in GCS, re-analyzing", "filename", filename, "gcs_path", attrs.Name)

		tempFile, err := os.CreateTemp("", "litmus-fallback-*")
		if err != nil {
			return storedResult{}, fmt.Errorf("failed to create temp file: %w", err)
		}
		tempPath := tempFile.Name()
		defer func() {
			if err := os.Remove(tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				reqLogger.Debug("failed to remove temp file", "path", tempPath, "error", err)
			}
		}()
		defer func() {
			if err := tempFile.Close(); err != nil {
				reqLogger.Debug("failed to close temp file", "error", err)
			}
		}()

		reqLogger.Debug("downloading from GCS", "temp_path", tempPath)
		rc, err := gcsClient.Bucket(gcsBucket).Object(attrs.Name).NewReader(lctx)
		if err != nil {
			return storedResult{}, fmt.Errorf("GCS reader failed: %w", err)
		}
		defer func() {
			if err := rc.Close(); err != nil {
				reqLogger.Debug("failed to close GCS reader", "error", err)
			}
		}()

		dlStart := time.Now()
		if _, err := io.Copy(tempFile, rc); err != nil {
			return storedResult{}, fmt.Errorf("failed to download from GCS: %w", err)
		}
		reqLogger.Debug("GCS download complete", "duration_ms", time.Since(dlStart).Milliseconds())
		if err := tempFile.Close(); err != nil {
			reqLogger.Debug("failed to close temp file after download", "error", err)
		}

		reqLogger.Debug("starting fallback analysis")
		lr, err := runLitmus(lctx, tempPath, filename, reqLogger)
		if err != nil {
			return storedResult{}, fmt.Errorf("litmus failed: %w", err)
		}

		return storedResult{
			Filename:       filename,
			RawLitmus:      lr.RawLitmus,
			Classification: lr.Classification,
			Formula:        lr.Formula,
			FileType:       lr.FileType,
		}, nil
	})
	return cacheHit, res, err
}

func serveFileJSON(w http.ResponseWriter, r *http.Request, sha, ip string) {
	if !validSHA256(sha) {
		http.Error(w, "invalid sha256", http.StatusBadRequest)
		return
	}

	reqLogger := logger.With("sha256", sha, "client_ip", ip)

	_, res, err := lookupResult(r.Context(), sha, reqLogger)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, "not found", http.StatusNotFound)
		} else {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	if res.RawLitmus == "" {
		http.Error(w, "raw report not available for this result", http.StatusNotFound)
		return
	}

	// Pass the raw litmus response through with minimal intervention: only
	// normalise the server-side temp path to the original uploaded filename.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(res.RawLitmus), &raw); err != nil {
		http.Error(w, "failed to parse stored report", http.StatusInternalServerError)
		return
	}
	filenameJSON, err := json.Marshal(res.Filename)
	if err != nil {
		http.Error(w, "failed to encode filename", http.StatusInternalServerError)
		return
	}
	raw["path"] = filenameJSON

	b, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		http.Error(w, "failed to encode result", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if _, err := w.Write(b); err != nil {
		reqLogger.Debug("json write failed", "error", err)
	}
}

//nolint:revive,maintidx // renderError calls are more verbose than http.Error but worth it for UX
func handleUpload(w http.ResponseWriter, r *http.Request) {
	requestStart := time.Now()
	h := sha256.Sum256(fmt.Appendf(nil, "%d-%p", time.Now().UnixNano(), r))
	requestID := hex.EncodeToString(h[:])

	ip := clientIP(r)
	reqLogger := logger.With(
		"request_id", requestID,
		"remote_addr", r.RemoteAddr,
		"client_ip", ip,
		"user_agent", r.UserAgent(),
	)

	// Rate limit per IP.
	if !rateLimiter.allow(ip) {
		reqLogger.Warn("upload rate limited")
		renderError(w, r, http.StatusTooManyRequests, errorData{
			Icon:    "⏳",
			Title:   "Rate limit reached",
			Message: "Too many uploads. Please wait a minute before trying again.",
		})
		return
	}

	reqLogger.Info("upload request received")

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	// Cap total request body to 100MB to prevent disk exhaustion.
	// ParseMultipartForm's maxMemory only limits RAM; excess spills to temp files
	// with no size bound unless we cap the body reader itself.
	const maxUploadSize = 100 * 1024 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)

	reqLogger.Debug("parsing multipart form", "max_memory", "100MB")
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		if err.Error() == "http: request body too large" {
			reqLogger.Warn("upload rejected: file too large", "error", err, "max_bytes", maxUploadSize)
			renderError(w, r, http.StatusRequestEntityTooLarge, errorData{
				Icon:  "⚖",
				Title: "File too large",
				Message: "The web interface accepts files up to 100 MB. For larger files, use " +
					`<a href="https://codeberg.org/atomdrift/litmus">litmus</a>, our open-source command-line tool — no size limits.`,
			})
		} else {
			reqLogger.Error("failed to parse multipart form", "error", err)
			renderError(w, r, http.StatusBadRequest, errorData{
				Icon:    "⚠",
				Title:   "Upload failed",
				Message: "Something went wrong reading your file. Please try again.",
			})
		}
		return
	}

	// Validate CSRF token (30-minute window). Must come after ParseMultipartForm
	// so that form values from multipart bodies are accessible.
	if !csrfValid(r.FormValue("csrf_token"), 30*time.Minute) {
		reqLogger.Warn("invalid or missing CSRF token")
		renderError(w, r, http.StatusForbidden, errorData{
			Icon:    "🔒",
			Title:   "Session expired",
			Message: "Your form session has expired. Please reload the page and try again.",
		})
		return
	}

	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		reqLogger.Error("failed to read uploaded file", "error", err)
		renderError(w, r, http.StatusBadRequest, errorData{
			Icon:    "⚠",
			Title:   "No file received",
			Message: "We didn't receive a file. Please select a file and try again.",
		})
		return
	}
	defer func() {
		if err := file.Close(); err != nil {
			reqLogger.Debug("failed to close uploaded file", "error", err)
		}
	}()

	filename := filepath.Base(fileHeader.Filename)
	ext := filepath.Ext(filename)
	reqLogger = reqLogger.With("filename", filename, "size", fileHeader.Size, "ext", ext)
	reqLogger.Info("file received")

	tempPattern := "litmus-*"
	if ext != "" {
		tempPattern = "litmus-*" + ext
	}
	tempFile, err := os.CreateTemp("", tempPattern)
	if err != nil {
		reqLogger.Error("failed to create temp file", "error", err)
		renderError(w, r, http.StatusInternalServerError, errorData{
			Icon:    "⚠",
			Title:   "Server error",
			Message: "Something went wrong on our end. Please try again shortly.",
		})
		return
	}
	tempPath := tempFile.Name()
	reqLogger.Debug("temp file created", "path", tempPath)

	// cleanupWg tracks only the background GCS upload goroutine.
	// Analysis runs synchronously inside cache.Fetch, so the temp file is
	// guaranteed to exist for the duration of that call.  The defer below
	// waits for GCS (if started) before removing the file.
	var cleanupWg sync.WaitGroup
	defer func() {
		cleanupWg.Wait()
		if err := os.Remove(tempPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			reqLogger.Debug("failed to remove temp file", "path", tempPath, "error", err)
		} else {
			reqLogger.Debug("temp file removed", "path", tempPath)
		}
	}()

	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(tempFile, hash), file)
	if err != nil {
		if cerr := tempFile.Close(); cerr != nil {
			reqLogger.Debug("failed to close temp file", "error", cerr)
		}
		reqLogger.Error("failed to write temp file", "error", err, "bytes_written", written)
		renderError(w, r, http.StatusInternalServerError, errorData{
			Icon:    "⚠",
			Title:   "Server error",
			Message: "Something went wrong on our end. Please try again shortly.",
		})
		return
	}
	if err := tempFile.Close(); err != nil {
		reqLogger.Debug("failed to close temp file after write", "error", err)
	}

	sha256Hex := hex.EncodeToString(hash.Sum(nil))
	reqLogger = reqLogger.With("sha256", sha256Hex)
	reqLogger.Info("file written to temp", "bytes", written)

	// Upload to GCS if configured (background, simultaneous to analysis).
	// Add(1) here so the defer above waits for the upload before deleting the file.
	if gcsBucket != "" && gcsClient != nil {
		cleanupWg.Add(1)
		go func() { //nolint:contextcheck,modernize // background context intentional: upload must outlive request
			defer cleanupWg.Done()
			reqLogger.Debug("starting background GCS upload")
			// Use a background context that isn't tied to the request lifecycle
			// so the upload can continue after the redirect.
			bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			f, err := os.Open(tempPath)
			if err != nil {
				reqLogger.Error("failed to open temp file for background GCS upload", "error", err)
				return
			}
			defer func() {
				if err := f.Close(); err != nil {
					reqLogger.Debug("failed to close temp file in GCS upload", "error", err)
				}
			}()

			if err := uploadToGCS(bgCtx, gcsBucket, sha256Hex, filename, f, reqLogger); err != nil {
				reqLogger.Error("background GCS upload failed", "error", err)
			}
		}()
	} else {
		reqLogger.Debug("skipping GCS upload (not configured)")
	}

	// Run litmus analysis via fido.Fetch to deduplicate concurrent requests
	// With --no-cache, uses null store which doesn't persist but still deduplicates
	reqLogger.Info("starting/joining analysis fetch", "sha256", sha256Hex, "filename", filename)
	fetchStart := time.Now()
	res, err := cache.Fetch(ctx, sha256Hex, func(_ context.Context) (storedResult, error) {
		reqLogger.Info("cache miss, executing new analysis", "sha256", sha256Hex)
		lctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancel()

		analysisStart := time.Now()
		//nolint:contextcheck // analysis uses its own timeout independent of request context
		lr, runErr := runLitmus(lctx, tempPath, filename, reqLogger)
		analysisDuration := time.Since(analysisStart)

		if runErr != nil {
			reqLogger.Error("litmus analysis failed",
				"error", runErr,
				"duration_ms", analysisDuration.Milliseconds(),
			)
			return storedResult{}, fmt.Errorf("litmus run error: %w", runErr)
		}

		reqLogger.Info("litmus analysis completed",
			"duration_ms", analysisDuration.Milliseconds(),
			"classification", lr.Classification,
		)

		return storedResult{
			Filename:       filename,
			RawLitmus:      lr.RawLitmus,
			Classification: lr.Classification,
			Formula:        lr.Formula,
			FileType:       lr.FileType,
		}, nil
	})

	fetchDuration := time.Since(fetchStart)
	if err != nil {
		reqLogger.Error("analysis fetch failed", "error", err, "fetch_duration_ms", fetchDuration.Milliseconds())
		renderError(w, r, http.StatusInternalServerError, errorData{
			Icon:  "⚠",
			Title: "Analysis failed",
			Message: "Something went wrong analyzing this file. Please try again, or use " +
				`<a href="https://codeberg.org/atomdrift/litmus">litmus</a> for local analysis.`,
		})
		return
	}

	reqLogger.Info("request completed, redirecting to result",
		"total_duration_ms", time.Since(requestStart).Milliseconds(),
		"fetch_duration_ms", fetchDuration.Milliseconds(),
		"cached_filename", res.Filename,
		"raw_bytes", len(res.RawLitmus),
	)

	http.Redirect(w, r, "/file/"+sha256Hex, http.StatusSeeOther)
}

// prepareResultData converts raw cleave output to template data.
//
//nolint:gocognit,maintidx // inherently complex data assembly
func prepareResultData(filename, sha256Hex string, res *storedResult) resultData {
	data := resultData{
		Filename:     html.EscapeString(filename),
		SHA256:       sha256Hex,
		SHA256Short:  sha256Hex[:12] + "...",
		FileType:     "UNKNOWN",
		RiskLevel:    "",
		RiskLabel:    "",
		Size:         "0 B",
		FindingCount: "0",
		Duration:     "0ms",
		MoleculeJSON: template.JS("{}"),
	}

	if sha256Hex != "" && len(sha256Hex) >= 12 {
		data.SHA256Short = sha256Hex[:12] + "..."
	}

	// Parse raw litmus response to extract cleave analysis data.
	var litmusResp litmusAPIResponse
	if err := json.Unmarshal([]byte(res.RawLitmus), &litmusResp); err != nil {
		logger.Debug("failed to parse raw litmus response", "sha256", sha256Hex, "error", err)
		data.Formula = template.HTML("?")
		return data
	}
	// Use thresholds from litmus response, with sensible defaults.
	data.SuspiciousT = litmusResp.Thresholds.Suspicious
	data.HostileT = litmusResp.Thresholds.Hostile
	if data.SuspiciousT == 0 {
		data.SuspiciousT = 0.65
	}
	if data.HostileT == 0 {
		data.HostileT = 0.887
	}

	var cleaveResp cleaveAPIResponse
	if len(litmusResp.Cleave) > 0 {
		if err := json.Unmarshal(litmusResp.Cleave, &cleaveResp); err != nil {
			logger.Debug("failed to parse cleave data", "sha256", sha256Hex, "error", err)
		}
	}
	report := parseAPIResponse(&cleaveResp)

	// Normalize paths: replace the temp file path with the real uploaded filename
	// for any top-level file (depth=0, no archive separator). Cleave reports the
	// path it analyzed on the server, which may be a tmp path.
	for i := range report.Files {
		if report.Files[i].Depth == 0 && !strings.Contains(report.Files[i].Path, "!!") {
			report.Files[i].Path = filename
		}
	}

	// Ascribe litmus ML evaluations to individual files. The top-level file gets
	// the archive-level classification; embedded files are matched by path suffix.
	if len(litmusResp.EmbeddedFiles) > 0 {
		evalByPath := make(map[string]*litmusEmbeddedFile, len(litmusResp.EmbeddedFiles))
		for i := range litmusResp.EmbeddedFiles {
			evalByPath[litmusResp.EmbeddedFiles[i].Path] = &litmusResp.EmbeddedFiles[i]
		}
		for i := range report.Files {
			if ef, ok := evalByPath[report.Files[i].Path]; ok {
				report.Files[i].Classification = strings.ToLower(ef.Classification)
				report.Files[i].Probability = ef.Probability
			}
		}
	}
	// Top-level file inherits the archive-level litmus classification.
	for i := range report.Files {
		if report.Files[i].Depth == 0 {
			report.Files[i].Classification = strings.ToLower(litmusResp.Classification)
			report.Files[i].Probability = float64(litmusResp.Probability)
			break
		}
	}

	if len(report.Files) == 0 && report.Summary == nil {
		logger.Debug("empty cleave report", "sha256", sha256Hex)
		data.Formula = template.HTML("?")
		return data
	}

	// Extract target info from top-level file (depth=0) or first file
	for i := range report.Files {
		file := &report.Files[i]
		if file.Depth == 0 {
			data.FileType = strings.ToUpper(file.FileType)
			data.Size = formatBytes(file.Size)
			break
		}
	}
	// Fallback to first file if no depth=0 found
	if data.FileType == "" && len(report.Files) > 0 {
		data.FileType = strings.ToUpper(report.Files[0].FileType)
		data.Size = formatBytes(report.Files[0].Size)
	}

	// Extract duration from summary
	if report.Summary != nil {
		data.Duration = fmt.Sprintf("%dms", report.Summary.AnalysisDurationMs)
	}

	// Extract findings for formula generation (skip structural/internal findings)
	var findings []FindingForFormula
	var totalFindings int

	for i := range report.Files {
		file := &report.Files[i]
		for _, f := range file.Findings {
			// Skip structural/internal symbols - they clutter the formula
			if f.Kind == "structural" || strings.HasPrefix(f.ID, "metadata/internal/") {
				continue
			}
			totalFindings++
			findings = append(findings, FindingForFormula{
				ID:        f.ID,
				Severity:  critToSeverity(f.Crit),
				TraitRefs: f.TraitRefs,
			})
		}
	}

	data.FindingCount = strconv.Itoa(totalFindings)

	// Build traits lookup for molecule info panel (trait ID → description + evidence).
	traitDetails := make(map[string]*TraitDetail)
	for i := range report.Files {
		for _, f := range report.Files[i].Findings {
			if f.Kind == "structural" || strings.HasPrefix(f.ID, "metadata/internal/") {
				continue
			}
			if _, exists := traitDetails[f.ID]; exists {
				continue // deduplicate
			}
			td := &TraitDetail{Desc: f.Desc, Crit: f.Crit}
			for _, e := range f.Evidence {
				if e.Value != "" {
					td.Evidence = append(td.Evidence, e.Value)
				}
			}
			traitDetails[f.ID] = td
		}
	}

	// Set verdict and risk level from litmus classification.
	switch res.Classification {
	case "hostile":
		data.Verdict = "HOSTILE"
		data.RiskLevel = "hostile"
		data.RiskLabel = "Hostile"
	case "suspicious":
		data.Verdict = "SUSPICIOUS"
		data.RiskLevel = "suspicious"
		data.RiskLabel = "Suspicious"
	case "benign":
		data.Verdict = "BENIGN"
		// RiskLevel intentionally empty for benign
	default:
		data.Verdict = "UNKNOWN"
		data.RiskLevel = "unknown"
		data.RiskLabel = "Unknown"
	}

	// Set top-level probability from the depth-0 file.
	for i := range report.Files {
		if report.Files[i].Depth == 0 {
			data.Probability = report.Files[i].Probability
			break
		}
	}

	// Flag when we have limited analysis info (unknown file type AND no findings)
	if (data.FileType == "UNKNOWN" || data.FileType == "") && totalFindings == 0 {
		data.LimitedInfo = true
		logger.Info("limited analysis info for file",
			"filename", filename,
			"sha256", sha256Hex,
			"file_type", data.FileType,
			"finding_count", totalFindings,
		)
	}

	// Build structured data for table display
	data.FileFindings = buildStructuredFindings(report.Files)
	data.FileStrings = buildStructuredStrings(report.Files)
	data.FileSymbols = buildStructuredSymbols(report.Files)
	data.FileSections = buildStructuredSections(report.Files)
	data.FileMetrics = buildStructuredMetrics(report.Files)

	// Compute trait column width from longest trait ID across all files.
	maxTraitLen := 0
	for _, ff := range data.FileFindings {
		for _, cat := range ff.Categories {
			for _, f := range cat.Findings {
				if len(f.ID) > maxTraitLen {
					maxTraitLen = len(f.ID)
				}
			}
		}
	}
	// ~0.65em per character in monospace at 12px, with 2em padding
	data.TraitColWidth = fmt.Sprintf("%.1fem", float64(maxTraitLen)*0.65+2)
	data.IsArchive = len(data.FileFindings) > 1

	// Use formula from cleave with file type prefix.
	// For archives, find the top-level entry (Depth == 0).
	var formula string
	for i := range report.Files {
		file := &report.Files[i]
		if file.Depth == 0 {
			formula = file.Formula
			break
		}
	}
	// Fallback to first file if no depth=0 found.
	if formula == "" && len(report.Files) > 0 {
		formula = report.Files[0].Formula
	}
	// Fallback to the top-level formula returned directly by litmus, which is
	// computed before finalize() and may not be present in per-file JSON.
	if formula == "" && res.Formula != "" {
		formula = res.Formula
	}
	if formula == "" {
		formula = "∅"
	}
	data.Formula = template.HTML(html.EscapeString(formula)) //nolint:gosec // html.EscapeString sanitizes the input before conversion

	// Generate molecule/galaxy data for 3D visualization
	// For archives with multiple files, build a galaxy
	if len(report.Files) > 1 {
		var fileFindings []FileFindings
		for i := range report.Files {
			file := &report.Files[i]
			var ff []FindingForFormula
			for _, f := range file.Findings {
				if f.Kind == "structural" || strings.HasPrefix(f.ID, "metadata/internal/") {
					continue
				}
				ff = append(ff, FindingForFormula{
					ID:        f.ID,
					Severity:  critToSeverity(f.Crit),
					TraitRefs: f.TraitRefs,
				})
			}

			// Extract string values for dropper detection
			var strs []string
			for _, s := range file.Strings {
				strs = append(strs, s.Value)
			}

			// Also scan evidence for dropper detection (may contain file references)
			for _, f := range file.Findings {
				for _, e := range f.Evidence {
					strs = append(strs, e.Value)
				}
			}

			if len(ff) > 0 {
				fileFindings = append(fileFindings, FileFindings{
					Path:           file.Path,
					Risk:           file.Risk,
					Classification: file.Classification,
					Probability:    file.Probability,
					Formula:        file.Formula,
					Findings:       ff,
					Strings:        strs,
				})
			}
		}

		galaxy := BuildGalaxy(fileFindings)
		if galaxy.IsGalaxy {
			galaxy.Traits = traitDetails
			galaxyJSON, err := json.Marshal(galaxy)
			if err != nil {
				logger.Debug("failed to marshal galaxy data", "error", err)
				data.MoleculeJSON = template.JS("{}")
			} else {
				data.MoleculeJSON = template.JS(galaxyJSON) //nolint:gosec // JSON-marshalled data is safe for JS embedding
			}
		} else {
			// Galaxy rejected (e.g. archive with single inner file) — fall through to single molecule
			mol := BuildMalecule(findings, formula)
			mol.Filename = filename
			mol.FileType = data.FileType
			mol.Traits = traitDetails
			molJSON, err := json.Marshal(mol)
			if err != nil {
				logger.Debug("failed to marshal molecule data", "error", err)
				data.MoleculeJSON = template.JS("{}")
			} else {
				data.MoleculeJSON = template.JS(molJSON) //nolint:gosec // JSON-marshalled data is safe for JS embedding
			}
		}
	} else {
		// Single file - build single molecule
		mol := BuildMalecule(findings, formula)
		mol.Filename = filename
		mol.FileType = data.FileType
		molJSON, err := json.Marshal(mol)
		if err != nil {
			logger.Debug("failed to marshal molecule data", "error", err)
			data.MoleculeJSON = template.JS("{}")
		} else {
			data.MoleculeJSON = template.JS(molJSON) //nolint:gosec // JSON-marshalled data is safe for JS embedding
		}
	}

	return data
}

// buildStructuredFindings converts cleave findings into structured display data grouped by category.
// Findings are aggregated by directory path, keeping only the highest criticality/confidence per directory.
//
//nolint:gocognit // complex findings aggregation logic
func buildStructuredFindings(files []cleaveFile) []FileFindingsDisplay {
	var result []FileFindingsDisplay

	// Category display names
	categoryNames := map[string]string{
		"objectives":      "Objectives",
		"micro-behaviors": "Micro-behaviors",
		"metadata":        "Metadata",
		"well-known":      "Well-known",
		"third_party":     "Third-party",
	}

	// Criticality ordering for comparison
	critOrder := map[string]int{
		"hostile":    3,
		"suspicious": 2,
		"notable":    1,
		"baseline":   0,
		"":           -1,
	}

	for i := range files {
		file := &files[i]
		if len(file.Findings) == 0 {
			continue
		}

		// Aggregate findings by directory path (everything except last component)
		// Key: "topLevel/dirPath", Value: best finding for that directory
		type aggregatedFinding struct {
			evidence map[string]bool
			dirPath  string
			topLevel string
			crit     string
			desc     string
			conf     float64
		}
		aggregated := make(map[string]*aggregatedFinding)

		for _, f := range file.Findings {
			// Skip structural/internal findings
			if f.Kind == "structural" || strings.HasPrefix(f.ID, "metadata/internal/") {
				continue
			}

			// Only show notable or higher (skip baseline/component/empty)
			if f.Crit == "" || f.Crit == "component" || f.Crit == "baseline" {
				continue
			}

			// Split into parts: topLevel / rest
			parts := strings.Split(f.ID, "/")
			if len(parts) < 2 {
				continue
			}

			topLevel := parts[0]

			// Directory path is everything except the last component, excluding top-level
			// e.g., "objectives/execution/shell/bash" -> dirPath = "execution/shell"
			var dirPath string
			if len(parts) > 2 {
				dirPath = strings.Join(parts[1:len(parts)-1], "/")
			} else {
				// Only 2 parts like "objectives/execution" -> show as "execution"
				dirPath = parts[1]
			}

			key := topLevel + "/" + dirPath

			existing, ok := aggregated[key]
			if !ok {
				// New directory - create entry
				evidenceSet := make(map[string]bool)
				for _, e := range f.Evidence {
					evidenceSet[e.Value] = true
				}
				aggregated[key] = &aggregatedFinding{
					dirPath:  dirPath,
					topLevel: topLevel,
					crit:     f.Crit,
					conf:     f.Conf,
					desc:     f.Desc,
					evidence: evidenceSet,
				}
			} else {
				// Existing directory - keep higher criticality, then higher confidence
				existingCrit := critOrder[existing.crit]
				newCrit := critOrder[f.Crit]

				shouldReplace := newCrit > existingCrit ||
					(newCrit == existingCrit && f.Conf > existing.conf)

				if shouldReplace {
					existing.crit = f.Crit
					existing.conf = f.Conf
					existing.desc = f.Desc
				}

				// Merge evidence (always)
				for _, e := range f.Evidence {
					existing.evidence[e.Value] = true
				}
			}
		}

		// Group by top-level category
		categoryMap := make(map[string][]FindingDisplay)

		for _, agg := range aggregated {
			// Convert evidence map to sorted slice
			var evidence []string
			for e := range agg.evidence {
				evidence = append(evidence, e)
			}
			sort.Strings(evidence)
			if len(evidence) > 4 {
				evidence = evidence[:4]
			}

			fd := FindingDisplay{
				ID:       agg.dirPath, // Show directory path without top-level
				Crit:     agg.crit,
				Desc:     agg.desc,
				Evidence: evidence,
			}

			categoryMap[agg.topLevel] = append(categoryMap[agg.topLevel], fd)
		}

		// Sort findings within each category by criticality (desc), then alphabetically
		for cat := range categoryMap {
			findings := categoryMap[cat]
			sort.Slice(findings, func(i, j int) bool {
				ci, cj := critOrder[findings[i].Crit], critOrder[findings[j].Crit]
				if ci != cj {
					return ci > cj // Higher criticality first
				}
				return findings[i].ID < findings[j].ID // Alphabetical
			})
			categoryMap[cat] = findings
		}

		// Build categories sorted by highest criticality finding, then by default order.
		defaultOrder := map[string]int{"well-known": 0, "objectives": 1, "micro-behaviors": 2, "metadata": 3, "third_party": 4}
		critRank := map[string]int{"hostile": 3, "suspicious": 2, "notable": 1}

		var categories []CategoryGroup
		for cat, findings := range categoryMap {
			if len(findings) == 0 {
				continue
			}
			name := categoryNames[cat]
			if name == "" {
				name = cat
			}
			categories = append(categories, CategoryGroup{
				Name:     name,
				Findings: findings,
			})
		}

		// Sort: highest criticality first, then by default category order.
		sort.Slice(categories, func(i, j int) bool {
			maxCrit := func(cg CategoryGroup) int {
				best := 0
				for _, f := range cg.Findings {
					if r := critRank[f.Crit]; r > best {
						best = r
					}
				}
				return best
			}
			ci, cj := maxCrit(categories[i]), maxCrit(categories[j])
			if ci != cj {
				return ci > cj
			}
			// Same criticality: use default order
			catKey := func(name string) string {
				for k, v := range categoryNames {
					if v == name {
						return k
					}
				}
				return name
			}
			oi, oj := defaultOrder[catKey(categories[i].Name)], defaultOrder[catKey(categories[j].Name)]
			return oi < oj
		})

		if len(categories) > 0 {
			// Extract basename
			path := file.Path
			basename := path
			if strings.Contains(path, "!!") {
				parts := strings.Split(path, "!!")
				basename = parts[len(parts)-1]
			}
			if idx := strings.LastIndex(basename, "/"); idx >= 0 {
				basename = basename[idx+1:]
			}

			result = append(result, FileFindingsDisplay{
				Path:           file.Path,
				Basename:       basename,
				Risk:           file.Risk,
				Classification: file.Classification,
				Probability:    file.Probability,
				SHA256:         file.SHA256,
				Formula:        file.Formula,
				FileType:       strings.ToUpper(file.FileType),
				Categories:     categories,
			})
		}
	}

	return result
}

// buildStructuredStrings extracts strings data for table display.

func buildStructuredStrings(files []cleaveFile) []FileStringsDisplay {
	var result []FileStringsDisplay

	for i := range files {
		file := &files[i]
		if len(file.Strings) == 0 {
			continue
		}

		basename := extractBasename(file.Path)

		// Build section ranges for offset-to-section lookup using file offsets.
		type sectionRange struct {
			name       string
			start, end uint64
		}
		var sectionRanges []sectionRange
		for _, sec := range file.Sections {
			if sec.Offset != nil && sec.Size > 0 {
				sectionRanges = append(sectionRanges, sectionRange{
					name:  sec.Name,
					start: *sec.Offset,
					end:   *sec.Offset + uint64(sec.Size),
				})
			}
		}

		var strs []StringDisplay
		for _, s := range file.Strings {
			section := s.Section
			// Compute section from offset if not already set.
			if section == "" && s.Offset != "" && len(sectionRanges) > 0 {
				off, err := strconv.ParseUint(strings.TrimPrefix(s.Offset, "0x"), 16, 64)
				if err == nil {
					for _, sr := range sectionRanges {
						if off >= sr.start && off < sr.end {
							section = sr.name
							break
						}
					}
				}
			}
			strs = append(strs, StringDisplay{
				Value:   s.Value,
				Section: section,
				Offset:  s.Offset,
			})
		}

		// Sort by offset (hex string comparison works for zero-padded offsets;
		// for non-padded, parse as integers).
		sort.Slice(strs, func(i, j int) bool {
			oi, _ := strconv.ParseUint(strings.TrimPrefix(strs[i].Offset, "0x"), 16, 64)
			oj, _ := strconv.ParseUint(strings.TrimPrefix(strs[j].Offset, "0x"), 16, 64)
			return oi < oj
		})

		// Group strings by section when section data is available.
		hasSections := false
		sectionOrder := []string{}
		sectionMap := map[string][]StringDisplay{}
		for _, s := range strs {
			sec := s.Section
			if sec != "" {
				hasSections = true
			} else {
				sec = "(other)"
			}
			if _, ok := sectionMap[sec]; !ok {
				sectionOrder = append(sectionOrder, sec)
			}
			sectionMap[sec] = append(sectionMap[sec], s)
		}
		var sections []StringSectionGroup
		if hasSections {
			for _, sec := range sectionOrder {
				sections = append(sections, StringSectionGroup{
					Section: sec,
					Strings: sectionMap[sec],
				})
			}
		}

		result = append(result, FileStringsDisplay{
			Basename:       basename,
			Risk:           file.Risk,
			Classification: file.Classification,
			Probability:    file.Probability,
			SHA256:         file.SHA256,
			Formula:        file.Formula,
			FileType:       strings.ToUpper(file.FileType),
			Strings:        strs,
			Sections:       sections,
			HasSections:    hasSections,
		})
	}

	return result
}

// buildStructuredSymbols extracts symbols data for table display.
func buildStructuredSymbols(files []cleaveFile) []FileSymbolsDisplay {
	var result []FileSymbolsDisplay

	for i := range files {
		file := &files[i]
		if len(file.Imports) == 0 && len(file.Exports) == 0 {
			continue
		}

		basename := extractBasename(file.Path)
		var imports, exports []SymbolDisplay

		for _, s := range file.Imports {
			name := s.Symbol
			if name == "" {
				name = s.Name
			}
			imports = append(imports, SymbolDisplay{
				Name:    name,
				Library: s.Library,
			})
		}

		for _, s := range file.Exports {
			name := s.Symbol
			if name == "" {
				name = s.Name
			}
			exports = append(exports, SymbolDisplay{
				Name:    name,
				Library: s.Library,
			})
		}

		result = append(result, FileSymbolsDisplay{
			Basename:       basename,
			Risk:           file.Risk,
			Classification: file.Classification,
			Probability:    file.Probability,
			SHA256:         file.SHA256,
			Formula:        file.Formula,
			FileType:       strings.ToUpper(file.FileType),
			Imports:        imports,
			Exports:        exports,
		})
	}

	return result
}

// buildStructuredSections extracts sections data for table display.
func buildStructuredSections(files []cleaveFile) []FileSectionsDisplay {
	var result []FileSectionsDisplay

	for i := range files {
		file := &files[i]
		if len(file.Sections) == 0 {
			continue
		}

		basename := extractBasename(file.Path)
		var sections []SectionDisplay

		for _, s := range file.Sections {
			var offsetStr string
			if s.Offset != nil {
				offsetStr = fmt.Sprintf("0x%x", *s.Offset)
			}
			sections = append(sections, SectionDisplay{
				Name:    s.Name,
				Offset:  offsetStr,
				Size:    s.Size,
				Entropy: s.Entropy,
				Flags:   s.Flags,
			})
		}

		result = append(result, FileSectionsDisplay{
			Basename:       basename,
			Risk:           file.Risk,
			Classification: file.Classification,
			Probability:    file.Probability,
			SHA256:         file.SHA256,
			Formula:        file.Formula,
			FileType:       strings.ToUpper(file.FileType),
			Sections:       sections,
		})
	}

	return result
}

// buildStructuredMetrics dynamically walks raw metrics JSON to produce display groups.
// This avoids hardcoding field names — any metric cleave emits will appear automatically.
func buildStructuredMetrics(files []cleaveFile) []FileMetricsDisplay {
	var result []FileMetricsDisplay

	for i := range files {
		file := &files[i]
		if len(file.Metrics) == 0 {
			continue
		}

		// Parse as map of group → map of key → value (any JSON type).
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(file.Metrics, &raw); err != nil {
			continue
		}

		var groups []metricGroup
		// Sort group names for deterministic order.
		groupNames := make([]string, 0, len(raw))
		for name := range raw {
			groupNames = append(groupNames, name)
		}
		sort.Strings(groupNames)

		for _, groupName := range groupNames {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw[groupName], &fields); err != nil {
				// Scalar at top level — skip (shouldn't happen with cleave metrics).
				continue
			}

			fieldNames := make([]string, 0, len(fields))
			for name := range fields {
				fieldNames = append(fieldNames, name)
			}
			sort.Strings(fieldNames)

			var mf []metricField
			for _, fieldName := range fieldNames {
				val := string(fields[fieldName])
				// Try to format nicely: strip quotes from strings, format numbers.
				var s string
				if err := json.Unmarshal(fields[fieldName], &s); err == nil {
					val = s
				} else {
					var f float64
					if err := json.Unmarshal(fields[fieldName], &f); err == nil {
						if f == float64(int64(f)) {
							val = strconv.FormatInt(int64(f), 10)
						} else {
							val = strconv.FormatFloat(f, 'f', -1, 64)
						}
					} else {
						var b bool
						if err := json.Unmarshal(fields[fieldName], &b); err == nil {
							val = strconv.FormatBool(b)
						}
						// Otherwise use raw JSON string (arrays, objects, etc.)
					}
				}
				// Convert snake_case key to readable label.
				label := strings.ReplaceAll(fieldName, "_", " ")
				mf = append(mf, metricField{Label: label, Value: val})
			}

			if len(mf) > 0 {
				groups = append(groups, metricGroup{Name: groupName, Fields: mf})
			}
		}

		if len(groups) == 0 {
			continue
		}

		result = append(result, FileMetricsDisplay{
			Basename:       extractBasename(file.Path),
			Risk:           file.Risk,
			Classification: file.Classification,
			Probability:    file.Probability,
			SHA256:         file.SHA256,
			Formula:        file.Formula,
			FileType:       strings.ToUpper(file.FileType),
			Groups:         groups,
		})
	}

	return result
}

// extractBasename extracts the filename from a path, handling archive paths.
func extractBasename(path string) string {
	if strings.Contains(path, "!!") {
		parts := strings.Split(path, "!!")
		path = parts[len(parts)-1]
	}
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

// formatBytes formats bytes into human-readable format.
func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// litmusAPIResponse represents the JSON response from litmus server's /analyze endpoint.
// It wraps the cleave analysis report with an ML-based classification outcome.
type litmusThresholds struct {
	Suspicious float64 `json:"suspicious"`
	Hostile    float64 `json:"hostile"`
}

type litmusAPIResponse struct {
	Path           string               `json:"path"`
	Classification string               `json:"classification"`
	Formula        string               `json:"formula"`
	FileType       string               `json:"file_type"`
	SHA256         string               `json:"sha256"`
	Cleave         json.RawMessage      `json:"cleave,omitempty"`
	EmbeddedFiles  []litmusEmbeddedFile `json:"embedded_files,omitempty"`
	TopFindings    []litmusTopFinding   `json:"top_findings,omitempty"`
	SizeBytes      int64                `json:"size_bytes"`
	Probability    float64              `json:"probability"`
	Thresholds     litmusThresholds     `json:"thresholds"`
}

// litmusEmbeddedFile is a per-file ML evaluation from litmus for archive members.
type litmusEmbeddedFile struct {
	Path           string             `json:"path"`
	FileType       string             `json:"file_type"`
	Classification string             `json:"classification"`
	Formula        string             `json:"formula,omitempty"`
	TopFindings    []litmusTopFinding `json:"top_findings,omitempty"`
	Probability    float64            `json:"probability"`
}

// litmusTopFinding is a representative finding surfaced by litmus ML evaluation.
type litmusTopFinding struct {
	ID   string `json:"id"`
	Crit string `json:"crit"`
	Desc string `json:"desc"`
}

// cleaveAPIResponse represents the JSON response from cleave's AnalysisReport.
// After finalize(), cleave clears top-level arrays and target — all data lives in files[].
type cleaveAPIResponse struct {
	Files    []cleaveAPIFile    `json:"files"`
	Findings []finding          `json:"findings,omitempty"`
	Strings  []stringInfo       `json:"strings,omitempty"`
	Imports  []symbolInfo       `json:"imports,omitempty"`
	Exports  []symbolInfo       `json:"exports,omitempty"`
	Sections []cleaveAPISection `json:"sections,omitempty"`
	Version  string             `json:"version"`
	Summary  *cleaveAPISummary  `json:"summary,omitempty"`
	Metrics  json.RawMessage    `json:"metrics,omitempty"`
	Target   cleaveTargetInfo   `json:"target"`
}

type cleaveTargetInfo struct {
	Path     string `json:"path"`
	FileType string `json:"type"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size_bytes"`
}

type cleaveAPIFile struct {
	ParentID *int               `json:"parent_id,omitempty"`
	Metrics  json.RawMessage    `json:"metrics,omitempty"`
	Counts   *findingCounts     `json:"counts,omitempty"`
	Formula  string             `json:"formula,omitempty"`
	Risk     string             `json:"risk,omitempty"`
	SHA256   string             `json:"sha256"`
	FileType string             `json:"file_type"`
	Path     string             `json:"path"`
	Imports  []symbolInfo       `json:"imports,omitempty"`
	Sections []cleaveAPISection `json:"sections,omitempty"`
	Exports  []symbolInfo       `json:"exports,omitempty"`
	Strings  []stringInfo       `json:"strings,omitempty"`
	Findings []finding          `json:"findings,omitempty"`
	ID       int                `json:"id"`
	Depth    int                `json:"depth"`
	Size     int64              `json:"size"`
}

type cleaveAPISection struct {
	Name       string  `json:"name"`
	Flags      string  `json:"flags,omitempty"`
	Permission string  `json:"permission,omitempty"`
	Address    uint64  `json:"address,omitempty"`
	Offset     *uint64 `json:"offset,omitempty"`
	Size       int64   `json:"size"`
	Entropy    float64 `json:"entropy,omitempty"`
}


type cleaveAPISummary struct {
	Counts        *findingCounts `json:"counts,omitempty"`
	MaxRisk       string         `json:"max_risk,omitempty"`
	FilesAnalyzed int            `json:"files_analyzed"`
	DurationMs    int64          `json:"duration_ms,omitempty"`
}

// litmusResult holds the output of a runLitmus call.
type litmusResult struct {
	RawLitmus      string // raw JSON body from litmus /analyze, served as-is from the .json endpoint
	Classification string
	Formula        string
	FileType       string
}

// runLitmus sends a file to the litmus server for analysis.
func runLitmus(
	ctx context.Context,
	filePath, originalFilename string,
	reqLogger *slog.Logger,
) (litmusResult, error) {
	startTime := time.Now()

	fileInfo, err := os.Stat(filePath) //nolint:gosec // filePath is an internal temp file path, not user input
	if err != nil {
		return litmusResult{}, fmt.Errorf("failed to stat file: %w", err)
	}

	reqLogger.Info("sending file to litmus server",
		"litmus_addr", litmusAddr,
		"file_path", filePath,
		"file_size", fileInfo.Size(),
	)

	file, err := os.Open(filePath) //nolint:gosec // filePath is an internal temp file path, not user input
	if err != nil {
		return litmusResult{}, fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			reqLogger.Debug("failed to close file", "error", err)
		}
	}()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	part, err := writer.CreateFormFile("file", originalFilename)
	if err != nil {
		return litmusResult{}, fmt.Errorf("failed to create form file: %w", err)
	}

	written, err := io.Copy(part, file)
	if err != nil {
		return litmusResult{}, fmt.Errorf("failed to copy file to form: %w", err)
	}

	if err := writer.Close(); err != nil {
		return litmusResult{}, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	bodyBytes := buf.Bytes()
	contentType := writer.FormDataContentType()
	reqLogger.Debug("multipart form created",
		"body_size", len(bodyBytes),
		"file_bytes_written", written,
		"content_type", contentType,
	)

	analyzeURL := fmt.Sprintf("http://%s/analyze", litmusAddr) //nolint:revive // http is correct: litmus is a local internal service

	// retryCtx bounds how long we will keep retrying when litmus is unreachable.
	// Individual HTTP requests still use ctx so an in-flight analysis is not cut short.
	retryCtx, retryCancel := context.WithTimeout(ctx, time.Minute)
	defer retryCancel()

	var litmusResp litmusAPIResponse
	var attempt int
	var rawBody []byte
	if retryErr := retry.Do(
		func() error {
			attempt++
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, analyzeURL, bytes.NewReader(bodyBytes))
			if err != nil {
				return retry.Unrecoverable(fmt.Errorf("failed to create request: %w", err))
			}
			req.Header.Set("Content-Type", contentType)
			req.ContentLength = int64(len(bodyBytes))

			reqLogger.Debug("sending HTTP request to litmus",
				"url", analyzeURL,
				"content_length", req.ContentLength,
				"attempt", attempt,
			)

			resp, err := litmusClient.Do(req) //nolint:gosec // SSRF risk accepted: litmusAddr is operator-configured, not user-supplied
			if err != nil {
				reqLogger.Warn("litmus HTTP request failed, will retry",
					"error", err,
					"attempt", attempt,
					"duration_ms", time.Since(startTime).Milliseconds(),
				)
				return fmt.Errorf("HTTP request failed: %w", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					reqLogger.Debug("failed to close response body", "error", err)
				}
			}()

			reqLogger.Debug("received HTTP response from litmus",
				"status", resp.StatusCode,
				"duration_ms", time.Since(startTime).Milliseconds(),
				"attempt", attempt,
			)

			// Cap response read to 64MB to prevent OOM from a misbehaving litmus server.
			const maxResponseSize = 64 * 1024 * 1024
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
			if err != nil {
				return fmt.Errorf("failed to read response: %w", err)
			}

			if resp.StatusCode != http.StatusOK {
				// Truncate body for logging to prevent log storage exhaustion.
				logBody := string(body)
				if len(logBody) > 1024 {
					logBody = logBody[:1024] + "...(truncated)"
				}
				reqLogger.Error("litmus server returned error",
					"status", resp.StatusCode,
					"body", logBody,
					"attempt", attempt,
				)
				// 4xx errors are not retryable (bad request, too large, etc.)
				if resp.StatusCode >= 400 && resp.StatusCode < 500 {
					return retry.Unrecoverable(fmt.Errorf("litmus server returned status %d: %s", resp.StatusCode, string(body)))
				}
				return fmt.Errorf("litmus server returned status %d: %s", resp.StatusCode, string(body))
			}

			if err := json.Unmarshal(body, &litmusResp); err != nil {
				return retry.Unrecoverable(fmt.Errorf("failed to parse litmus response: %w", err))
			}
			rawBody = body
			return nil
		},
		retry.Context(retryCtx),
		retry.Attempts(20),
		retry.Delay(200*time.Millisecond),
		retry.MaxDelay(10*time.Second),
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
	); retryErr != nil {
		return litmusResult{}, fmt.Errorf("failed to send request to litmus server: %w", retryErr)
	}

	reqLogger.Info("litmus analysis complete",
		"total_duration_ms", time.Since(startTime).Milliseconds(),
		"classification", litmusResp.Classification,
		"probability", litmusResp.Probability,
		"formula", litmusResp.Formula,
		"file_type", litmusResp.FileType,
		"raw_bytes", len(rawBody),
	)

	return litmusResult{
		RawLitmus:      string(rawBody),
		Classification: litmusResp.Classification,
		Formula:        litmusResp.Formula,
		FileType:       litmusResp.FileType,
	}, nil
}

// parseAPIResponse converts a cleaveAPIResponse into a cleaveReport for HTML rendering.
// It applies the same fallback logic as the old JSONL pipeline: depth-0 files inherit
// top-level imports, exports, strings, sections, and metrics when the per-file fields
// are absent.
//
//nolint:gocognit // inherently branchy: many independent optional blocks
func parseAPIResponse(resp *cleaveAPIResponse) *cleaveReport {
	report := &cleaveReport{}

	// If the files array is empty, synthesize a single entry from the top-level data.
	if len(resp.Files) == 0 && resp.Target.Path != "" {
		entry := cleaveFile{
			Path:     resp.Target.Path,
			Depth:    0,
			FileType: resp.Target.FileType,
			SHA256:   resp.Target.SHA256,
			Size:     resp.Target.Size,
			Findings: resp.Findings,
			Strings:  resp.Strings,
			Imports:  resp.Imports,
			Exports:  resp.Exports,
		}
		for _, f := range resp.Findings {
			switch f.Crit {
			case "hostile":
				entry.Risk = "hostile"
			case "suspicious":
				if entry.Risk != "hostile" {
					entry.Risk = "suspicious"
				}
			case "notable":
				if entry.Risk == "" {
					entry.Risk = "notable"
				}
			default:
			}
		}
		counts := &findingCounts{}
		for _, f := range resp.Findings {
			switch f.Crit {
			case "hostile":
				counts.Hostile++
			case "suspicious":
				counts.Suspicious++
			case "notable":
				counts.Notable++
			default:
			}
		}
		if counts.Hostile > 0 || counts.Suspicious > 0 || counts.Notable > 0 {
			entry.Counts = counts
		}
		for _, sec := range resp.Sections {
			entry.Sections = append(entry.Sections, sectionInfo{
				Name: sec.Name, Address: sec.Address, Offset: sec.Offset, Size: sec.Size, Entropy: sec.Entropy, Flags: sec.Flags,
			})
		}
		entry.Metrics = resp.Metrics
		report.Files = append(report.Files, entry)
	}

	for i := range resp.Files {
		f := &resp.Files[i]
		entry := cleaveFile{
			ID:       f.ID,
			Path:     f.Path,
			Depth:    f.Depth,
			FileType: f.FileType,
			SHA256:   f.SHA256,
			Size:     f.Size,
			Risk:     f.Risk,
			Counts:   f.Counts,
			Findings: f.Findings,
			Strings:  f.Strings,
			Formula:  f.Formula,
		}

		if f.Depth == 0 {
			if entry.FileType == "" || entry.FileType == "unknown" {
				if resp.Target.FileType != "" && resp.Target.FileType != "unknown" {
					entry.FileType = resp.Target.FileType
				}
			}
			if len(f.Imports) == 0 {
				entry.Imports = resp.Imports
			} else {
				entry.Imports = f.Imports
			}
			if len(f.Exports) == 0 {
				entry.Exports = resp.Exports
			} else {
				entry.Exports = f.Exports
			}
			if len(f.Strings) == 0 {
				entry.Strings = resp.Strings
			}
			if len(entry.Metrics) == 0 && len(resp.Metrics) > 0 {
				entry.Metrics = resp.Metrics
			}
		} else {
			entry.Imports = f.Imports
			entry.Exports = f.Exports
		}

		sections := f.Sections
		if f.Depth == 0 && len(sections) == 0 {
			sections = resp.Sections
		}
		for _, sec := range sections {
			entry.Sections = append(entry.Sections, sectionInfo{
				Name: sec.Name, Address: sec.Address, Offset: sec.Offset, Size: sec.Size, Entropy: sec.Entropy, Flags: sec.Flags,
			})
		}
		if len(f.Metrics) > 0 && len(entry.Metrics) == 0 {
			entry.Metrics = f.Metrics
		}

		report.Files = append(report.Files, entry)
	}

	if resp.Summary != nil {
		report.Summary = &cleaveSummary{
			FilesAnalyzed:      resp.Summary.FilesAnalyzed,
			AnalysisDurationMs: resp.Summary.DurationMs,
		}
		if resp.Summary.Counts != nil {
			report.Summary.Hostile = resp.Summary.Counts.Hostile
			report.Summary.Suspicious = resp.Summary.Counts.Suspicious
			report.Summary.Notable = resp.Summary.Counts.Notable
		}
	} else {
		summary := &cleaveSummary{FilesAnalyzed: max(len(resp.Files), 1)}
		for i := range resp.Files {
			switch resp.Files[i].Risk {
			case "hostile":
				summary.Hostile++
			case "suspicious":
				summary.Suspicious++
			case "notable":
				summary.Notable++
			default:
			}
		}
		if len(resp.Files) == 0 {
			for _, f := range resp.Findings {
				switch f.Crit {
				case "hostile":
					summary.Hostile++
				case "suspicious":
					summary.Suspicious++
				case "notable":
					summary.Notable++
				default:
				}
			}
		}
		report.Summary = summary
	}

	return report
}

// uploadToGCS uploads data to GCS with exponential backoff retry.
func uploadToGCS(ctx context.Context, bucket, sha256Hex, filename string, r io.Reader, reqLogger *slog.Logger) error {
	if gcsClient == nil {
		return errors.New("GCS client not initialized")
	}

	objectPath := fmt.Sprintf("%s/%s", sha256Hex, filename)
	reqLogger.Debug("preparing GCS upload", "bucket", bucket, "object", objectPath)

	var attempt int
	startTime := time.Now()
	err := retry.Do(
		func() error {
			attempt++
			reqLogger.Debug("uploading to GCS",
				"bucket", bucket,
				"object", objectPath,
				"attempt", attempt,
			)

			wc := gcsClient.Bucket(bucket).Object(objectPath).NewWriter(ctx)
			wc.ContentType = "application/octet-stream"

			if _, err := io.Copy(wc, r); err != nil {
				if cerr := wc.Close(); cerr != nil {
					reqLogger.Debug("failed to close GCS writer after copy error", "error", cerr)
				}
				// Seek back to start if it's a seeker for the next retry
				if rs, ok := r.(io.Seeker); ok {
					if _, serr := rs.Seek(0, io.SeekStart); serr != nil {
						reqLogger.Debug("failed to seek file", "error", serr)
					}
				}
				return fmt.Errorf("write: %w", err)
			}

			if err := wc.Close(); err != nil {
				return fmt.Errorf("close: %w", err)
			}

			return nil
		},
		retry.Context(ctx),
		retry.Attempts(5),
		retry.MaxDelay(2*time.Minute),
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
		retry.OnRetry(func(n uint, err error) {
			reqLogger.Warn("GCS upload retry",
				"attempt", n+1,
				"error", err,
				"bucket", bucket,
				"object", objectPath,
			)
		}),
	)

	if err == nil {
		reqLogger.Info("GCS upload complete", "duration_ms", time.Since(startTime).Milliseconds(), "bucket", bucket, "object", objectPath)
	}

	return err
}
