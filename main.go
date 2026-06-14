//nolint:revive // max-public-structs: prism is a single-binary web service; the structs are the page-data shape and exporting them is what html/template needs.
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
	"flag"
	"fmt"
	"html"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"codeberg.org/atomdrift/hopper"
	"codeberg.org/atomdrift/obs"
	"github.com/alecthomas/chroma/v2"
	chromahtml "github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/codeGROOVE-dev/fido"
	"github.com/codeGROOVE-dev/fido/pkg/store/localfs"
	"github.com/codeGROOVE-dev/fido/pkg/store/null"
	"github.com/codeGROOVE-dev/retry"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// buildCommit is set via -ldflags at build time (see Makefile).
var buildCommit = "dev"

// shortBuildCommit returns the first 5 characters of buildCommit, or the
// full string if it is shorter (e.g. the "dev" placeholder). Used in the
// page footer so visitors can pin issues to a specific deploy.
func shortBuildCommit() string {
	if len(buildCommit) > 5 {
		return buildCommit[:5]
	}
	return buildCommit
}

var (
	uploadTemplate     *template.Template
	resultTemplate     *template.Template
	errorTemplate      *template.Template
	formatsTemplate    *template.Template
	poweredByTemplate  *template.Template
	helpQueryTemplate  *template.Template
	pendingTemplate    *template.Template
	hopperAPIAddr      string       // Address of hopper API server (e.g., "hopper-api:8081")
	hopperClient       *http.Client // HTTP client for hopper API server
	litmusAddr         string       // Address of the dedicated litmus analysis server; empty disables it
	litmusClient       *http.Client // HTTP client for the litmus analysis server
	cache              *fido.TieredCache[string, storedResult]
	feedCache          *fido.TieredCache[string, cachedFeedSnapshot]
	reportCache        *fido.TieredCache[string, cachedReport]
	parentArchiveCache *fido.TieredCache[string, cachedParents]
	logger             *slog.Logger
	publicMode         bool // true when --public flag is set; changes branding and shows data-sharing notice
	// hopperDB is the sample-registry handle. Stored as an atomic.Pointer
	// because connectHopperWithRetry may replace it from a background
	// goroutine after a startup-time hopper.Open failure; all readers must
	// use hopperDB.Load() to get a stable snapshot.
	hopperDB    atomic.Pointer[hopper.DB]
	hopperDBDSN string // saved for background reconnect after startup failure; never contains user input
)

const (
	defaultHopperDSN     = "postgres://hopper@hopper-db:5432/hopper?sslmode=disable"
	defaultHopperAPIAddr = "hopper-api:8081"
	// defaultLitmusAddr is the dedicated litmus analysis server (litmus serve's
	// default listen port). Uploads are analyzed here first; when it returns,
	// prism publishes the result to hopper so hopper's own worker pool doesn't
	// duplicate the work. Optional — when unreachable, hopper analyzes instead.
	defaultLitmusAddr = "litmus:49999"
	// feedCacheTTL is the absolute lifetime of any cached feed query
	// (frontpage default, criticality variants, ecosystem/domain/formula
	// filtered, and free-text ?q= searches). Every feed query goes through
	// the cache — even untyped filter combinations and one-off searches — to
	// avoid thundering-herd hopper hits when many users request the same
	// view at once. The 30-minute envelope keeps the long tail of distinct
	// search terms cheap and gives the pre-cache loop a wide safety margin: at
	// a 5-minute refresh, a hot key survives several missed ticks before it can
	// expire. The high-traffic default and criticality views are kept fresher
	// than this by refreshFeedCacheLoop.
	feedCacheTTL = 30 * time.Minute
	// The feed pre-cache runs in two tiers. The hot tier re-warms the views
	// people actually hit (the top feedHotPrecacheCount structured pivots, by
	// observed traffic) every feedHotPrecacheInterval, so popular ecosystem and
	// severity pages stay fresh. The static tier sweeps a fixed baseline set —
	// the frontpage, the criticality views, and a static ecosystem list — every
	// feedStaticPrecacheInterval so even a rarely-visited page is reasonably
	// warm. Both are well under feedCacheTTL, so a key is rebuilt several times
	// within its lifetime and never serves a fully cold loader.
	feedHotPrecacheInterval    = 5 * time.Minute
	feedStaticPrecacheInterval = 15 * time.Minute
	feedHotPrecacheCount       = 10
	// auxCacheTTL is the TTL for ancillary per-SHA caches (report, parent
	// archives, etc.). They key off an immutable SHA-256, and a rescan
	// explicitly invalidates them (see requestRescan), so the only thing this
	// bounds is drift for a sample nobody rescans — hence a long 24-hour
	// envelope. A hard refresh (Cache-Control: no-cache) bypasses it on demand.
	auxCacheTTL = 24 * time.Hour
	// rescanCooldown is the minimum age of the most recent analysis
	// before another rescan request is accepted. Enforced both
	// client-side (button hidden) and server-side (atomic check in the
	// UPDATE statement), so a race or hand-crafted POST can't bypass.
	rescanCooldown = 15 * time.Minute
)

// csrfKey is the 32-byte key for HMAC-signing CSRF tokens. Tokens are
// stateless: HMAC(cookie || action || ts) verified on POST. loadCSRFKey
// (called from loadConfig) replaces this per-process random default with a
// stable key derived from PRISM_CSRF_KEY when set, so tokens stay valid when
// Cloud Run routes a visitor's POST to a different instance than the GET that
// minted the token, and across deploys. The random default keeps single-
// instance and test runs working with no configuration.
var csrfKey = randomCSRFKey()

func randomCSRFKey() [32]byte {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		panic("csrf: failed to generate key: " + err.Error())
	}
	return k
}

// loadCSRFKey resolves the CSRF HMAC key from PRISM_CSRF_KEY. The secret is run
// through SHA-256 so any encoding (hex, base64, raw) yields a full-width
// 256-bit key; a >=32-character minimum is a coarse entropy floor. Absent or
// too-short, it keeps the per-process random key and warns — fine for a single
// instance or local dev, but a multi-instance deployment will otherwise see
// intermittent "session expired" failures on upload/rescan/download.
func loadCSRFKey() [32]byte {
	secret := strings.TrimSpace(os.Getenv("PRISM_CSRF_KEY"))
	if len(secret) < 32 {
		if secret != "" {
			logger.Warn("PRISM_CSRF_KEY too short (need >=32 chars); using per-process CSRF key")
		} else {
			logger.Warn("PRISM_CSRF_KEY unset; using per-process CSRF key — tokens will not validate across instances or restarts")
		}
		return csrfKey
	}
	return sha256.Sum256([]byte(secret))
}

const (
	// csrfCookieName is the per-browser session marker used to bind a CSRF
	// token to the visitor who received it. Cookies set by ensureCSRFCookie
	// carry HttpOnly, SameSite=Strict, and Secure whenever the request is
	// HTTPS (directly, via X-Forwarded-Proto, or --public).
	csrfCookieName = "prism_csrf"
	// csrfMaxAge bounds a token's validity. Short enough that a leaked
	// token (e.g. via page-scrape) has a small window.
	csrfMaxAge = 15 * time.Minute
)

type ctxKey int

const (
	scriptNonceKey ctxKey = iota
	styleNonceKey
	csrfSessionKey
)

// ensureCSRFCookie reads (or freshly creates) the per-browser CSRF session
// cookie and stashes its value in the request context. The cookie value is
// HMAC-mixed into every token issued for this visitor, so a token stolen
// from one user cannot be used by another. SameSite=Strict means an
// attacker site cannot make the browser ship this cookie cross-origin.
func ensureCSRFCookie(w http.ResponseWriter, r *http.Request) *http.Request {
	// 22 == base64.RawURLEncoding.EncodedLen(16); reject truncated cookies.
	if c, err := r.Cookie(csrfCookieName); err == nil && len(c.Value) >= 22 {
		return r.WithContext(context.WithValue(r.Context(), csrfSessionKey, c.Value))
	}
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Without entropy we can't issue safe tokens; let the request
		// continue cookieless and any CSRF check will reject.
		return r
	}
	val := base64.RawURLEncoding.EncodeToString(buf[:])
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   publicMode || requestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(24 * time.Hour / time.Second),
	})
	return r.WithContext(context.WithValue(r.Context(), csrfSessionKey, val))
}

// requestIsHTTPS reports whether the request reached prism over TLS, either
// directly or through a TLS-terminating proxy (Cloud Run forwards over
// plaintext but sets X-Forwarded-Proto=https). It only ever ENABLES the Secure
// cookie flag, so a spoofed header can make the cookie more restrictive
// (fail-closed) but never strip Secure.
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func csrfSession(r *http.Request) string {
	if v, ok := r.Context().Value(csrfSessionKey).(string); ok {
		return v
	}
	return ""
}

// csrfMAC binds the session cookie, action name, and timestamp into a single
// HMAC. NUL separators keep the three fields unambiguous so e.g. action "ab"
// at ts "cd" cannot collide with action "a" at ts "bcd".
func csrfMAC(session, action, ts string) string {
	mac := hmac.New(sha256.New, csrfKey[:])
	mac.Write([]byte(session))
	mac.Write([]byte{0})
	mac.Write([]byte(action))
	mac.Write([]byte{0})
	mac.Write([]byte(ts))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// csrfToken generates a signed, timestamped CSRF token bound to the request's
// CSRF session cookie and a named action (e.g. "rescan", "upload"). A token
// is only valid for the same browser, same action, within csrfMaxAge.
func csrfToken(r *http.Request, action string) string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	return ts + "." + csrfMAC(csrfSession(r), action, ts)
}

// csrfValid checks token shape, signature, age, session-cookie binding, and
// action binding. The session is read from the cookie on the live request,
// so a token issued for one browser cannot be replayed from another.
func csrfValid(r *http.Request, action, token string) bool {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return false
	}
	ts, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false
	}
	if age := time.Since(time.Unix(ts, 0)); age < 0 || age > csrfMaxAge {
		return false
	}
	session := csrfSession(r)
	if session == "" {
		return false
	}
	expected := csrfMAC(session, action, parts[0])
	return hmac.Equal([]byte(parts[1]), []byte(expected))
}

// tokenLimiter implements a per-IP token bucket rate limiter.
type tokenLimiter struct {
	buckets map[string]*bucket
	mu      sync.Mutex
	burst   float64 // max tokens in a bucket
	rate    float64 // tokens per second
}

type bucket struct {
	lastSeen time.Time
	tokens   float64
}

const (
	bucketLifetime = 10 * time.Minute // evict idle entries
	// maxLimiterBuckets caps the per-limiter map size to bound memory under
	// adversarial input (e.g. attacker rotating client IPs). When the cap is
	// hit we evict the single least-recently-seen entry inline. Sized for
	// ~80 B/entry × 65k = ~5 MB resident per limiter — comfortably small,
	// large enough to track real traffic without collisions.
	maxLimiterBuckets = 65536
)

func newTokenLimiter(burst int, rate float64) *tokenLimiter {
	tl := &tokenLimiter{
		buckets: make(map[string]*bucket),
		burst:   float64(burst),
		rate:    rate,
	}
	go tl.reap()
	return tl
}

// allow checks whether the given IP may proceed.
func (tl *tokenLimiter) allow(ip string) bool {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	now := time.Now()
	b, ok := tl.buckets[ip]
	if !ok {
		// Bound the map under adversarial IP-rotation by evicting the
		// single least-recently-seen entry when we hit the cap.
		if len(tl.buckets) >= maxLimiterBuckets {
			var oldestIP string
			var oldestSeen time.Time
			for k, v := range tl.buckets {
				if oldestIP == "" || v.lastSeen.Before(oldestSeen) {
					oldestIP = k
					oldestSeen = v.lastSeen
				}
			}
			if oldestIP != "" {
				delete(tl.buckets, oldestIP)
			}
		}
		tl.buckets[ip] = &bucket{tokens: tl.burst - 1, lastSeen: now}
		return true
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastSeen).Seconds()
	b.tokens += elapsed * tl.rate
	if b.tokens > tl.burst {
		b.tokens = tl.burst
	}
	b.lastSeen = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// reap periodically removes stale entries to prevent memory growth.
func (tl *tokenLimiter) reap() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		tl.mu.Lock()
		now := time.Now()
		for ip, b := range tl.buckets {
			if now.Sub(b.lastSeen) > bucketLifetime {
				delete(tl.buckets, ip)
			}
		}
		tl.mu.Unlock()
	}
}

// Upload: 1 every 30 seconds per IP, burst of 2 (a single quick retry).
var uploadRateLimiter = newTokenLimiter(2, 1.0/30.0)

// uploadGlobalLimiter caps the total upload rate across all clients so a
// botnet rotating IPs can't bypass the per-IP limiter and overwhelm the
// hopper analyzer pipeline. 5/min sustained, burst of 10 absorbs a small
// crowd of legitimate users without queueing. Bypassing both this and the
// per-IP limiter requires both a botnet *and* patience.
var uploadGlobalLimiter = newTokenBucket(5.0/60.0, 10)

// Download: 25 per hour, no burst above the hourly budget.
var downloadRateLimiter = newTokenLimiter(25, 25.0/3600.0)

// sseWaiters tracks concurrent SSE wait connections (total + per IP) so we
// can refuse new ones when caps are exceeded.
var sseWaiters = struct {
	perIP map[string]int
	total int
	mu    sync.Mutex
}{perIP: make(map[string]int)}

// waitAcquire reserves a wait slot for ip. Returns false if either the
// global or per-IP cap is exceeded; on true the caller must defer waitRelease.
func waitAcquire(ip string) bool {
	sseWaiters.mu.Lock()
	defer sseWaiters.mu.Unlock()
	if sseWaiters.total >= waitMaxClientsTotal {
		return false
	}
	if sseWaiters.perIP[ip] >= waitMaxClientsPerIP {
		return false
	}
	// Bound the perIP map under IP-rotation. Treat over-cap as a refusal
	// rather than evicting a counter mid-use.
	if _, ok := sseWaiters.perIP[ip]; !ok && len(sseWaiters.perIP) >= maxLimiterBuckets {
		return false
	}
	sseWaiters.total++
	sseWaiters.perIP[ip]++
	return true
}

func waitRelease(ip string) {
	sseWaiters.mu.Lock()
	defer sseWaiters.mu.Unlock()
	sseWaiters.total--
	if sseWaiters.perIP[ip] <= 1 {
		delete(sseWaiters.perIP, ip)
	} else {
		sseWaiters.perIP[ip]--
	}
}

// maxDownloadSize caps the on-disk sample size eligible for /file/<sha>.dl.
// Browsers that have to fight through Cloudflare on a multi-hundred-MB
// stream are not the target audience here; larger samples are CLI-only
// via litmus.
const maxDownloadSize int64 = 400 * 1024 * 1024

// clientIP extracts the client IP from the request.
//
// Cloudflare Tunnel (our production deployment) sets CF-Connecting-IP to the
// real client IP and strips any inbound value, so it is the authoritative
// source when present and cannot be spoofed by the client. In local/dev
// runs without Cloudflare, we fall back to RemoteAddr.
//
// X-Forwarded-For is intentionally NOT honored: the rightmost-XFF heuristic
// collapses all visitors to the proxy IP behind Cloudflare, and the leftmost
// entry is fully attacker-controlled when no proxy is in front.
func clientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("Cf-Connecting-Ip")); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// openNullCache constructs an in-memory-only TieredCache backed by fido's
// null store — used when --no-cache disables persistence. Fatal on error;
// failing to spin up a cache means prism cannot serve safely under load.
func openNullCache[V any](label string) *fido.TieredCache[string, V] {
	c, err := fido.NewTiered(null.New[string, V]())
	if err != nil {
		logger.Error("failed to initialize fido "+label, "error", err)
		os.Exit(1)
	}
	return c
}

// openLocalFSCache constructs a localfs-backed TieredCache. id is the
// on-disk subdirectory name under cacheDir; label is used only for log
// output. Fatal on error for the same reason as openNullCache.
func openLocalFSCache[V any](id, cacheDir, label string) *fido.TieredCache[string, V] {
	store, err := localfs.New[string, V](id, cacheDir)
	if err != nil {
		logger.Error("failed to initialize fido "+label+" store", "error", err)
		os.Exit(1)
	}
	c, err := fido.NewTiered(store)
	if err != nil {
		logger.Error("failed to initialize fido "+label, "error", err)
		os.Exit(1)
	}
	return c
}

// FindingDisplay represents a single finding for table display.
type FindingDisplay struct {
	ID      string
	Crit    string
	Desc    string
	Matches []FindingMatch
	// Context holds the rendered source/hex windows for this trait, from
	// cleave's current per-line `ctx`. When present the expansion shows it in
	// place of the Matches rows; Matches remains the fallback for legacy
	// reports and uploads that carry no rich context.
	Context []contextBlock
	ConfPct int
}

// FindingMatch is one row in an expandable trait card, rendered as
// "filename — location — evidence". For archive aggregations the filename
// and location are resolved from cleave's parallel `ev` / `loc` arrays;
// for per-file findings the evidence stands on its own (the file is
// implied by the surrounding view) and Filename/Location stay empty.
type FindingMatch struct {
	Evidence string
	Path     string // full inner-archive path, shown as the row's tooltip
	Filename string // basename of Path, the visible filename column
	Location string // offset within the file from cleave's `loc`, e.g. "1042"
	// Tokens is the chroma-highlighted form of Evidence, lexed by the
	// source filename. Empty when no lexer matched; the template falls
	// back to plain Evidence text.
	Tokens []EvidenceToken
	Count  int
}

// EvidenceToken is one chroma-classified slice of an evidence string. Class
// is a chroma standard-type CSS class (always a fixed identifier from the
// chroma library, never attacker-controlled); empty means render Text as a
// bare text node with no wrapping span.
type EvidenceToken struct {
	Class string
	Text  string
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
	Classification string
	SHA256         string
	Formula        string
	FileType       string
	Categories     []CategoryGroup
	Probability    float64
	// TraitTotal is the number of distinct traits the sample produced;
	// TraitShown is how many survived the top-N cap. When TraitTotal >
	// TraitShown the Traits tab notes that the list was truncated.
	TraitTotal int
	TraitShown int
}

// FileStringsDisplay represents strings for a single file.
type FileStringsDisplay struct {
	Basename       string
	Risk           string
	Classification string
	SHA256         string
	Formula        string
	FileType       string
	Gradient       template.CSS
	Strings        []StringDisplay
	Sections       []StringSectionGroup
	Probability    float64
	HasSections    bool
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
	Gradient       template.CSS
	Imports        []SymbolDisplay
	Exports        []SymbolDisplay
	Probability    float64
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
	Gradient       template.CSS
	Sections       []SectionDisplay
	Probability    float64
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
	Gradient       template.CSS
	Groups         []metricGroup
	Probability    float64
}

// KVPair is a single row in the KV tab: dotted-path key ("package.name",
// "archive.member_count[0]") → string-rendered value.
type KVPair struct {
	Key   string
	Value string
}

// FileKVDisplay holds a single file's flat structural kv map for display.
type FileKVDisplay struct {
	Basename       string
	Risk           string
	Classification string
	SHA256         string
	Formula        string
	FileType       string
	Pairs          []KVPair
	Probability    float64
}

// ParentArchive is one archive that contains the currently-viewed file. It
// powers the "found in" backlinks shown on standalone child pages so users
// can navigate up to the archive context they came from.
type ParentArchive struct {
	SHA256         string
	SHA256Short    string
	Filename       string
	Path           string // path of this child within the parent (from sample_locations)
	Classification string // "hostile" / "suspicious" / "benign" / ""
	AnalyzedAt     string // human-readable UTC date
	AnalyzedAgo    string // relative time
}

// cachedReport wraps hopper.Report in a struct with a Found flag so the
// "no report exists for this SHA" case is itself cacheable — without this,
// every page render for a sample without a report would re-hit hopper.
type cachedReport struct {
	Report hopper.Report
	Found  bool
}

// cachedParents wraps the []ParentArchive returned by lookupParentArchives.
// A separate type (rather than just []ParentArchive) keeps the fido cache's
// type-parameter ergonomics clean and lets the empty/not-found case be
// distinguished from a cache miss.
type cachedParents struct {
	Entries []ParentArchive
}

// resultData is the page-data shape consumed by result.html. Field order is
// readability-driven (grouped by what the template renders, not packed for
// minimum size); the savings from reordering are negligible against page-
// render cost, and a packed layout would obscure the per-tab grouping.
//
//nolint:govet // field alignment intentionally relaxed; see comment above
type resultData struct {
	SHA256Short  string
	Filename     string
	SHA256       string
	Verdict      string
	Formula      template.HTML
	FormulaQuery string // raw formula with subscript digits desubscripted, for ?m=… links
	CSRFToken    string // signed CSRF token for operator actions (rescan)
	// DownloadToken is a separate CSRF token bound to the "download" action.
	// Rendered into the download button's href as `?t=…` so /file/<sha>.dl is
	// gated to button-driven flows: the token only validates for the browser
	// session that fetched the page, within csrfMaxAge. Bots, link previews,
	// pasted URLs from another browser, and stale wayback captures all fail.
	DownloadToken  string
	FileType       string
	MoleculeJSON   template.JS
	Duration       string
	FindingCount   string
	Nonce          string // script-src nonce
	StyleNonce     string // style-src nonce
	Size           string
	SizeBytes      int64 // raw size of the top-level (or first) file; gates the download button
	RiskLevel      string
	ReportCreated  string
	ReportProvider string
	ReportContent  string
	AnalyzedAgo    string
	AnalyzedAt     string
	// AnalyzedAtMillis is the unix-ms timestamp of the most recent
	// analysis, exposed to JS via a data-attribute on the rescan button
	// so the rescan-then-wait flow can ask the server "tell me when a
	// fresh analysis lands AFTER this point" instead of accepting the
	// already-stale result.
	AnalyzedAtMillis int64
	RiskLabel        string
	FirstSeenAgo     string
	FirstSeenAt      string
	// SourceURL is the full canonical download URL forager recorded when
	// the bytes first landed in hopper. Used as the link href; empty for
	// uploads and legacy rows without provenance.
	SourceURL string
	// SourceLabel is the short string shown inline in the meta-table:
	// the URL's hostname when SourceURL is set, otherwise the eTLD+1
	// from samples.domain as a fallback. Empty when neither is known
	// (the template hides the row).
	SourceLabel string
	// Ecosystem is hopper's registry/distro label (e.g. "npm", "pypi").
	// Empty for uploads or rows hopper could not attribute; the template
	// hides the meta row when empty.
	Ecosystem string
	// EcosystemURL is the in-app feed link for this ecosystem (e.g.
	// "/npm/"). Empty when Ecosystem is empty.
	EcosystemURL string
	Layout       string
	BuildCommit  string
	FileMetrics  []FileMetricsDisplay
	FileSections []FileSectionsDisplay
	FileSymbols  []FileSymbolsDisplay
	FileStrings  []FileStringsDisplay
	FileFindings []FileFindingsDisplay
	FileKVs      []FileKVDisplay
	// FileViews is the per-file context view shown in the File tab. When
	// non-empty the File tab renders and is the page's default tab; empty for
	// legacy reports without current-format context, which keep Traits default.
	FileViews []fileView
	// ContentLocStyle sets the --ctx-loc-ch CSS variable (the widest loc string
	// across every window) on the Content tab, so each window's line-number /
	// hex-offset column shares one width and the columns line up within and
	// between files. Empty when there are no file views.
	ContentLocStyle template.HTMLAttr
	// Provenance is the grouped origin record shown in the Provenance tab:
	// what hopper's database knows about where this sample came from. Empty
	// for samples with no recorded provenance beyond their own identity.
	Provenance []ProvenanceGroup
	// Parents lists archives that contain this file. Populated only on
	// standalone child pages (non-archive views) so the user can navigate
	// up to the archive context the file came from.
	Parents []ParentArchive
	// ArchiveCategories is the aggregated trait categories across every
	// file in an archive (deduped by trait ID). The archive Traits tab
	// shows this summary; expanding a trait reveals its per-file
	// filename — location — evidence rows.
	ArchiveCategories []CategoryGroup
	// ArchiveTraitTotal / ArchiveTraitShown mirror the per-file counts for
	// the aggregated archive Traits tab: total distinct traits vs. how many
	// survived the top-N cap.
	ArchiveTraitTotal int
	ArchiveTraitShown int
	HostileT          float64
	SuspiciousT       float64
	// Threshold/Class/Level populated from v=5 envelopes. Threshold > 0 is
	// the sentinel for "use the v=5 exact-band path"; v=4 inputs leave it 0
	// and the template falls back to the legacy two-edge gradient.
	Threshold float64
	Class     int
	Level     *int
	// StampGradient is the verdict-stamp CSS gradient for the top-level file,
	// precomputed per envelope version (v6/v7 colors by level; v4/v5 by threshold).
	StampGradient template.CSS
	// LevelConfidence is the level-derived "how confident this is hostile"
	// percentage shown on the litmus badge (from ml.conf, falling back to
	// levelConfidence for cached envelopes).
	LevelConfidence int
	Probability     float64
	IsArchive       bool
	LimitedInfo     bool
	RescanAllowed   bool // last analysis is older than rescanCooldown — the rescan button is hidden when false
}

// storedResult is what we persist in fido/datastore.
type storedResult struct {
	CachedAt       time.Time
	AnalyzedAt     time.Time
	CreatedAt      time.Time
	Metrics        string
	Symbols        string
	Sections       string
	Filename       string
	Classification string
	Formula        string
	FileType       string
	Strings        string
	Traits         string
	RawLitmus      string
	// SourceURL is the canonical download URL forager (or another
	// ingester) captured when the bytes first landed in hopper. Empty
	// for samples without provenance (uploads, legacy harvested rows).
	SourceURL string
	// SourceDomain is the eTLD+1 of SourceURL (or registry-derived when
	// the URL is missing), used as a fallback display when SourceURL is
	// empty so the page still surfaces *something* about provenance.
	SourceDomain string
	// Ecosystem is hopper's registry/distro label for the sample (e.g.
	// "npm", "pypi", "debian"). Empty for uploads or rows hopper could
	// not attribute.
	Ecosystem string
	// SizeBytes is hopper's authoritative byte count for the sample,
	// recorded from the actual stored bytes at ingest. It is the source of
	// truth for size: the cleave report's entry-level size is absent on
	// compacted and pre-v7 root entries, so size must not be re-derived
	// from the report when this is available.
	SizeBytes int64
	// The fields below carry the rest of hopper's provenance record for the
	// Provenance tab. All are empty/zero for uploads (which arrive without
	// provenance) and for legacy rows hopper never attributed; the tab
	// drops empty rows so absent fields simply don't appear.
	//
	// Source is hopper's ingest source column (the harvester or importer that
	// first recorded the bytes); Feed is the threat-intel or registry feed
	// the sample arrived on (e.g. "npmjs.org", "malshare").
	Source string
	Feed   string
	// Package and Version identify the software release the bytes belong to
	// (e.g. "lodash" / "4.17.21") when hopper attributed one.
	Package string
	Version string
	// Label is hopper's ground-truth verdict ("bad"/"good"/"unknown") and
	// LabelSource records who or what assigned it.
	Label       string
	LabelSource string
	// TraitsVersion is the short traits-repo commit prefix used for the most
	// recent analysis.
	TraitsVersion string
	// CanonicalSHA256 is the min SHA256 across the sample and its embedded
	// files — the identity hopper uses for train/test dedup. Shown only when
	// it differs from the sample's own SHA256.
	CanonicalSHA256 string
	// UpdatedAt and FirstAnalyzedAt round out the provenance timeline
	// alongside CreatedAt (first seen) and AnalyzedAt (last analyzed).
	UpdatedAt       time.Time
	FirstAnalyzedAt time.Time
}

type feedRow struct {
	AnalyzedAt     time.Time
	Source         string
	EcosystemURL   string
	Classification string
	TimeAgo        string
	AnalyzedDate   string
	SHA256Short    string
	Formula        string
	FileType       string
	SHA256         string
	Ecosystem      string
	Filename       string
	// Feed is the hopper.Sample.Feed column — the threat-intel or
	// registry source name (e.g. "malshare", "npmjs.org"). Surfaced
	// only on the /?feeds=1 view; left empty in JSON otherwise.
	Feed        string
	HostileT    float64
	SuspiciousT float64
	Probability float64
	// Threshold/Class populated from v=5 envelopes; Threshold > 0 selects
	// the exact-band rendering path in templates.
	Threshold float64
	Class     int
}

type feedPageData struct {
	SelectedDomain  string
	Nonce           string // script-src nonce
	StyleNonce      string // style-src nonce
	BuildCommit     string
	Title           string
	SelectedFormula string
	SelectedCrit    string
	SelectedQ       string
	SearchQuery     string
	CSRFToken       string
	SelectedEco     string
	// PrevURL/NextURL are empty when there is no adjacent page.
	PrevURL    string
	NextURL    string
	Domains    []string
	Ecosystems []string
	Rows       []feedRow
	// Pages holds the per-page links (empty when a single page covers every
	// row); Page is the 1-indexed current page over the cached snapshot.
	Pages         []feedPageLink
	TotalCount    int
	FilteredCount int
	Page          int
	Refresh       bool
	HasHopper     bool
	// UploadEnabled mirrors the package-level toggle so the template can
	// pick the real upload form vs. the disabled placeholder.
	UploadEnabled bool
	// FeedsOnly enables the hidden "malware feeds" view: only label='bad'
	// samples (threat-intel + curated open-source malware sources) are
	// listed, and the table grows a "Feed" column showing which source
	// each row came from. Activated by ?feeds=1 — no dropdown surface.
	FeedsOnly bool
}

// feedPageLink is one entry in the feed's pagination strip.
type feedPageLink struct {
	URL     string
	Num     int
	Current bool
}

// queryDiag is a single data-source diagnostic, emitted as an HTML comment at
// the end of the page (one per query). Duration/Age are pre-formatted strings.
type queryDiag struct {
	Name     string
	Source   string // "cache" or "postgres"
	Duration string
	Age      string
	Params   string
	Rows     int
	Bytes    int
}

type cachedFeedSnapshot struct {
	GeneratedAt time.Time
	Rows        []cachedFeedSample
	Ecosystems  []string
	Domains     []string
	TotalCount  int
	// Bytes is the JSON-serialized size of this snapshot (the same encoding
	// the localfs cache persists), captured once at build time so the
	// per-request diagnostics can report payload size without re-marshaling
	// on a cache hit.
	Bytes int
}

type cachedFeedSample struct {
	CreatedAt      time.Time
	SHA256         string
	Filename       string
	Classification string
	Formula        string
	FileType       string
	Source         string
	Feed           string
	Ecosystem      string
	Probability    float64
	SuspiciousT    float64
	HostileT       float64
	Threshold      float64 // v=5 only; zero for v=4 inputs
	Class          int     // v=5 only; mirrored from envelope for rendering
}

// cleaveReport is constructed from JSONL output (multiple lines).
type cleaveReport struct {
	Files []cleaveFile `json:"files"`
}

// cleaveFile represents a file entry in cleave compact output.
// Litmus injects "class" and "prob" into each files[] entry.
type cleaveFile struct {
	KV             map[string]json.RawMessage `json:"k,omitempty"`
	Gradient       template.CSS               `json:"-"`
	Path           string                     `json:"path"`
	FileType       string                     `json:"type"`
	SHA256         string                     `json:"sha"`
	Classification string                     `json:"-"`
	Formula        string                     `json:"mol,omitempty"`
	Facts          cleaveFacts                `json:"fact,omitzero"`
	Exports        []symbolInfo               `json:"exports,omitempty"`
	Findings       []finding                  `json:"find,omitempty"`
	Ctx            []contextWindow            `json:"ctx,omitempty"`
	Strings        []json.RawMessage          `json:"ss,omitempty"`
	Imports        []string                   `json:"is,omitempty"`
	Sections       []sectionInfo              `json:"sections,omitempty"`
	Metrics        json.RawMessage            `json:"ms,omitempty"`
	Probability    float64                    `json:"-"`
	Threshold      float64                    `json:"-"`
	Class          int                        `json:"-"`
	Size           int64                      `json:"size"`
	ID             int                        `json:"id"`
	Depth          int                        `json:"dp"`
}

type cleaveFacts struct {
	Metrics   json.RawMessage            `json:"met,omitempty"`
	KV        map[string]json.RawMessage `json:"val,omitempty"`
	Strings   []json.RawMessage          `json:"str,omitempty"`
	Imports   []json.RawMessage          `json:"imp,omitempty"`
	Exports   []json.RawMessage          `json:"exp,omitempty"`
	Functions []json.RawMessage          `json:"fn,omitempty"`
	Sections  []json.RawMessage          `json:"sec,omitempty"`
}

func (f *cleaveFacts) UnmarshalJSON(data []byte) error {
	var raw struct {
		Metrics     json.RawMessage            `json:"met,omitempty"`
		OldMetrics  json.RawMessage            `json:"m,omitempty"`
		KV          map[string]json.RawMessage `json:"val,omitempty"`
		OldKV       map[string]json.RawMessage `json:"v,omitempty"`
		Strings     []json.RawMessage          `json:"str,omitempty"`
		OldStrings  []json.RawMessage          `json:"s,omitempty"`
		Imports     []json.RawMessage          `json:"imp,omitempty"`
		OldImports  []json.RawMessage          `json:"i,omitempty"`
		Exports     []json.RawMessage          `json:"exp,omitempty"`
		OldExports  []json.RawMessage          `json:"x,omitempty"`
		Functions   []json.RawMessage          `json:"fn,omitempty"`
		Sections    []json.RawMessage          `json:"sec,omitempty"`
		OldSections []json.RawMessage          `json:"sc,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	f.Metrics = raw.Metrics
	if len(f.Metrics) == 0 {
		f.Metrics = raw.OldMetrics
	}
	f.KV = raw.KV
	if len(f.KV) == 0 {
		f.KV = raw.OldKV
	}
	f.Strings = raw.Strings
	if len(f.Strings) == 0 {
		f.Strings = raw.OldStrings
	}
	f.Imports = raw.Imports
	if len(f.Imports) == 0 {
		f.Imports = raw.OldImports
	}
	f.Exports = raw.Exports
	if len(f.Exports) == 0 {
		f.Exports = raw.OldExports
	}
	f.Functions = raw.Functions
	f.Sections = raw.Sections
	if len(f.Sections) == 0 {
		f.Sections = raw.OldSections
	}
	return nil
}

func (r *cleaveReport) UnmarshalJSON(data []byte) error {
	var raw struct {
		Files    []cleaveFile `json:"files"`
		OldFiles []cleaveFile `json:"fs"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	r.Files = raw.Files
	if len(r.Files) == 0 {
		r.Files = raw.OldFiles
	}
	return nil
}

func (f *cleaveFile) UnmarshalJSON(data []byte) error {
	var raw struct {
		KV          map[string]json.RawMessage `json:"k,omitempty"`
		Path        string                     `json:"path"`
		FileType    string                     `json:"type"`
		SHA256      string                     `json:"sha"`
		Formula     string                     `json:"mol,omitempty"`
		OldFormula  string                     `json:"f,omitempty"`
		Facts       cleaveFacts                `json:"fact,omitzero"`
		OldFacts    cleaveFacts                `json:"ff,omitzero"`
		Exports     []symbolInfo               `json:"exports,omitempty"`
		Findings    []finding                  `json:"find,omitempty"`
		OldFindings []finding                  `json:"ts,omitempty"`
		Ctx         []contextWindow            `json:"ctx,omitempty"`
		Strings     []json.RawMessage          `json:"ss,omitempty"`
		Imports     []string                   `json:"is,omitempty"`
		Sections    []sectionInfo              `json:"sections,omitempty"`
		Metrics     json.RawMessage            `json:"ms,omitempty"`
		Size        int64                      `json:"size"`
		OldSize     int64                      `json:"sz"`
		ID          int                        `json:"id"`
		Depth       int                        `json:"dp"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*f = cleaveFile{
		KV:       raw.KV,
		Path:     raw.Path,
		FileType: raw.FileType,
		SHA256:   raw.SHA256,
		Formula:  raw.Formula,
		Facts:    raw.Facts,
		Exports:  raw.Exports,
		Findings: raw.Findings,
		Ctx:      raw.Ctx,
		Strings:  raw.Strings,
		Imports:  raw.Imports,
		Sections: raw.Sections,
		Metrics:  raw.Metrics,
		Size:     raw.Size,
		ID:       raw.ID,
		Depth:    raw.Depth,
	}
	if f.Formula == "" {
		f.Formula = raw.OldFormula
	}
	if len(f.Facts.Metrics) == 0 && f.Facts.KV == nil && len(f.Facts.Strings) == 0 && len(f.Facts.Imports) == 0 && len(f.Facts.Exports) == 0 && len(f.Facts.Functions) == 0 && len(f.Facts.Sections) == 0 {
		f.Facts = raw.OldFacts
	}
	if len(f.Findings) == 0 {
		f.Findings = raw.OldFindings
	}
	if f.Size == 0 {
		f.Size = raw.OldSize
	}
	f.applyFacts()
	return nil
}

func (f *cleaveFile) applyFacts() {
	if len(f.Metrics) == 0 && len(f.Facts.Metrics) > 0 {
		f.Metrics = f.Facts.Metrics
	}
	if len(f.KV) == 0 && len(f.Facts.KV) > 0 {
		f.KV = f.Facts.KV
	}
	if len(f.Strings) == 0 && len(f.Facts.Strings) > 0 {
		f.Strings = f.Facts.Strings
	}
	if len(f.Imports) == 0 && len(f.Facts.Imports) > 0 {
		f.Imports = compactImports(f.Facts.Imports)
	}
	if len(f.Exports) == 0 && len(f.Facts.Exports) > 0 {
		f.Exports = compactExports(f.Facts.Exports)
	}
	if len(f.Sections) == 0 && len(f.Facts.Sections) > 0 {
		f.Sections = compactSections(f.Facts.Sections)
	}
}

func compactImports(raw []json.RawMessage) []string {
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		var tuple []json.RawMessage
		if json.Unmarshal(item, &tuple) != nil || len(tuple) == 0 {
			continue
		}
		if len(tuple) == 1 {
			var name string
			_ = json.Unmarshal(tuple[0], &name) //nolint:errcheck // best-effort display field
			if name != "" {
				out = append(out, name)
			}
			continue
		}
		var lib, name string
		_ = json.Unmarshal(tuple[0], &lib)  //nolint:errcheck // best-effort display field
		_ = json.Unmarshal(tuple[1], &name) //nolint:errcheck // best-effort display field
		switch {
		case lib != "" && name != "":
			out = append(out, lib+"!"+name)
		case name != "":
			out = append(out, name)
		case lib != "":
			out = append(out, lib)
		}
	}
	return out
}

func compactExports(raw []json.RawMessage) []symbolInfo {
	out := make([]symbolInfo, 0, len(raw))
	for _, item := range raw {
		var tuple []json.RawMessage
		if json.Unmarshal(item, &tuple) != nil || len(tuple) == 0 {
			continue
		}
		var name, forward string
		_ = json.Unmarshal(tuple[0], &name) //nolint:errcheck // best-effort display field
		if len(tuple) > 1 {
			_ = json.Unmarshal(tuple[1], &forward) //nolint:errcheck // best-effort display field
		}
		if name != "" {
			out = append(out, symbolInfo{Symbol: name, Library: forward})
		}
	}
	return out
}

func compactSections(raw []json.RawMessage) []sectionInfo {
	out := make([]sectionInfo, 0, len(raw))
	for _, item := range raw {
		var tuple []json.RawMessage
		if json.Unmarshal(item, &tuple) != nil || len(tuple) < 3 {
			continue
		}
		var name, flags string
		var offset uint64
		var size int64
		var entropy float64
		_ = json.Unmarshal(tuple[0], &name)   //nolint:errcheck // best-effort display field
		_ = json.Unmarshal(tuple[1], &offset) //nolint:errcheck // best-effort display field
		_ = json.Unmarshal(tuple[2], &size)   //nolint:errcheck // best-effort display field
		if len(tuple) > 3 {
			_ = json.Unmarshal(tuple[3], &entropy) //nolint:errcheck // best-effort display field
		}
		if len(tuple) > 4 {
			_ = json.Unmarshal(tuple[4], &flags) //nolint:errcheck // best-effort display field
		}
		out = append(out, sectionInfo{Name: name, Offset: &offset, Size: size, Entropy: entropy, Flags: flags})
	}
	return out
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

// contextWindow is one entry in a file's `ctx` array. Two wire formats coexist:
//
//   - Legacy: a pre-rendered slice of file content in Text ("t") at byte offset
//     Offset, with Hex marking a hex dump. Notes name the traits that matched.
//   - Current (cleave rc.6+): one entry per source line or hex unit, carrying
//     the raw matched bytes in Data (Z85-decoded from "b") with Addr ("a") the
//     byte start of a source line's content. Offset ("l") is then a 1-based line
//     number (source) or a byte offset (hex/minified). The richer File and
//     per-trait context views render from this; legacy Text is the fallback.
//
// Data is non-nil exactly when the entry used the current format, so it is the
// flag the renderer keys on.
type contextWindow struct {
	Text   string        `json:"t"`
	Notes  []contextNote `json:"n,omitempty"`
	Offset int64         `json:"l"`
	Hex    bool          `json:"x,omitempty"`
	Addr   *int64        `json:"-"`
	Data   []byte        `json:"-"`
}

func (w *contextWindow) UnmarshalJSON(data []byte) error {
	var raw struct {
		Text   string        `json:"t"`
		Bytes  string        `json:"b"`
		Notes  []contextNote `json:"n"`
		Offset int64         `json:"l"`
		Addr   *int64        `json:"a"`
		Hex    bool          `json:"x"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*w = contextWindow{Text: raw.Text, Notes: raw.Notes, Offset: raw.Offset, Hex: raw.Hex, Addr: raw.Addr}
	if raw.Bytes != "" {
		decoded, err := z85Decode(raw.Bytes)
		if err != nil {
			return fmt.Errorf("ctx window z85: %w", err)
		}
		w.Data = decoded
	}
	return nil
}

// contextNote attributes a span of a contextWindow to a single trait by its
// full ID. Offset/Size locate the match within the window.
type contextNote struct {
	ID     string `json:"i"`
	Desc   string `json:"d,omitempty"`
	Offset int64  `json:"o"`
	Crit   int    `json:"c,omitempty"`
	Size   int    `json:"z,omitempty"`
}

type finding struct {
	ID   string `json:"id"`
	Desc string `json:"desc,omitempty"`
	// Evidence values (cleave's compact `ev`). Parallel to Locations when
	// the latter is non-empty; same index = same match.
	Evidence []string `json:"ev,omitempty"`
	// Locations is cleave's compact `loc` — one entry per Evidence item,
	// or empty when the finding was never rolled up through an archive
	// member. Archive-attributed entries look like
	// "archive:<member-path>", with optional "!" nesting for archives
	// inside archives. Used by aggregateArchiveCategories to point the
	// user at the inner file a container-level trait actually matched.
	Locations []string `json:"loc,omitempty"`
	// Src is the origin member's files[] index when this finding was inherited
	// from an embedded file; nil when the finding is native to this file. The
	// archive (top-level) view shows only native findings — inherited ones are
	// rendered within the member that actually produced them.
	Src *int `json:"src,omitempty"`
	// Sources lists the archive members a cross-file composite fired on, each
	// with the component's anchor. Non-empty marks a composite; the File view
	// links each entry to the member's own section.
	Sources []compactSource `json:"srcs,omitempty"`
	Crit    int             `json:"crit"`
	Conf    float64         `json:"conf,omitempty"`
}

// compactSource is one member a cross-file composite drew from: the member's
// files[] id and the component match's line/offset, when known.
type compactSource struct {
	Line   *int64 `json:"ln,omitempty"`
	Offset *int64 `json:"o,omitempty"`
	File   int    `json:"f"`
}

func (f *finding) UnmarshalJSON(data []byte) error {
	var raw struct {
		ID           string          `json:"id"`
		OldID        string          `json:"i"`
		Desc         string          `json:"desc,omitempty"`
		OldDesc      string          `json:"d,omitempty"`
		Evidence     []string        `json:"ev,omitempty"`
		OldEvidence  []string        `json:"e,omitempty"`
		Locations    []string        `json:"loc,omitempty"`
		OldLocations []string        `json:"el,omitempty"`
		Src          *int            `json:"src,omitempty"`
		Sources      []compactSource `json:"srcs,omitempty"`
		Crit         int             `json:"crit"`
		OldCrit      int             `json:"l"`
		Conf         float64         `json:"conf,omitempty"`
		OldConf      float64         `json:"c,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	f.Src = raw.Src
	f.Sources = raw.Sources
	f.ID = raw.ID
	if f.ID == "" {
		f.ID = raw.OldID
	}
	f.Desc = raw.Desc
	if f.Desc == "" {
		f.Desc = raw.OldDesc
	}
	f.Evidence = raw.Evidence
	if len(f.Evidence) == 0 {
		f.Evidence = raw.OldEvidence
	}
	f.Locations = raw.Locations
	if len(f.Locations) == 0 {
		f.Locations = raw.OldLocations
	}
	f.Crit = raw.Crit
	if f.Crit == 0 {
		f.Crit = raw.OldCrit
	}
	f.Conf = raw.Conf
	if f.Conf == 0 {
		f.Conf = raw.OldConf
	}
	return nil
}

//nolint:maintidx,gocognit // main is inherently complex: flag parsing, config, template init, server setup
func main() {
	// Initialize structured logger with JSON output for production. Tee
	// through obs so records also reach OTLP/Loki without touching the
	// existing stdout-JSON contract container log collectors rely on.
	baseHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})

	ctx, cancelApp := context.WithCancel(context.Background())
	obsShutdown, err := obs.Init(ctx, obs.Config{ServiceName: "prism", DisableSlog: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "obs init: %v\n", err) //nolint:forbidigo // pre-logger startup error
		os.Exit(1)
	}
	logger = slog.New(obs.TeeSlog(baseHandler, "prism"))
	slog.SetDefault(logger)

	// Parse command-line flags via the stdlib flag package. Single-dash and
	// double-dash forms are both accepted (flag package treats `--foo` as
	// `-foo`), with `-flag=value` and `-flag value` both supported.
	var (
		noCache bool
		dbDSN   string
		port    string
	)
	cli := flag.NewFlagSet("prism", flag.ExitOnError)
	cli.BoolVar(&noCache, "no-cache", false, "disable persistent caching (in-memory only)")
	cli.BoolVar(&publicMode, "public", false, "public-deployment mode: atomdrift lab branding and Secure cookies")
	cli.BoolVar(&uploadEnabled, "uploads", uploadEnabled, "enable browser uploads via POST /upload (also reads PRISM_UPLOADS env, set to 1/true to enable)")
	cli.StringVar(&dbDSN, "db", "", "hopper postgres DSN (overrides HOPPER_DSN / FALLOUT_DB env)")
	cli.StringVar(&port, "port", "", "HTTP listen port (overrides PORT env)")
	cli.StringVar(&hopperAPIAddr, "hopper-api-addr", hopperAPIAddr, "hopper API host:port")
	cli.StringVar(&litmusAddr, "litmus", litmusAddr, "litmus analysis server host:port (also reads LITMUS_ADDR env; empty disables, falling back to hopper-only analysis)")
	if err := cli.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	// Env-var fallback so the rc.d script can flip uploads without
	// shipping a new binary. CLI flag wins if both are set.
	uploadsFlagSet := false
	cli.Visit(func(f *flag.Flag) {
		if f.Name == "uploads" {
			uploadsFlagSet = true
		}
	})
	if !uploadsFlagSet {
		if v := os.Getenv("PRISM_UPLOADS"); v != "" {
			switch strings.ToLower(v) {
			case "1", "true", "yes", "on":
				uploadEnabled = true
			case "0", "false", "no", "off":
				uploadEnabled = false
			}
		}
	}

	if dbDSN == "" {
		dbDSN = os.Getenv("HOPPER_DSN")
	}
	if dbDSN == "" {
		dbDSN = os.Getenv("FALLOUT_DB")
	}
	if dbDSN == "" {
		dbDSN = defaultHopperDSN
	}

	if port == "" {
		port = os.Getenv("PORT")
	}
	if port == "" {
		port = "8080"
	}

	logger.Info("prism starting",
		"go_version", runtime.Version(),
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
		"pid", os.Getpid(),
		"public_mode", publicMode,
	)

	// Load configuration from environment
	loadConfig()

	// Initialize fido caches. See doc.go for the cache discipline.
	if noCache {
		logger.Info("cache disabled via --no-cache flag, using null stores")
		cache = openNullCache[storedResult]("result cache")
		feedCache = openNullCache[cachedFeedSnapshot]("feed cache")
		reportCache = openNullCache[cachedReport]("report cache")
		parentArchiveCache = openNullCache[cachedParents]("parent-archive cache")
	} else {
		cacheDir := os.Getenv("CACHE_DIR")
		if cacheDir == "" {
			userCache, err := os.UserCacheDir()
			if err != nil {
				logger.Error("failed to get user cache dir", "error", err)
				os.Exit(1)
			}
			cacheDir = filepath.Join(userCache, "prism")
		}
		logger.Info("initializing localfs caches", "dir", cacheDir)
		cache = openLocalFSCache[storedResult]("prism", cacheDir, "result cache")
		// feedCache is intentionally memory-only even when localfs is enabled.
		// Its key includes the free-text ?q= and formula filters, so a caller
		// can mint unlimited distinct keys; the localfs tier has no size cap
		// and no active eviction (only lazy per-read expiry), so persisting
		// those would let GET /?q=<random> fill the cache dir — tmpfs/RAM on
		// Cloud Run — and OOM the instance. The bounded, scan-resistant
		// in-memory tier caps growth instead; singleflight still protects
		// hopper, the precache loop keeps hot variants warm, and a feed
		// snapshot is cheap to rebuild after a restart. The per-SHA caches
		// below stay on disk: their keys are bounded by real data.
		feedCache = openNullCache[cachedFeedSnapshot]("feed cache")
		reportCache = openLocalFSCache[cachedReport]("prism-report", cacheDir, "report cache")
		parentArchiveCache = openLocalFSCache[cachedParents]("prism-parents", cacheDir, "parent-archive cache")
	}

	// Parse templates. isPublic is available in all templates so base.html
	// can switch branding and banners without per-handler plumbing.
	funcs := template.FuncMap{
		"isPublic":         func() bool { return publicMode },
		"buildCommit":      func() string { return buildCommit },
		"buildCommitShort": shortBuildCommit,
		"mul":              func(a, b float64) float64 { return a * b },
		"formulaQuery":     desubscriptFormula,
		// deref unwraps an optional int so templates can compare it: html/template's
		// eq/ne operate on basic kinds only and error on a raw *int, which aborts
		// rendering mid-page. A nil pointer reads as 0 (no caller relies on that case).
		"deref": func(p *int) int {
			if p == nil {
				return 0
			}
			return *p
		},
		"ecoColor":  ecosystemColor,
		"chromaCSS": func() template.CSS { return chromaStylesheet },
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
	helpQueryTemplate, tmplErr = template.New("help-query.html").Funcs(funcs).ParseFS(templatesFS, "templates/base.html", "templates/help-query.html")
	if tmplErr != nil {
		logger.Error("template loading failed", "error", tmplErr)
		os.Exit(1)
	}
	pendingTemplate, tmplErr = template.New("pending.html").Funcs(funcs).ParseFS(templatesFS, "templates/base.html", "templates/pending.html")
	if tmplErr != nil {
		logger.Error("template loading failed", "error", tmplErr)
		os.Exit(1)
	}

	// Connect to hopper sample registry. Explicit --db, HOPPER_DSN, and
	// FALLOUT_DB override the local hopper default. If the first attempt
	// fails (hopper-db is still starting, network blip, etc.) we keep
	// serving cached results and reconnect in the background — operators
	// shouldn't have to restart prism to recover.
	if dbDSN != "" {
		hopperDBDSN = dbDSN
		db, err := hopper.Open(context.Background(), dbDSN)
		if err != nil {
			logger.Error("failed to connect to hopper",
				"error", err,
				"hopper_db_host", hopperDSNHost(dbDSN),
			)
			go connectHopperWithRetry(ctx)
		} else {
			hopperDB.Store(db)
			logger.Info("hopper connected", "hopper_db_host", hopperDSNHost(dbDSN))
			if err := obs.PoolStats("prism", db.Pool()); err != nil {
				logger.Warn("pool stats registration", "error", err)
			}
			go refreshFeedCacheLoop(ctx)
		}
	}

	mux := newMux()

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           obs.Middleware(requestLogger(securityHeaders(mux))),
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
		cancelApp()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}

		if cache != nil {
			if err := cache.Close(); err != nil {
				logger.Error("failed to close fido cache", "error", err)
			}
		}
		if feedCache != nil {
			if err := feedCache.Close(); err != nil {
				logger.Error("failed to close fido feed cache", "error", err)
			}
		}
		if reportCache != nil {
			if err := reportCache.Close(); err != nil {
				logger.Error("failed to close fido report cache", "error", err)
			}
		}
		if parentArchiveCache != nil {
			if err := parentArchiveCache.Close(); err != nil {
				logger.Error("failed to close fido parent-archive cache", "error", err)
			}
		}

		// Flush OTel exporters last so the shutdown logs/spans go out.
		if err := obsShutdown(shutdownCtx); err != nil {
			logger.Warn("obs shutdown", "error", err)
		}

		close(done)
	}()

	logger.Info("server starting",
		"port", port,
		"hopper_api_addr", hopperAPIAddr,
	)

	// SO_REUSEPORT(_LB) on the listening socket so the deploy rollout
	// can start the new prism alongside the old one — see
	// hacks/rollout-bastille.sh. The kernel routes new connections to
	// whichever process is up; we SIGTERM the predecessor only after
	// the new one is verified accepting.
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var inner error
			if err := c.Control(func(fd uintptr) {
				inner = setReusePort(fd)
			}); err != nil {
				return err
			}
			return inner
		},
	}
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
	// Force the MIME types we serve. Some hosts (FreeBSD jails, minimal
	// containers) ship a /etc/mime.types that maps .js to text/plain, which
	// causes the browser to refuse ES module loads with a "disallowed MIME
	// type" error. AddExtensionType wins over the system file because it's
	// applied to the runtime registry after mime.init().
	for ext, ctype := range map[string]string{
		".js":    "application/javascript",
		".mjs":   "application/javascript",
		".css":   "text/css; charset=utf-8",
		".json":  "application/json; charset=utf-8",
		".woff2": "font/woff2",
		".webp":  "image/webp",
		".svg":   "image/svg+xml",
	} {
		if err := mime.AddExtensionType(ext, ctype); err != nil {
			logger.Warn("mime registration failed", "ext", ext, "error", err)
		}
	}

	mux := http.NewServeMux()
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err) // impossible: embedded FS is always valid
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheStatic(http.FileServer(http.FS(staticContent)))))
	mux.HandleFunc("GET /{$}", handleIndex)
	mux.HandleFunc("POST /upload", handleUpload)
	mux.HandleFunc("GET /file/{sha256}", handleFile)
	mux.HandleFunc("GET /file/{sha256}/wait", handleFileWait)
	mux.HandleFunc("GET /file/{sha256}/status", handleFileStatus)
	mux.HandleFunc("POST /file/{sha256}/rescan", handleRescan)
	mux.HandleFunc("GET /formats", handleFormats)
	mux.HandleFunc("GET /powered-by", handlePoweredBy)
	mux.HandleFunc("GET /help/query", handleHelpQuery)
	mux.HandleFunc("GET /_/health", handleHealth)
	mux.Handle("GET /_/metrik", obs.MetricsHandler())
	mux.HandleFunc("GET /{ecosystem}", handleEcosystemRedirect)
	mux.HandleFunc("GET /{ecosystem}/", handleEcosystem)
	return mux
}

// loadConfig loads configuration from environment variables.
func loadConfig() {
	if hopperAPIAddr == "" {
		hopperAPIAddr = os.Getenv("HOPPER_API_ADDR")
	}
	if hopperAPIAddr == "" {
		hopperAPIAddr = defaultHopperAPIAddr
	}
	// 5-minute timeout covers a worst-case 100 MB upload over a slow
	// link plus hopper's local fsync + DB insert. Reads from /api/file
	// and similar smaller fetches finish well inside this budget.
	hopperClient = &http.Client{
		Timeout: 5 * time.Minute,
	}

	// litmus analysis server. Precedence: flag > LITMUS_ADDR env > default.
	// An explicit "off"/"none"/"disabled" turns the integration off so uploads
	// fall back to hopper-only analysis.
	if litmusAddr == "" {
		litmusAddr = os.Getenv("LITMUS_ADDR")
	}
	switch strings.ToLower(strings.TrimSpace(litmusAddr)) {
	case "":
		litmusAddr = defaultLitmusAddr
	case "off", "none", "disabled":
		litmusAddr = ""
	}
	// The litmus analyze can run the full ingest budget; give the client a
	// slightly longer backstop so the context deadline fires first.
	litmusClient = &http.Client{
		Timeout: uploadIngestTimeout + time.Minute,
	}

	csrfKey = loadCSRFKey()

	logger.Debug("configuration loaded",
		"HOPPER_API_ADDR", hopperAPIAddr,
		"LITMUS_ADDR", litmusAddr,
		"PORT", os.Getenv("PORT"),
	)
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

// Flush forwards to the underlying ResponseWriter's Flusher if it has one.
// Needed by the SSE wait endpoint: wrapping an http.ResponseWriter hides
// the embedded interface implementations behind the wrapper's method set,
// so without this forward the cast `w.(http.Flusher)` in handleFileWait
// would fail and the stream would never push events.
func (sr *statusRecorder) Flush() {
	if f, ok := sr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
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
		if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/_/health" || r.URL.Path == "/_/metrik" {
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

		// Generate separate per-request nonces for <script> and <style>
		// so a leak in one channel doesn't authorize the other.
		scriptNonce, err := newCSPNonce()
		if err != nil {
			logger.Error("failed to generate script CSP nonce", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		styleNonce, err := newCSPNonce()
		if err != nil {
			logger.Error("failed to generate style CSP nonce", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'nonce-"+scriptNonce+"'; "+
				"script-src-elem 'self' 'nonce-"+scriptNonce+"'; "+
				"style-src 'self' 'nonce-"+styleNonce+"'; "+
				"font-src 'self'; "+
				"img-src 'self'; "+
				"connect-src 'self'; "+
				"worker-src 'self'; "+
				"frame-src 'none'; "+
				"frame-ancestors 'none'; "+
				"object-src 'none'; "+
				"base-uri 'self'; "+
				"form-action 'self'")

		// HSTS: safe for self-hosters behind any TLS termination.
		// Browsers ignore this header on plain HTTP, so no harm when running locally.
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

		ctx := context.WithValue(r.Context(), scriptNonceKey, scriptNonce)
		ctx = context.WithValue(ctx, styleNonceKey, styleNonce)
		r = ensureCSRFCookie(w, r.WithContext(ctx))
		next.ServeHTTP(w, r)
	})
}

func newCSPNonce() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(buf[:]), nil
}

func nonceFor(r *http.Request) string {
	if v, ok := r.Context().Value(scriptNonceKey).(string); ok {
		return v
	}
	return ""
}

func styleNonceFor(r *http.Request) string {
	if v, ok := r.Context().Value(styleNonceKey).(string); ok {
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
	Nonce      string // script-src nonce
	StyleNonce string // style-src nonce
	Icon       string
	Title      string
	// Message is the plain-text error body shown to the user. It is rendered
	// through html/template auto-escaping, so it is safe to populate from
	// any source. When a known-safe link or markup is required, use the
	// separate MessageHTML field instead — keeping the two channels distinct
	// makes accidental XSS via a future edit much harder.
	Message string
	// MessageHTML is rendered without escaping. Only assign string literals
	// or values constructed exclusively from string literals. Never pass
	// user-controlled bytes here.
	MessageHTML template.HTML
	Detail      string
	Action      string
	ShowBeaker  bool
}

func renderError(w http.ResponseWriter, r *http.Request, status int, data errorData) {
	logger.Debug("rendering error page",
		"status", status,
		"title", data.Title,
		"path", r.URL.Path,
		"client_ip", clientIP(r),
	)
	data.Nonce = nonceFor(r)
	data.StyleNonce = styleNonceFor(r)
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

// feedPageSize is how many rows render on a single feed page. feedLimit is
// the total pulled in one cached hopper query (feedPages × feedPageSize), so
// paging is a pure in-memory slice of the cached snapshot — every page after
// the first serves from cache with no extra query.
const (
	feedPageSize = 100
	feedPages    = 5
	feedLimit    = feedPageSize * feedPages
)

// feedEcosystemWindow bounds the ecosystem dropdown to ecosystems seen
// recently. Hopper emits the occasional non-canonical ecosystem (file
// extensions, OS version strings); gating on recency keeps the dropdown to
// what's actively flowing through the feed without a hardcoded allowlist.
const feedEcosystemWindow = 72 * time.Hour

// feedQueryArgs bundles the filter knobs that flow through the feed
// pipeline. Bundling avoids a long parameter pile and keeps the cache
// key + handler in step when a new dimension is added.
type feedQueryArgs struct {
	ecosystem   string
	domain      string
	criticality string
	formula     string
	// search is the free-text filter behind ?q=: case-insensitive filename
	// substring OR exact sha256, applied as a hopper SQL predicate (not an
	// in-memory pass) so it spans the whole index rather than the cached page.
	// (A full sha pasted into the box is caught earlier and redirected to the
	// file page; this equality is the no-JS / belt-and-suspenders path.)
	search string
	// feedsOnly toggles the "malware feeds" view: only label='bad'
	// samples (curated threat-intel / open-source malware sources) are
	// returned, and the table picks up a Feed column.
	feedsOnly bool
}

// feedCacheKey produces a deterministic cache key from the feed-query
// dimensions. Stable across reorderings (so swapping field order can't
// silently fragment the cache) and never empty. Version-prefixed so the
// next schema change can invalidate the whole on-disk set.
func feedCacheKey(a feedQueryArgs) string {
	feeds := "0"
	if a.feedsOnly {
		feeds = "1"
	}
	return "feed-v5:eco=" + a.ecosystem + ":dom=" + a.domain +
		":crit=" + a.criticality + ":formula=" + a.formula + ":feeds=" + feeds +
		":q=" + a.search
}

// loadFeedSnapshot fetches a feed page, caching every query for feedCacheTTL.
// All concurrent requests for the same filter set share one hopper round-
// trip via fido's built-in singleflight. Pre-cached variants (default +
// criticality) stay hot via feedPrecacheLoop so high-traffic views never
// hit a cold loader on the request path. The returned queryDiag reports
// whether the data came from cache, how long the fetch took, the snapshot's
// age, and its row/byte counts.
func loadFeedSnapshot(ctx context.Context, a feedQueryArgs, reqLogger *slog.Logger, bypass bool) (cachedFeedSnapshot, queryDiag, error) {
	feedPopular.record(a) // learn which views to keep hot
	start := time.Now()
	diag := queryDiag{Name: "index", Source: "postgres", Params: feedDiagParams(a)}
	var snapshot cachedFeedSnapshot
	var err error
	if feedCache == nil {
		snapshot, err = buildFeedSnapshot(ctx, a, reqLogger)
	} else {
		// A hard refresh drops the cached entry first so FetchTTL rebuilds it
		// live and repopulates the cache for the next visitor.
		if bypass {
			if delErr := feedCache.Delete(ctx, feedCacheKey(a)); delErr != nil {
				reqLogger.Debug("hard refresh: feed cache invalidation failed", "error", delErr)
			}
		}
		fromCache := true
		snapshot, err = feedCache.FetchTTL(ctx, feedCacheKey(a), feedCacheTTL, func(lctx context.Context) (cachedFeedSnapshot, error) {
			fromCache = false
			return buildFeedSnapshot(lctx, a, reqLogger)
		})
		if fromCache {
			diag.Source = "cache"
		}
	}
	if err != nil {
		return cachedFeedSnapshot{}, diag, err
	}
	diag.Duration = time.Since(start).Round(time.Microsecond).String()
	diag.Age = time.Since(snapshot.GeneratedAt).Round(time.Second).String()
	diag.Rows = len(snapshot.Rows)
	diag.Bytes = snapshot.Bytes
	return snapshot, diag, nil
}

// feedDiagParams renders the cache-key dimensions of a feed query into a
// compact comma-separated string for the diagnostics comment. Empty ecosystem
// and criticality read as "any"; the rarer filters appear only when set.
func feedDiagParams(a feedQueryArgs) string {
	parts := []string{
		"ecosystem=" + firstNonEmpty(diagSafe(a.ecosystem), "any"),
		"crit=" + firstNonEmpty(diagSafe(a.criticality), "any"),
	}
	if a.domain != "" {
		parts = append(parts, "domain="+diagSafe(a.domain))
	}
	if a.formula != "" {
		parts = append(parts, "formula="+diagSafe(a.formula))
	}
	if a.feedsOnly {
		parts = append(parts, "feeds=1")
	}
	return strings.Join(parts, ",")
}

// diagSafe reduces a request-derived value to plain ASCII alphanumerics
// (capped at 256 bytes) so it cannot break out of the HTML comment the
// diagnostics are written into. Anything else is dropped — the diagnostics
// don't need punctuation, and dropping it removes any injection surface.
func diagSafe(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 256; i++ {
		if c := s[i]; c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// buildFeedSnapshot runs the live hopper queries and packages the result
// into a cache-friendly snapshot (stable raw fields, no rendered relative-
// time strings — those re-derive at request time from CreatedAt).
func buildFeedSnapshot(ctx context.Context, a feedQueryArgs, reqLogger *slog.Logger) (cachedFeedSnapshot, error) {
	rows, ecosystems, domains, total, err := loadFeedRowsFromHopper(ctx, a, reqLogger)
	if err != nil {
		return cachedFeedSnapshot{}, err
	}
	snap := cachedFeedSnapshot{
		GeneratedAt: time.Now(),
		Rows:        cachedFeedSamplesFromRows(rows),
		Ecosystems:  ecosystems,
		Domains:     domains,
		TotalCount:  total,
	}
	if encoded, err := json.Marshal(snap); err == nil {
		snap.Bytes = len(encoded)
	}
	return snap, nil
}

func loadFeedRowsFromHopper(ctx context.Context, args feedQueryArgs, reqLogger *slog.Logger) (rows []feedRow, ecosystems, domains []string, total int, err error) {
	db := hopperDB.Load()
	if db == nil {
		return nil, nil, nil, 0, errors.New("hopper not connected")
	}
	// Source="" spans every Source value (legacy "harvest" rows from
	// before the rename, new "forager" rows, manual "upload"s) so the
	// dropdowns and the result set both work across the transition.
	ecosystems, err = db.FeedEcosystems(ctx, "", "", time.Now().Add(-feedEcosystemWindow))
	if err != nil {
		return nil, nil, nil, 0, err
	}
	domains, err = db.FeedDomains(ctx, "", "")
	if err != nil {
		return nil, nil, nil, 0, err
	}

	q := hopper.FeedQuery{
		OrderBy:       "created_at",
		Formula:       args.formula,
		Search:        args.search,
		TopLevelOnly:  true,
		Limit:         feedLimit,
		CriticalLevel: CriticalLevel,
	}
	if args.ecosystem != "" {
		q.Ecosystems = []string{args.ecosystem}
	}
	if args.domain != "" {
		q.Domains = []string{args.domain}
	}
	if classes, ok := criticalityClasses(args.criticality); ok {
		q.LitmusClasses = classes
	} else {
		q.RequireLitmus = true
	}
	if args.feedsOnly {
		// Forager tags every sample it pulls from a threat-intel feed
		// as `label='bad'` (see forager/db.go canonicalLabel). Filtering
		// on label here gives us the union of all such feeds without
		// having to enumerate the feed names by hand.
		q.Label = "bad"
	}

	samples, err := db.FeedSamples(ctx, &q)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	total, err = db.FeedSamplesCount(ctx, &q)
	if err != nil {
		return nil, nil, nil, 0, err
	}

	rows = make([]feedRow, 0, len(samples))
	now := time.Now()
	for _, sample := range samples {
		res, err := cachedResultForSample(ctx, sample, reqLogger)
		if err != nil {
			reqLogger.Debug("feed cache unavailable, rendering hopper sample directly", "sha256", sample.SHA256, "error", err)
			fresh, ferr := storedResultFromHopperSample(sample)
			if ferr != nil {
				reqLogger.Debug("hopper sample fallback failed", "sha256", sample.SHA256, "error", ferr)
				continue
			}
			res = fresh
		}
		classification := res.Classification
		if classification == "" {
			continue
		}
		// Belt-and-suspenders check that the row's class falls into the
		// requested set even after hopper's SQL filter. The criticality
		// argument may be a named band ("hostile") or a comparison
		// expression (">=1") — both go through criticalityClasses so we
		// compare against the same set the SQL filter used.
		if args.criticality != "" {
			classes, ok := criticalityClasses(args.criticality)
			if !ok {
				continue
			}
			rowClass, ok := classificationClass(classification)
			if !ok || !slices.Contains(classes, rowClass) {
				continue
			}
		}
		if args.formula != "" && firstNonEmpty(res.Formula, sample.Formula) != args.formula {
			continue
		}

		addedAt := sample.CreatedAt
		suspiciousT, hostileT := sampleThresholds(sample)
		rows = append(rows, feedRow{
			SHA256:         sample.SHA256,
			SHA256Short:    shortSHA(sample.SHA256),
			Filename:       firstNonEmpty(res.Filename, sample.Filename, filepath.Base(sample.Path)),
			Classification: classification,
			Probability:    sample.LitmusScore,
			SuspiciousT:    suspiciousT,
			HostileT:       hostileT,
			Formula:        res.Formula,
			FileType:       firstNonEmpty(res.FileType, sample.FileType),
			Source:         sample.Source,
			Feed:           sample.Feed,
			Ecosystem:      sample.Ecosystem,
			EcosystemURL:   ecosystemURL(sample.Ecosystem),
			AnalyzedAt:     addedAt,
			AnalyzedDate:   feedDate(addedAt, now),
			TimeAgo:        timeAgo(now.Sub(addedAt)),
		})
	}

	return rows, ecosystems, domains, total, nil
}

func feedRowsFromSnapshot(snapshot cachedFeedSnapshot) []feedRow {
	rows := make([]feedRow, 0, len(snapshot.Rows))
	now := time.Now()
	for i := range snapshot.Rows {
		sample := &snapshot.Rows[i]
		rows = append(rows, feedRow{
			SHA256:         sample.SHA256,
			SHA256Short:    shortSHA(sample.SHA256),
			Filename:       sample.Filename,
			Classification: sample.Classification,
			Probability:    sample.Probability,
			SuspiciousT:    sample.SuspiciousT,
			HostileT:       sample.HostileT,
			Formula:        sample.Formula,
			FileType:       sample.FileType,
			Source:         sample.Source,
			Feed:           sample.Feed,
			Ecosystem:      sample.Ecosystem,
			EcosystemURL:   ecosystemURL(sample.Ecosystem),
			AnalyzedAt:     sample.CreatedAt,
			AnalyzedDate:   feedDate(sample.CreatedAt, now),
			TimeAgo:        timeAgo(now.Sub(sample.CreatedAt)),
		})
	}
	return rows
}

// feedStaticPrecacheEcosystems is the baseline set of ecosystem feeds the static
// tier keeps warm regardless of traffic — the high-volume language ecosystems,
// so their landing pages are never cold for a first visitor. Lower-traffic
// ecosystems rely on the hot tier (once visited) and the on-demand cache.
var feedStaticPrecacheEcosystems = []string{
	"javascript", "python", "ruby", "rust", "go", "java", "php",
}

// feedPrecacheVariants enumerates the baseline feed views the static tier sweeps:
// the unfiltered frontpage, the criticality views, the feeds-only view, and the
// per-ecosystem default for each static ecosystem. The hot tier adds whatever
// pivots real traffic favors; everything else is cached on demand.
var feedPrecacheVariants = func() []feedQueryArgs {
	v := []feedQueryArgs{
		{},
		{criticality: "hostile"},
		{criticality: "suspicious"},
		{criticality: ">=1"},
		{criticality: "benign"},
		{feedsOnly: true},
	}
	for _, eco := range feedStaticPrecacheEcosystems {
		v = append(v, feedQueryArgs{ecosystem: eco})
	}
	return v
}()

// refreshFeedCacheLoop runs the two-tier feed pre-cache: a hot loop that keeps
// the most-visited views fresh, and a static loop that sweeps the baseline set.
// It is the single entry point launched at startup; each tier runs in its own
// goroutine so a slow sweep in one can't stall the other.
func refreshFeedCacheLoop(ctx context.Context) {
	if feedCache == nil {
		return
	}
	go feedHotPrecacheLoop(ctx)
	feedStaticPrecacheLoop(ctx)
}

// feedStaticPrecacheLoop sweeps feedPrecacheVariants — the frontpage, the
// criticality views, and the static ecosystem list — every
// feedStaticPrecacheInterval, refreshing any entry older than that. Runs once
// immediately so the baseline is warm at startup.
func feedStaticPrecacheLoop(ctx context.Context) {
	sweep := func() {
		for _, v := range feedPrecacheVariants {
			if err := refreshFeedCacheEntry(ctx, v, feedStaticPrecacheInterval); err != nil {
				logger.Warn("feed static pre-cache refresh failed", "key", feedCacheKey(v), "error", err)
			}
		}
	}
	sweep()
	ticker := time.NewTicker(feedStaticPrecacheInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// feedHotPrecacheLoop refreshes the top feedHotPrecacheCount most-requested
// structured pivots every feedHotPrecacheInterval. It waits for the first tick
// rather than running immediately — there is no traffic to rank at startup, and
// the static loop already warms the baseline.
func feedHotPrecacheLoop(ctx context.Context) {
	ticker := time.NewTicker(feedHotPrecacheInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, v := range feedPopular.top(feedHotPrecacheCount) {
				if err := refreshFeedCacheEntry(ctx, v, feedHotPrecacheInterval); err != nil {
					logger.Warn("feed hot pre-cache refresh failed", "key", feedCacheKey(v), "error", err)
				}
			}
		}
	}
}

// refreshFeedCacheEntry no-ops when the cached entry is younger than maxAge —
// the tier's refresh interval — so the hot and static loops don't rebuild a key
// the other just warmed. Otherwise it runs the live hopper query and writes a
// fresh snapshot. On-demand requests for the same key may race this loader
// through their own fido.Fetch path; both produce consistent snapshots, so the
// rare duplicate hopper query is benign.
func refreshFeedCacheEntry(ctx context.Context, a feedQueryArgs, maxAge time.Duration) error {
	key := feedCacheKey(a)
	if snapshot, found, err := feedCache.Get(ctx, key); err == nil && found {
		if time.Since(snapshot.GeneratedAt) <= maxAge {
			return nil
		}
	}
	snapshot, err := buildFeedSnapshot(ctx, a, logger)
	if err != nil {
		return err
	}
	if err := feedCache.SetTTL(ctx, key, snapshot, feedCacheTTL); err != nil {
		return err
	}
	logger.Debug("feed pre-cache refreshed", "key", key, "rows", len(snapshot.Rows), "total", snapshot.TotalCount)
	return nil
}

// feedPopularity tracks how often each structured feed pivot is requested, so
// the hot pre-cache tier can keep genuinely-popular ecosystem and severity views
// warm. Free-text searches and formula filters are excluded — their key space is
// unbounded and one-off, not worth pre-warming — as is the domain dimension, so
// a /npm/ visit with any domain filter still counts toward the plain /npm/ view.
type feedPopularity struct {
	mu     sync.Mutex
	counts map[feedQueryArgs]uint64
}

// feedPopularityCap bounds the tracked key set so cycling through distinct
// pivots can't grow it without bound; past the cap only already-seen keys keep
// counting. The real structured key space (ecosystems × criticalities × feeds)
// is well under this.
const feedPopularityCap = 512

var feedPopular = &feedPopularity{counts: make(map[feedQueryArgs]uint64)}

// record bumps the visit count for the structured form of a, ignoring free-text
// and domain dimensions. A no-op for search/formula queries.
func (p *feedPopularity) record(a feedQueryArgs) {
	if a.search != "" || a.formula != "" {
		return
	}
	key := feedQueryArgs{ecosystem: a.ecosystem, criticality: a.criticality, feedsOnly: a.feedsOnly}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.counts[key] == 0 && len(p.counts) >= feedPopularityCap {
		return
	}
	p.counts[key]++
}

// top returns the n most-requested pivots, most-popular first (ties broken by
// cache key for a stable order).
func (p *feedPopularity) top(n int) []feedQueryArgs {
	p.mu.Lock()
	type entry struct {
		args  feedQueryArgs
		count uint64
	}
	entries := make([]entry, 0, len(p.counts))
	for a, c := range p.counts {
		entries = append(entries, entry{a, c})
	}
	p.mu.Unlock()

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].count != entries[j].count {
			return entries[i].count > entries[j].count
		}
		return feedCacheKey(entries[i].args) < feedCacheKey(entries[j].args)
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	out := make([]feedQueryArgs, len(entries))
	for i, e := range entries {
		out[i] = e.args
	}
	return out
}

func cachedFeedSamplesFromRows(rows []feedRow) []cachedFeedSample {
	samples := make([]cachedFeedSample, 0, len(rows))
	for i := range rows {
		row := &rows[i]
		samples = append(samples, cachedFeedSample{
			SHA256:         row.SHA256,
			Filename:       row.Filename,
			Classification: row.Classification,
			Probability:    row.Probability,
			SuspiciousT:    row.SuspiciousT,
			HostileT:       row.HostileT,
			Formula:        row.Formula,
			FileType:       row.FileType,
			Source:         row.Source,
			Feed:           row.Feed,
			Ecosystem:      row.Ecosystem,
			CreatedAt:      row.AnalyzedAt,
		})
	}
	return samples
}

// feedDate formats t as a compact relative string for the feed table —
// "7m ago", "3h ago", "2d ago" fit a narrow column; entries older than a
// week fall back to a short date in the server's local timezone.
func feedDate(t, now time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
	return t.Local().Format("Jan 2") //nolint:gosmopolitan // server-local rendering is intentional for the public feed
}

// errSampleNotEligible is returned by requestRescan when the SHA matches no
// top-level, non-skipped sample in the hopper database OR when the sample
// was analyzed within the rescanCooldown window. Distinguishing between
// the two cases would require a second query; the handler surfaces a
// single user-facing message covering both possibilities.
var errSampleNotEligible = errors.New("sample not found, is an archive child, is marked skip, or is within the rescan cooldown")

// tokenBucket is a minimal global rate limiter. Tokens refill continuously
// at refillRate per second up to capacity; Allow consumes one token and
// returns false when none are available. Safe for concurrent use.
//
// Used for the rescan endpoint: a public-facing operator action whose
// rate must be capped to protect hopper from coordinated re-queue storms.
// The per-SHA 15-minute cooldown handles single-sample spam; this caps
// aggregate pressure across all samples.
type tokenBucket struct {
	last       time.Time
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	refillRate float64 // tokens per second
}

func newTokenBucket(refillPerSec, capacity float64) *tokenBucket {
	return &tokenBucket{
		last:       time.Now(),
		tokens:     capacity,
		capacity:   capacity,
		refillRate: refillPerSec,
	}
}

// Allow consumes one token if available, returning true on success.
func (b *tokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * b.refillRate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// rescanLimiter caps the global rescan request rate at 1/sec sustained
// with a burst of 10 (so several operators can each click once without
// being blocked, but sustained pressure is throttled to the configured
// rate). See handleRescan for use.
var rescanLimiter = newTokenBucket(1.0, 10)

// requestRescan clears the cached analysis fields for the given sample
// hash so the next worker poll picks it up as Tier 1 (unanalyzed) work.
// Limited to top-level non-skipped samples (parent is empty, skip is
// empty) — archive children inherit analysis from their parent, and
// skipped samples are excluded deliberately. The prism-side result cache
// is invalidated on success so a subsequent GET /file/<sha> does not
// serve the stale rendered view.
//
// This currently uses the raw pgxpool exposed by hopper.DB.Pool(); it
// would belong as a hopper.DB.RequestRescan method but is kept local to
// avoid a hopper version bump for this single operator action.
func requestRescan(ctx context.Context, sha string) error {
	db := hopperDB.Load()
	if db == nil {
		return errors.New("hopper database unavailable")
	}
	if err := db.RequestRescan(ctx, sha, rescanCooldown); err != nil {
		if errors.Is(err, hopper.ErrRescanNotEligible) {
			return errSampleNotEligible
		}
		return fmt.Errorf("hopper rescan: %w", err)
	}
	// Invalidate every prism-local cache keyed on this sha so the next
	// GET /file/<sha> rebuilds the whole page from the re-queued state
	// instead of serving the stale rendered view. The aux caches now hold a
	// 24-hour TTL, so without this a rescan wouldn't surface for a day.
	// Failures are not fatal — the next refresh window picks up the new
	// state — but worth logging.
	invalidateSampleCaches(ctx, sha, "rescan")
	return nil
}

// isHardRefresh reports whether the request is a browser hard reload
// (Cmd-Shift-R / Ctrl-F5). Browsers send Cache-Control: no-cache on a hard
// reload (Chrome and friends also send Pragma: no-cache); we honor that as the
// user's explicit "skip the cache, rebuild, and repopulate" signal. A normal
// reload sends max-age=0, which we deliberately ignore so it still hits cache.
func isHardRefresh(r *http.Request) bool {
	if strings.Contains(strings.ToLower(r.Header.Get("Cache-Control")), "no-cache") {
		return true
	}
	return strings.EqualFold(r.Header.Get("Pragma"), "no-cache")
}

// invalidateSampleCaches drops every per-sha cache entry for sha: the rendered
// result, its external report, and its parent-archive list. Used by rescan and
// by a hard refresh, so a forced reload rebuilds the page top to bottom.
func invalidateSampleCaches(ctx context.Context, sha, reason string) {
	for _, c := range []struct {
		name string
		del  func(context.Context, string) error
	}{
		{"result", cache.Delete},
		{"report", reportCache.Delete},
		{"parents", parentArchiveCache.Delete},
	} {
		if err := c.del(ctx, sha); err != nil {
			logger.Debug("sample cache invalidation failed", "sha256", sha, "cache", c.name, "reason", reason, "error", err)
		}
	}
}

func cachedResultForSample(ctx context.Context, sample *hopper.Sample, reqLogger *slog.Logger) (storedResult, error) {
	res, err := cache.Fetch(ctx, sample.SHA256, func(_ context.Context) (storedResult, error) {
		reqLogger.Debug("feed cache miss, hydrating from hopper sample", "sha256", sample.SHA256)
		return storedResultFromHopperSample(sample)
	})
	if err != nil {
		return storedResult{}, err
	}
	if shouldRefreshCachedSample(&res, sample) {
		fresh, err := storedResultFromHopperSample(sample)
		if err != nil {
			// Refresh failed: serve the stale cached value rather than fail
			// the whole feed render. Logged at Debug for diagnostics.
			reqLogger.Debug("feed cache refresh failed; serving stale", "sha256", sample.SHA256, "error", err)
			return res, nil
		}
		if err := cache.SetAsync(ctx, sample.SHA256, fresh); err != nil {
			reqLogger.Debug("feed cache update failed", "sha256", sample.SHA256, "error", err)
			return res, nil
		}
		return fresh, nil
	}
	return res, nil
}

// criticalityClasses translates a UI/URL criticality token into the litmus
// class integers the feed query filters on. Accepts either named bands
// ("benign"/"suspicious"/"hostile") or comparison expressions over the
// raw class number (0=benign, 1=suspicious, 2=hostile), so a caller that
// wants "suspicious or hostile" writes ">=1" instead of inventing a new
// token. Unrecognized inputs return (nil, false).
//
// Supported grammar:
//
//	benign | suspicious | hostile      named single bands
//	N | =N                              exact class number
//	>=N | >N                            class >= / > N
//	<=N | <N                            class <= / < N
func criticalityClasses(criticality string) ([]int, bool) {
	switch criticality {
	case "benign":
		return []int{0}, true
	case "suspicious":
		return []int{1}, true
	case "hostile":
		return []int{2}, true
	}
	op, n, ok := parseCritExpr(criticality)
	if !ok {
		return nil, false
	}
	// Litmus emits only 0/1/2. We accept any N but clamp the resulting
	// set to that universe so e.g. `>=0` doesn't become "ignore filter".
	all := [...]int{0, 1, 2}
	var keep []int
	for _, c := range all {
		hit := false
		switch op {
		case "=":
			hit = c == n
		case ">=":
			hit = c >= n
		case ">":
			hit = c > n
		case "<=":
			hit = c <= n
		case "<":
			hit = c < n
		}
		if hit {
			keep = append(keep, c)
		}
	}
	if len(keep) == 0 {
		return nil, false
	}
	return keep, true
}

// classificationClass is the inverse of classificationName: map the
// display string back to the underlying litmus class integer.
func classificationClass(name string) (int, bool) {
	switch name {
	case "benign":
		return 0, true
	case "suspicious":
		return 1, true
	case "hostile":
		return 2, true
	default:
		return 0, false
	}
}

// parseBoolQuery treats common truthy strings ("1", "true", "yes", "on") as
// true and everything else (including empty) as false. Used for opt-in URL
// flags where we'd rather accept "/?feeds=1" and "/?feeds=true" alike than
// be strict about a single form.
func parseBoolQuery(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// parseCritExpr matches "[op]N" where op ∈ {=, >, >=, <, <=} (default =).
// Returns the operator, integer, and whether the input parsed.
func parseCritExpr(s string) (op string, n int, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, false
	}
	op = "="
	switch {
	case strings.HasPrefix(s, ">="):
		op, s = ">=", s[2:]
	case strings.HasPrefix(s, "<="):
		op, s = "<=", s[2:]
	case strings.HasPrefix(s, ">"):
		op, s = ">", s[1:]
	case strings.HasPrefix(s, "<"):
		op, s = "<", s[1:]
	case strings.HasPrefix(s, "="):
		s = s[1:]
	}
	s = strings.TrimSpace(s)
	v, err := strconv.Atoi(s)
	if err != nil {
		return "", 0, false
	}
	return op, v, true
}

func normalizeCriticality(criticality string) string {
	criticality = strings.ToLower(strings.TrimSpace(criticality))
	if _, ok := criticalityClasses(criticality); ok {
		return criticality
	}
	return ""
}

func sampleThresholds(sample *hopper.Sample) (suspiciousT, hostileT float64) {
	const (
		defaultSuspiciousT = 0.65
		defaultHostileT    = 0.887
	)
	if sample != nil && len(sample.LitmusResult) > 0 {
		var mlResp litmusMlResponse
		if json.Unmarshal(sample.LitmusResult, &mlResp) == nil {
			suspiciousT, hostileT := mlResp.suspiciousT(), mlResp.hostileT()
			if suspiciousT > 0 && hostileT > 0 {
				return suspiciousT, hostileT
			}
		}
	}
	return defaultSuspiciousT, defaultHostileT
}

func shouldRefreshCachedSample(res *storedResult, sample *hopper.Sample) bool {
	sampleUpdated := sampleTime(sample)
	if !sampleUpdated.IsZero() && sampleUpdated.After(res.CachedAt) {
		return true
	}
	return (res.Formula == "" && sample.Formula != "") ||
		(res.FileType == "" && sample.FileType != "") ||
		(res.Classification == "" && len(sample.LitmusResult) > 0)
}

func storedResultFromHopperSample(sample *hopper.Sample) (storedResult, error) {
	envelope := map[string]json.RawMessage{}
	if json.Valid(sample.LitmusResult) {
		envelope["ml"] = sample.LitmusResult
	}
	if json.Valid(sample.CleaveResult) {
		envelope["raw"] = sample.CleaveResult
	}
	rawLitmus, err := json.Marshal(envelope)
	if err != nil {
		rawLitmus = []byte("{}")
	}

	classification := ""
	if len(sample.LitmusResult) > 0 {
		var mlResp litmusMlResponse
		if json.Unmarshal(sample.LitmusResult, &mlResp) == nil {
			classification = classificationName(mlResp.verdictClass())
		}
	}

	cachedAt := sampleTime(sample)
	if cachedAt.IsZero() {
		cachedAt = time.Now().UTC()
	}
	var analyzedAt time.Time
	if sample.AnalyzedAt != nil {
		analyzedAt = *sample.AnalyzedAt
	}
	var firstAnalyzedAt time.Time
	if sample.FirstAnalyzedAt != nil {
		firstAnalyzedAt = *sample.FirstAnalyzedAt
	}

	return storedResult{
		Filename:        firstNonEmpty(sample.Filename, filepath.Base(sample.Path)),
		RawLitmus:       string(rawLitmus),
		Classification:  classification,
		Formula:         sample.Formula,
		FileType:        sample.FileType,
		CachedAt:        cachedAt,
		CreatedAt:       sample.CreatedAt,
		AnalyzedAt:      analyzedAt,
		SourceURL:       sample.URL,
		SourceDomain:    sample.Domain,
		Ecosystem:       sample.Ecosystem,
		SizeBytes:       sample.SizeBytes,
		Source:          sample.Source,
		Feed:            sample.Feed,
		Package:         sample.Package,
		Version:         sample.Version,
		Label:           sample.Label,
		LabelSource:     sample.LabelSource,
		TraitsVersion:   sample.TraitsVersion,
		CanonicalSHA256: sample.CanonicalSHA256,
		UpdatedAt:       sample.UpdatedAt,
		FirstAnalyzedAt: firstAnalyzedAt,
	}, nil
}

// sourceDisplay returns the href and label pair for the result page's
// "Source" meta row. If sourceURL parses cleanly, label is its host
// (compact, recognizable — "registry.npmjs.org" beats a 200-char URL)
// and href is the full URL. If the URL is missing or unparseable, the
// domain fallback is used as a plain-text label with an empty href.
// When neither is set, both returns are empty and the template hides
// the row entirely.
func sourceDisplay(sourceURL, domain string) (href, label string) {
	if sourceURL != "" {
		if u, err := url.Parse(sourceURL); err == nil && u.Host != "" {
			return sourceURL, u.Host
		}
		// Unparseable URL: fall through to domain. We don't render the
		// raw string as a link because it might be malformed and
		// confuse the browser.
	}
	if domain != "" {
		return "", domain
	}
	return "", ""
}

// ProvenanceRow is one label→value fact in the Provenance tab. Href, when
// set, renders the value as a link (External adds target/rel for off-site
// URLs); Mono selects the monospace face for hashes and versions. A row with
// an empty Value is dropped before its group is rendered.
type ProvenanceRow struct {
	Label    string
	Value    string
	Href     string
	Mono     bool
	External bool
}

// ProvenanceGroup is a titled cluster of provenance rows. A group with no
// surviving rows is omitted so the tab never shows a bare heading.
type ProvenanceGroup struct {
	Title string
	Rows  []ProvenanceRow
}

// provenanceGroups assembles the Provenance tab's record from the stored
// sample. Every fact originates in hopper's database (res), so this never
// depends on the litmus envelope parse: uploads, which carry no provenance,
// degrade to just the identity rows. Empty rows and empty groups are dropped
// so absent fields simply don't appear.
func provenanceGroups(sha256Hex, filename string, res *storedResult) []ProvenanceGroup {
	ts := func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Format("2 Jan 2006 15:04 UTC")
	}
	// Only surface the canonical hash when it actually differs — for a
	// standalone file it equals the sample's own SHA256 and adds noise.
	canonical := ""
	if res.CanonicalSHA256 != "" && res.CanonicalSHA256 != sha256Hex {
		canonical = res.CanonicalSHA256
	}

	groups := []ProvenanceGroup{
		{Title: "Identity", Rows: []ProvenanceRow{
			{Label: "SHA-256", Value: sha256Hex, Mono: true},
			{Label: "Canonical SHA-256", Value: canonical, Mono: true},
			{Label: "Filename", Value: filename},
			{Label: "Package", Value: res.Package},
			{Label: "Version", Value: res.Version, Mono: true},
		}},
		{Title: "Origin", Rows: []ProvenanceRow{
			{Label: "Source", Value: res.Source},
			{Label: "Feed", Value: res.Feed},
			{Label: "Ecosystem", Value: res.Ecosystem, Href: ecosystemURL(res.Ecosystem)},
			{Label: "Domain", Value: res.SourceDomain},
			{Label: "URL", Value: res.SourceURL, Href: res.SourceURL, Mono: true, External: true},
		}},
		{Title: "Timeline", Rows: []ProvenanceRow{
			{Label: "First seen", Value: ts(res.CreatedAt)},
			{Label: "First analyzed", Value: ts(res.FirstAnalyzedAt)},
			{Label: "Last analyzed", Value: ts(res.AnalyzedAt)},
			{Label: "Last updated", Value: ts(res.UpdatedAt)},
		}},
		{Title: "Labeling", Rows: []ProvenanceRow{
			{Label: "Label", Value: res.Label},
			{Label: "Label source", Value: res.LabelSource},
			{Label: "Traits version", Value: res.TraitsVersion, Mono: true},
		}},
	}

	out := groups[:0]
	for _, g := range groups {
		rows := g.Rows[:0]
		for _, r := range g.Rows {
			if r.Value != "" {
				rows = append(rows, r)
			}
		}
		if len(rows) > 0 {
			g.Rows = rows
			out = append(out, g)
		}
	}
	return out
}

func sampleTime(sample *hopper.Sample) time.Time {
	newest := sample.CreatedAt
	if sample.Mtime != nil && sample.Mtime.After(newest) {
		newest = *sample.Mtime
	}
	if sample.AnalyzedAt != nil && sample.AnalyzedAt.After(newest) {
		newest = *sample.AnalyzedAt
	}
	if sample.UpdatedAt.After(newest) {
		newest = sample.UpdatedAt
	}
	return newest
}

func shortSHA(sha string) string {
	if len(sha) <= 12 {
		return sha
	}
	return sha[:12]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" && value != "." {
			return value
		}
	}
	return "unknown"
}

func ecosystemURL(ecosystem string) string {
	if ecosystem == "" {
		return ""
	}
	return "/" + strings.ToLower(urlPathSegment(ecosystem)) + "/"
}

// ecosystemColor assigns each ecosystem a badge hue, leaning on the brand
// color where it does not collide. Hopper normalizes registry names to
// runtime names (npm → javascript, pypi → python, etc.), so this switch
// keys on the canonical runtime. High-volume runtimes each get a distinct
// family so they stay legible in a dense feed; lower-volume runtimes
// reuse the same families.
func ecosystemColor(eco string) string {
	switch strings.ToLower(eco) {
	// Languages — high volume, each gets its own family.
	case "javascript":
		return "yellow"
	case "python":
		return "blue"
	case "ruby":
		return "red"
	case "rust":
		return "brown"
	case "go":
		return "cyan"
	case "java":
		return "orange"
	case "php":
		return "purple"
	case "dart":
		return "cyan"
	case "wordpress":
		return "indigo"
	// Languages — lower volume, share families.
	case "dotnet":
		return "indigo"
	case "powershell":
		return "blue"
	case "erlang", "perl":
		return "rose"
	case "haskell":
		return "purple"
	case "r", "lua":
		return "green"
	// OS targets.
	case "linux":
		return "yellow"
	case "bsd":
		return "red"
	case "macos":
		return "slate"
	case "windows":
		return "blue"
	case "android":
		return "green"
	// Application hosts.
	case "vscode":
		return "blue"
	case "chrome":
		return "green"
	case "edge":
		return "cyan"
	case "firefox":
		return "orange"
	// Agent skills, containers, source hosts.
	case "agent", "openclaw":
		return "purple"
	case "container":
		return "cyan"
	case "github":
		return "slate"
	default:
		return "slate"
	}
}

// composeSearchQuery rebuilds the canonical search-box string from the
// individual URL filters so the box reflects the page's current state on
// load (and after non-JS form submissions). Mirror of parseQuery() in
// upload.js — keep the key order and prefixes in sync.
func composeSearchQuery(crit, eco, domain, formula, q string) string {
	var parts []string
	if crit != "" {
		parts = append(parts, "crit:"+crit)
	}
	if eco != "" {
		parts = append(parts, "ecosystem:"+eco)
	}
	if domain != "" {
		parts = append(parts, "domain:"+domain)
	}
	if formula != "" {
		parts = append(parts, "m:"+desubscriptFormula(formula))
	}
	if q != "" {
		parts = append(parts, q)
	}
	return strings.Join(parts, " ")
}

// shaFromSearchQuery extracts a SHA-256 from a search box value that is
// purely a SHA reference — either `sha256:<64-hex>` or a bare 64-hex
// string. Returns lowercase hex.
func shaFromSearchQuery(q string) (string, bool) {
	q = strings.TrimSpace(q)
	if strings.HasPrefix(strings.ToLower(q), "sha256:") {
		q = q[len("sha256:"):]
	}
	q = strings.ToLower(strings.TrimSpace(q))
	if validSHA256(q) {
		return q, true
	}
	return "", false
}

// maxFilterLen bounds the free-text feed filters (search, domain, formula).
// It is longer than any real filename, registrable domain, or chemical
// formula, yet short enough that a hostile value can't drive a giant LIKE
// scan, bloat the logs, or balloon a snapshot. The cache key is hashed, so
// this is an abuse bound, not a correctness one.
const maxFilterLen = 256

// sanitizeFilter makes a raw query-string filter value safe to put in a SQL
// bind parameter and a cache key, regardless of which input channel (filter
// dropdown, search box, or hand-typed URL) it arrived through. Ranging over
// the string folds invalid UTF-8 to U+FFFD, so the result is always valid
// UTF-8 — Postgres rejects text parameters that aren't. Control bytes,
// including the NUL that Postgres also rejects, fold to spaces; the value is
// then trimmed and rune-capped. Returns "" for empty or whitespace-only input.
func sanitizeFilter(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsControl(r) {
			r = ' '
		}
		b.WriteRune(r)
	}
	s = strings.TrimSpace(b.String())
	if r := []rune(s); len(r) > maxFilterLen {
		s = strings.TrimSpace(string(r[:maxFilterLen]))
	}
	return s
}

// normalizeSearch canonicalizes the free-text ?q= filter so "Requests",
// "requests ", and "  requests" all collapse to one cache key and one query:
// sanitize, lowercase (the hopper Search predicate is case-insensitive), and
// collapse internal whitespace runs to a single space.
func normalizeSearch(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(sanitizeFilter(s)), " "))
}

// normalizeDomain canonicalizes the ?domain= filter to the lowercase eTLD+1
// form hopper stores (so the same domain via dropdown, search box, or URL is
// one cache key). A value carrying any byte outside the registrable-domain
// charset can never match a stored value, so it is dropped to "" rather than
// fragmenting the cache with a filter that returns nothing.
func normalizeDomain(s string) string {
	s = strings.ToLower(sanitizeFilter(s))
	if s == "" {
		return ""
	}
	for i := range len(s) {
		if c := s[i]; c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' {
			continue
		}
		return ""
	}
	return s
}

// formulaFromQuery reads the cleave formula filter from either ?m= (the form
// the search box emits) or the legacy ?formula= alias, and routes both through
// the same subscripting so "CHO2" and "CHO₂" resolve to one stored value and
// one cache key — formula is matched exactly. Chemical formulas carry no
// whitespace, so internal spaces are stripped.
func formulaFromQuery(values url.Values) string {
	raw := values.Get("m")
	if strings.TrimSpace(raw) == "" {
		raw = values.Get("formula")
	}
	raw = sanitizeFilter(raw)
	if raw == "" {
		return ""
	}
	return resubscriptFormula(strings.ReplaceAll(raw, " ", ""))
}

func desubscriptFormula(formula string) string {
	replacer := strings.NewReplacer(
		"₀", "0", "₁", "1", "₂", "2", "₃", "3", "₄", "4",
		"₅", "5", "₆", "6", "₇", "7", "₈", "8", "₉", "9",
	)
	return replacer.Replace(formula)
}

func resubscriptFormula(formula string) string {
	var b strings.Builder
	for _, r := range formula {
		switch r {
		case '0':
			b.WriteRune('₀')
		case '1':
			b.WriteRune('₁')
		case '2':
			b.WriteRune('₂')
		case '3':
			b.WriteRune('₃')
		case '4':
			b.WriteRune('₄')
		case '5':
			b.WriteRune('₅')
		case '6':
			b.WriteRune('₆')
		case '7':
			b.WriteRune('₇')
		case '8':
			b.WriteRune('₈')
		case '9':
			b.WriteRune('₉')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func urlPathSegment(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, " ", "-")
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	renderFeed(w, r, "")
}

func handleEcosystem(w http.ResponseWriter, r *http.Request) {
	// Ecosystems are stored lowercase (forager NormalizeEcosystem), so fold
	// case here: /NPM/ and /npm/ then share one cache key and one query
	// instead of fragmenting into a hit and a guaranteed miss.
	eco := strings.ToLower(strings.Trim(r.PathValue("ecosystem"), "/"))
	if !validEcosystem(eco) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	renderFeed(w, r, eco)
}

func handleEcosystemRedirect(w http.ResponseWriter, r *http.Request) {
	eco := strings.ToLower(strings.Trim(r.PathValue("ecosystem"), "/"))
	if !validEcosystem(eco) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	target := "/" + eco + "/"
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// validEcosystem accepts a conservative subset of characters real package
// ecosystems use (alnum, dash, dot, underscore). Anything else — slash,
// backslash, control bytes, whitespace — is rejected, which defeats
// open-redirect tricks like "\evil.com" that some browsers normalize into
// "//evil.com" when emitted as the Location of a relative redirect.
func validEcosystem(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		ok := c >= 'a' && c <= 'z' ||
			c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' ||
			c == '-' || c == '.' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// paginateFeed slices the already-filtered, cached rows down to the page
// requested via ?page=N (1-indexed) and fills in the navigation links. Every
// page is served from the same cached snapshot, so only the slice bounds
// change between pages — no extra hopper query. FilteredCount becomes the
// number of rows actually shown on the page.
func paginateFeed(data *feedPageData, r *http.Request) {
	total := len(data.Rows)
	totalPages := max((total+feedPageSize-1)/feedPageSize, 1)
	page := 1
	if p, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && p > page {
		page = p
	}
	if page > totalPages {
		page = totalPages
	}
	data.Page = page

	start := (page - 1) * feedPageSize
	end := min(start+feedPageSize, total)
	data.Rows = data.Rows[start:end]
	data.FilteredCount = len(data.Rows)

	if totalPages <= 1 {
		return
	}
	pageURL := func(n int) string {
		q := r.URL.Query()
		if n <= 1 {
			q.Del("page")
		} else {
			q.Set("page", strconv.Itoa(n))
		}
		if enc := q.Encode(); enc != "" {
			return r.URL.Path + "?" + enc
		}
		return r.URL.Path
	}
	data.Pages = make([]feedPageLink, 0, totalPages)
	for n := 1; n <= totalPages; n++ {
		data.Pages = append(data.Pages, feedPageLink{Num: n, URL: pageURL(n), Current: n == page})
	}
	if page > 1 {
		data.PrevURL = pageURL(page - 1)
	}
	if page < totalPages {
		data.NextURL = pageURL(page + 1)
	}
}

func renderFeed(w http.ResponseWriter, r *http.Request, ecosystem string) {
	// Server-side fallback for ?q=sha256:<hex> / ?q=<64-hex> deep links —
	// JS already short-circuits these before sending, but a pasted URL or
	// a no-JS client still gets the redirect. Run it on the raw value;
	// shaFromSearchQuery trims and lowercases internally.
	if sha, ok := shaFromSearchQuery(r.URL.Query().Get("q")); ok {
		http.Redirect(w, r, "/file/"+sha, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := feedPageData{
		CSRFToken:       csrfToken(r, "upload"),
		UploadEnabled:   uploadEnabled,
		FeedsOnly:       parseBoolQuery(r.URL.Query().Get("feeds")),
		Nonce:           nonceFor(r),
		StyleNonce:      styleNonceFor(r),
		BuildCommit:     buildCommit,
		Refresh:         r.URL.Query().Get("refresh") == "1",
		SelectedEco:     ecosystem,
		SelectedDomain:  normalizeDomain(r.URL.Query().Get("domain")),
		SelectedCrit:    normalizeCriticality(r.URL.Query().Get("criticality")),
		SelectedFormula: formulaFromQuery(r.URL.Query()),
		SelectedQ:       normalizeSearch(r.URL.Query().Get("q")),
		Title:           "Fallout",
		HasHopper:       hopperDB.Load() != nil,
	}
	data.SearchQuery = composeSearchQuery(
		data.SelectedCrit, data.SelectedEco, data.SelectedDomain,
		data.SelectedFormula, data.SelectedQ,
	)
	if ecosystem != "" {
		data.Title = ecosystem + " Fallout"
	}

	var diags []queryDiag
	if hopperDB.Load() != nil {
		snapshot, diag, err := loadFeedSnapshot(
			r.Context(),
			feedQueryArgs{
				ecosystem:   data.SelectedEco,
				domain:      data.SelectedDomain,
				criticality: data.SelectedCrit,
				formula:     data.SelectedFormula,
				search:      data.SelectedQ,
				feedsOnly:   data.FeedsOnly,
			},
			logger,
			isHardRefresh(r),
		)
		if err != nil {
			logger.Warn("failed to load feed rows", "error", err, "ecosystem", ecosystem)
			renderError(w, r, http.StatusInternalServerError, errorData{
				Icon:    "⚠",
				Title:   "Feed unavailable",
				Message: "The recent analysis feed could not be loaded.",
			})
			return
		}
		diags = append(diags, diag)
		data.Rows = feedRowsFromSnapshot(snapshot)
		data.TotalCount = snapshot.TotalCount
		data.Domains = snapshot.Domains
		data.Ecosystems = snapshot.Ecosystems
		paginateFeed(&data, r)
	}
	if err := uploadTemplate.Execute(w, data); err != nil {
		logger.Error("template execution failed",
			"template", "feed",
			"error", err,
		)
		return
	}
	writeQueryDiags(w, diags)
}

// writeQueryDiags appends one HTML comment per executed query to the response.
// html/template strips comments from template source, so these are written
// after Execute rather than from the template itself.
func writeQueryDiags(w io.Writer, diags []queryDiag) {
	for _, d := range diags {
		// Params is the only request-derived field and is reduced to ASCII
		// alphanumerics by diagSafe, so it cannot break out of the
		// surrounding HTML comment; gosec's taint analysis can't see the
		// custom sanitizer.
		if _, err := fmt.Fprintf(w, "\n<!-- %s source:%s duration:%s age:%s params:%s rows=%d bytes=%d -->", //nolint:gosec // params sanitized by diagSafe
			d.Name, d.Source, d.Duration, d.Age, d.Params, d.Rows, d.Bytes); err != nil {
			return
		}
	}
}

func handleFormats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct{ Nonce, StyleNonce string }{Nonce: nonceFor(r), StyleNonce: styleNonceFor(r)}
	if err := formatsTemplate.Execute(w, data); err != nil {
		logger.Error("template execution failed",
			"template", "formats",
			"error", err,
		)
	}
}

func handlePoweredBy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct{ Nonce, StyleNonce string }{Nonce: nonceFor(r), StyleNonce: styleNonceFor(r)}
	if err := poweredByTemplate.Execute(w, data); err != nil {
		logger.Error("template execution failed",
			"template", "powered-by",
			"error", err,
		)
	}
}

func handleHelpQuery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct{ Nonce, StyleNonce string }{Nonce: nonceFor(r), StyleNonce: styleNonceFor(r)}
	if err := helpQueryTemplate.Execute(w, data); err != nil {
		logger.Error("template execution failed",
			"template", "help-query",
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
	// Normalize once at the boundary so suffix matching, validation, and
	// every downstream lookup work on the same lowercase form.
	sha := strings.ToLower(r.PathValue("sha256"))
	ip := clientIP(r)

	// GET /file/{sha256} also matches /file/<hash>.json because the wildcard
	// captures the full path segment including any extension.
	if bare, ok := strings.CutSuffix(sha, ".json"); ok {
		serveFileJSON(w, r, bare, ip)
		return
	}
	if bare, ok := strings.CutSuffix(sha, ".dl"); ok {
		serveFileDownload(w, r, bare, ip)
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

	// A hard refresh (Cmd-Shift-R) drops every per-sha cache up front so the
	// lookups below rebuild the page from the current hopper state.
	if isHardRefresh(r) {
		reqLogger.Info("hard refresh: bypassing sample caches")
		invalidateSampleCaches(r.Context(), sha, "hard-refresh")
	}

	cacheHit, res, err := lookupResult(r.Context(), sha, reqLogger)
	if err != nil {
		var pend *pendingAnalysisError
		if errors.As(err, &pend) {
			reqLogger.Info("rendering pending state", "filename", pend.Filename)
			renderPending(w, r, sha, pend.Filename)
			return
		}
		reqLogger.Warn("failed to retrieve or regenerate result",
			"error", err,
			"hopper_api_addr", hopperAPIAddr,
			"hopper_db_host", hopperDSNHost(hopperDBDSN),
			"hopper_db_connected", hopperDB.Load() != nil,
		)
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
	data.Nonce = nonceFor(r)
	data.StyleNonce = styleNonceFor(r)
	data.BuildCommit = buildCommit
	data.CSRFToken = csrfToken(r, "rescan")
	data.DownloadToken = csrfToken(r, "download")
	if hopperDB.Load() != nil {
		if cached, ok := latestReport(r.Context(), sha, reqLogger); ok {
			data.ReportContent = cached.Content
			data.ReportProvider = cached.Provider
			if !cached.CreatedAt.IsZero() {
				data.ReportCreated = cached.CreatedAt.Format("2 Jan 2006 15:04 UTC")
			}
		}
		// Parent archives: only meaningful on a standalone child view, not
		// when the user is already looking at the archive itself.
		if !data.IsArchive {
			data.Parents = lookupParentArchives(r.Context(), sha, reqLogger)
		}
	}
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

// maxParentArchives caps how many "found in" backlinks a child page renders.
// A single popular file (e.g. a stock package.json) can appear in hundreds
// of archives; showing all of them would dominate the page.
const maxParentArchives = 10

// latestReport returns the most recent reverse-engineering report for
// sha (or zero-valued + false when none exists). Cached via reportCache
// with auxCacheTTL and fido's built-in singleflight, so concurrent page
// renders for the same SHA share one hopper round-trip. The not-found
// case is itself cached (via cachedReport.Found=false) so SHAs without
// reports don't fan out one query per request.
func latestReport(ctx context.Context, sha string, log *slog.Logger) (hopper.Report, bool) {
	db := hopperDB.Load()
	if reportCache == nil || db == nil {
		return hopper.Report{}, false
	}
	cached, err := reportCache.FetchTTL(ctx, sha, auxCacheTTL, func(lctx context.Context) (cachedReport, error) {
		rep, ferr := db.LatestReport(lctx, sha, "re")
		if ferr != nil {
			if errors.Is(ferr, hopper.ErrNotFound) {
				return cachedReport{Found: false}, nil
			}
			return cachedReport{}, ferr
		}
		return cachedReport{Report: *rep, Found: true}, nil
	})
	if err != nil {
		log.Debug("failed to load reverse-engineering report", "error", err)
		return hopper.Report{}, false
	}
	if !cached.Found {
		return hopper.Report{}, false
	}
	return cached.Report, true
}

// lookupParentArchives finds archives that contain childSHA, sorted by
// most recent analysis. Returns nil on error (best-effort metadata).
//
// Implementation: walk sample_locations rows for childSHA, dedup by parent
// SHA, then resolve each parent's display fields. The whole computation
// is wrapped in parentArchiveCache.FetchTTL so concurrent page renders
// for the same child share one full hopper sweep (singleflighted), and
// a request-bound timeout caps the worst case so a slow hopper-db
// doesn't block page render: when the deadline fires we return whatever
// we've collected so far.
func lookupParentArchives(ctx context.Context, childSHA string, log *slog.Logger) []ParentArchive {
	if parentArchiveCache == nil || hopperDB.Load() == nil {
		return nil
	}
	cached, err := parentArchiveCache.FetchTTL(ctx, childSHA, auxCacheTTL, func(lctx context.Context) (cachedParents, error) {
		entries := lookupParentArchivesFromHopper(lctx, childSHA, log)
		return cachedParents{Entries: entries}, nil
	})
	if err != nil {
		log.Debug("parent archive cache fetch failed", "error", err)
		return nil
	}
	return cached.Entries
}

// lookupParentArchivesFromHopper is the uncached loader body invoked by
// lookupParentArchives. Direct callers should not exist; route through
// the cached wrapper so concurrent fetches dedupe.
func lookupParentArchivesFromHopper(ctx context.Context, childSHA string, log *slog.Logger) []ParentArchive {
	ctx, cancel := context.WithTimeout(ctx, parentLookupTimeout)
	defer cancel()
	db := hopperDB.Load()
	if db == nil {
		return nil
	}
	locs, err := db.LocationsForSHA(ctx, childSHA)
	if err != nil {
		log.Debug("parent archive lookup: locations failed", "error", err)
		return nil
	}
	seen := make(map[string]bool, len(locs))
	out := make([]ParentArchive, 0, maxParentArchives)
	for _, loc := range locs {
		if ctx.Err() != nil {
			// Deadline hit mid-loop — return what we have so the page
			// renders something rather than nothing.
			break
		}
		if loc.ParentSHA256 == "" || seen[loc.ParentSHA256] {
			continue
		}
		seen[loc.ParentSHA256] = true
		parent, err := db.SampleBySHA256(ctx, loc.ParentSHA256)
		if err != nil {
			// Missing parent rows are normal (e.g. extracted-then-deleted);
			// skip silently. A real DB error logs once and continues.
			if !errors.Is(err, hopper.ErrNotFound) {
				log.Debug("parent archive lookup: sample fetch failed",
					"parent_sha", loc.ParentSHA256, "error", err)
			}
			continue
		}
		entry := ParentArchive{
			SHA256:      parent.SHA256,
			SHA256Short: shortSHA(parent.SHA256),
			Filename:    firstNonEmpty(parent.Filename, filepath.Base(parent.Path)),
			Path:        loc.Path,
		}
		if len(parent.LitmusResult) > 0 {
			var ml litmusMlResponse
			if json.Unmarshal(parent.LitmusResult, &ml) == nil {
				entry.Classification = classificationName(ml.verdictClass())
			}
		}
		if parent.AnalyzedAt != nil {
			entry.AnalyzedAt = parent.AnalyzedAt.Format("2 Jan 2006 15:04 UTC")
			entry.AnalyzedAgo = timeAgo(time.Since(*parent.AnalyzedAt))
		}
		out = append(out, entry)
		if len(out) >= maxParentArchives {
			break
		}
	}
	return out
}

// parentLookupTimeout bounds the N+1 SampleBySHA256 lookups behind
// ParentArchives so a slow hopper-db degrades the backlinks, not the page.
const parentLookupTimeout = 2 * time.Second

// hopperCacheTTL is how long a cached result is served without consulting
// hopper. Older entries are still served immediately; the refresh happens
// in a background goroutine so the request path never waits on the database.
const hopperCacheTTL = time.Hour

// refreshInFlight deduplicates concurrent background refreshes per sha so a
// stale entry under load triggers one hopper query, not one per request.
var refreshInFlight sync.Map // key: sha string, value: struct{}{}

// lookupResult retrieves a stored result, treating hopper as the source of
// truth and the fido cache as an in-memory/disk tier in front of it.
//
// On cache miss, fetches from hopper synchronously (shared via fido's
// singleflight so concurrent requests coalesce). On cache hit older than
// hopperCacheTTL, serves the cached value immediately and fires an async
// refresh — the serving path never blocks on hopper for stale data.
func lookupResult(ctx context.Context, sha string, reqLogger *slog.Logger) (bool, storedResult, error) {
	cacheHit := true
	res, err := cache.Fetch(ctx, sha, func(lctx context.Context) (storedResult, error) {
		cacheHit = false
		dbHost := hopperDSNHost(hopperDBDSN)
		reqLogger.Debug("cache miss, loading from hopper",
			"hopper_db_host", dbHost,
		)
		if hopperDB.Load() == nil {
			return storedResult{}, fmt.Errorf("hopper db not connected (host=%s); background reconnect in progress", dbHost)
		}
		return fetchFromHopper(lctx, sha)
	})
	if err != nil {
		// A just-uploaded sample may not be in hopper yet (upload + analysis
		// run in the background) and may not have reached prism's cache either.
		// Show the "analyzing" page rather than a 404 until ingestion lands a
		// result or gives up.
		if v, ok := uploadsInFlight.Load(sha); ok {
			var pend *pendingAnalysisError
			if filename, isStr := v.(string); isStr && !errors.As(err, &pend) {
				return false, storedResult{}, &pendingAnalysisError{SHA: sha, Filename: filename}
			}
		}
		return false, storedResult{}, err
	}
	// Self-heal stale cache entries from before the enrichment deploy: if a
	// cache hit still has truncated/omitted_files markers in its raw envelope,
	// it predates fetchFromHopper's reassembly. Re-fetch synchronously so the
	// caller gets the enriched view this request — without this, users would
	// see the un-enriched page until the TTL-based refresh below kicked in.
	if cacheHit && hopperDB.Load() != nil && envelopeNeedsEnrichment(res.RawLitmus) {
		reqLogger.Debug("cached envelope still compacted, re-enriching")
		if fresh, ferr := fetchFromHopper(ctx, sha); ferr == nil {
			res = fresh
			if err := cache.SetAsync(ctx, sha, fresh); err != nil {
				reqLogger.Debug("post-enrichment cache update failed", "error", err)
			}
		} else {
			reqLogger.Debug("re-enrichment fetch failed; serving cached value", "error", ferr)
		}
	}
	if cacheHit && hopperDB.Load() != nil && time.Since(res.CachedAt) > hopperCacheTTL {
		if _, loaded := refreshInFlight.LoadOrStore(sha, struct{}{}); !loaded {
			go refreshFromHopper(context.WithoutCancel(ctx), sha, reqLogger)
		}
	}
	return cacheHit, res, nil
}

// envelopeNeedsEnrichment reports whether a cached storedResult's raw
// litmus envelope still carries the truncated/omitted_files markers that
// hopper's compactor writes. Used to detect cache entries that predate
// the enrichment deploy and need to be reassembled on read.
func envelopeNeedsEnrichment(rawLitmus string) bool {
	if rawLitmus == "" {
		return false
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rawLitmus), &env); err != nil {
		return false
	}
	return hopperWasCompacted(env["raw"])
}

// pendingAnalysisError signals that a sample exists in hopper but has not
// been analyzed yet (cleave_result is NULL). Handlers should render the
// "Analyzing…" page and not cache the partial result.
type pendingAnalysisError struct {
	SHA      string
	Filename string
}

func (e *pendingAnalysisError) Error() string { return "analysis pending for " + e.SHA }

// fetchFromHopper loads a sample from hopper and reshapes it into the
// storedResult shape expected by the rest of prism. Returns an error whose
// message contains "not found" when the sample is absent, so HTTP handlers
// render a 404 instead of a 500. Returns *pendingAnalysisError when the
// sample row exists but no worker has produced a cleave result yet — the
// expected state during the upload→worker handoff.
//
// When the sample's stored cleave result has been compacted (children
// stripped — see hopper.compactCleaveResultForStorage), reassemble children
// from sibling rows so downstream display and JSON export see a full archive
// view. The reassembled envelope is what gets cached.
func fetchFromHopper(ctx context.Context, sha string) (storedResult, error) {
	db := hopperDB.Load()
	if db == nil {
		return storedResult{}, fmt.Errorf("hopper db not connected (host=%s)", hopperDSNHost(hopperDBDSN))
	}
	if err := dbBreaker.allow(); err != nil {
		return storedResult{}, fmt.Errorf("hopper-db lookup: %w", err)
	}
	sample, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		if errors.Is(err, hopper.ErrNotFound) {
			// The DB answered; "not found" is a healthy response, not a fault.
			dbBreaker.success()
			return storedResult{}, fmt.Errorf("sample not found in hopper: %w", err)
		}
		dbBreaker.failure()
		return storedResult{}, fmt.Errorf("hopper lookup (host=%s): %w", hopperDSNHost(hopperDBDSN), err)
	}
	dbBreaker.success()

	if len(sample.CleaveResult) == 0 {
		return storedResult{}, &pendingAnalysisError{
			SHA:      sha,
			Filename: firstNonEmpty(sample.Filename, filepath.Base(sample.Path)),
		}
	}

	res, err := storedResultFromHopperSample(sample)
	if err != nil {
		return res, err
	}
	if hopperWasCompacted(sample.CleaveResult) {
		children, cerr := db.SamplesByParent(ctx, sha)
		if cerr != nil {
			logger.Debug("samples by parent failed", "sha", sha, "error", cerr)
		} else if len(children) > 0 {
			enriched, eerr := reassembleEnvelope([]byte(res.RawLitmus), children, res.Filename)
			if eerr != nil {
				logger.Debug("reassemble envelope failed", "sha", sha, "error", eerr)
			} else {
				res.RawLitmus = string(enriched)
			}
		}
	}
	return res, nil
}

// hopperWasCompacted reports whether the cleave result was stripped of
// child entries by hopper's compactCleaveResultForStorage. Callers should
// query hopper for samples whose parent matches and splice them back in.
func hopperWasCompacted(cleaveResult []byte) bool {
	if len(cleaveResult) == 0 {
		return false
	}
	var env struct {
		Truncated    bool `json:"truncated"`
		OmittedFiles int  `json:"omitted_files"`
	}
	if err := json.Unmarshal(cleaveResult, &env); err != nil {
		return false
	}
	return env.Truncated || env.OmittedFiles > 0
}

// reassembleEnvelope takes a parent's litmus envelope (containing ml + raw)
// and a list of child hopper samples, and produces a new envelope where the
// child entries are spliced back into raw.files[] and ml.files[]. The returned
// envelope drops the truncated/omitted_files markers because they are no
// longer accurate after reassembly.
//
// Each child contributes its own top-level files entry (depth 0 in the child's
// own report) which is appended to the parent's files[] with depth bumped to 1
// and Path prefixed by parentPath + "!!". Child IDs are renumbered so they
// stay unique across the merged report; the same renumbering is mirrored
// into the merged ml.files entries so per-file ML stays correctly attributed.
//
// The function is best-effort: a child whose CleaveResult or LitmusResult
// fails to parse is logged and skipped so a single bad child does not break
// the whole archive view.
func reassembleEnvelope(envelope []byte, children []*hopper.Sample, parentPath string) ([]byte, error) {
	if len(envelope) == 0 {
		return envelope, nil
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(envelope, &env); err != nil {
		return nil, fmt.Errorf("parse envelope: %w", err)
	}

	parentRaw, parentFS, err := extractFS(env, "raw")
	if err != nil {
		return nil, err
	}
	parentML, parentMLFS, err := extractFS(env, "ml")
	if err != nil {
		return nil, err
	}

	parentFS, parentMLFS = mergeChildren(parentFS, parentMLFS, children, parentPath)

	// The truncation markers are no longer accurate after reassembly.
	delete(parentRaw, "truncated")
	delete(parentRaw, "omitted_files")
	if b, err := json.Marshal(parentFS); err == nil {
		delete(parentRaw, "fs")
		parentRaw["files"] = b
	}
	if b, err := json.Marshal(parentRaw); err == nil {
		env["raw"] = b
	}
	if b, err := json.Marshal(parentMLFS); err == nil {
		delete(parentML, "fs")
		parentML["files"] = b
	}
	if b, err := json.Marshal(parentML); err == nil {
		env["ml"] = b
	}
	return json.Marshal(env)
}

// extractFS pulls env[key] (a JSON object) and the "files" array within it.
// Missing values yield empty results so callers can append unconditionally.
func extractFS(env map[string]json.RawMessage, key string) (map[string]json.RawMessage, []json.RawMessage, error) {
	inner := map[string]json.RawMessage{}
	if blob, ok := env[key]; ok && len(blob) > 0 {
		if err := json.Unmarshal(blob, &inner); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", key, err)
		}
	}
	var entries []json.RawMessage
	blob, ok := inner["files"]
	if !ok || len(blob) == 0 {
		blob = inner["fs"]
	}
	if len(blob) > 0 {
		if err := json.Unmarshal(blob, &entries); err != nil {
			return nil, nil, fmt.Errorf("parse %s.files: %w", key, err)
		}
	}
	return inner, entries, nil
}

// mergeChildren splices each child's top-level files entry (and its mirrored
// ml entry) into the parent's lists, renumbering ids so they stay unique.
// Errors on individual children are logged and skipped.
func mergeChildren(parentFS, parentMLFS []json.RawMessage, children []*hopper.Sample, parentPath string) (mergedFS, mergedMLFS []json.RawMessage) {
	nextID := 1
	for _, raw := range parentFS {
		var f struct {
			ID int `json:"id"`
		}
		if json.Unmarshal(raw, &f) == nil && f.ID >= nextID {
			nextID = f.ID + 1
		}
	}
	for _, child := range children {
		if len(child.CleaveResult) == 0 {
			continue
		}
		topRaw, oldID, ok := childTopEntry(child)
		if !ok {
			continue
		}
		newID := nextID
		nextID++
		rewritten, err := rewriteChildEntry(topRaw, parentPath, child.Path, child.Filename, newID)
		if err != nil {
			logger.Debug("reassemble: rewrite child entry failed", "sha", child.SHA256, "error", err)
			continue
		}
		parentFS = append(parentFS, rewritten)
		if updated, ok := renumberedMLEntry(child.LitmusResult, oldID, newID); ok {
			parentMLFS = append(parentMLFS, updated)
		}
	}
	return parentFS, parentMLFS
}

// childTopEntry parses the child sample's cleave envelope and returns its
// representative files entry — preferring sha-match, then depth-0, then the
// first entry — along with the entry's original id.
func childTopEntry(child *hopper.Sample) (entry json.RawMessage, id int, ok bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(child.CleaveResult, &raw); err != nil {
		logger.Debug("reassemble: parse child cleave failed", "sha", child.SHA256, "error", err)
		return nil, 0, false
	}
	var entries []json.RawMessage
	blob, ok := raw["files"]
	if !ok || len(blob) == 0 {
		blob = raw["fs"]
	}
	if len(blob) > 0 {
		if err := json.Unmarshal(blob, &entries); err != nil {
			logger.Debug("reassemble: parse child files failed", "sha", child.SHA256, "error", err)
			return nil, 0, false
		}
	}
	if len(entries) == 0 {
		return nil, 0, false
	}

	type stub struct {
		SHA   string `json:"sha"`
		ID    int    `json:"id"`
		Depth int    `json:"dp"`
	}
	var fallback json.RawMessage
	var fallbackID int
	for _, e := range entries {
		var s stub
		if json.Unmarshal(e, &s) != nil {
			continue
		}
		if s.SHA == child.SHA256 {
			return e, s.ID, true
		}
		if s.Depth == 0 && fallback == nil {
			fallback = e
			fallbackID = s.ID
		}
	}
	if fallback != nil {
		return fallback, fallbackID, true
	}
	// No depth-0 found; fall back to the first entry. A parse failure here
	// just means the renumber loop later assigns a fresh id — nothing to
	// surface to the caller.
	var s stub
	_ = json.Unmarshal(entries[0], &s) //nolint:errcheck // best-effort; failure is fine
	return entries[0], s.ID, true
}

// renumberedMLEntry locates the child's own ml.files[] row for oldID and
// rewrites its id to newID. The boolean reports whether the row was
// found and successfully re-marshalled.
func renumberedMLEntry(litmus []byte, oldID, newID int) (json.RawMessage, bool) {
	if len(litmus) == 0 {
		return nil, false
	}
	var ml struct {
		Files    []json.RawMessage `json:"files"`
		OldFiles []json.RawMessage `json:"fs"`
	}
	if json.Unmarshal(litmus, &ml) != nil || len(ml.Files) == 0 {
		if len(ml.OldFiles) == 0 {
			return nil, false
		}
		ml.Files = ml.OldFiles
	}
	entry := ml.Files[0]
	for _, raw := range ml.Files {
		var stub struct {
			ID int `json:"id"`
		}
		if json.Unmarshal(raw, &stub) == nil && stub.ID == oldID {
			entry = raw
			break
		}
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(entry, &obj); err != nil {
		logger.Debug("reassemble: rewrite child ml entry failed", "error", err)
		return nil, false
	}
	if b, err := json.Marshal(newID); err == nil {
		obj["id"] = b
	}
	updated, err := json.Marshal(obj)
	if err != nil {
		return nil, false
	}
	return updated, true
}

// rewriteChildEntry mutates a single fs entry to fit the parent archive's
// view: prefixes the path with "<parentPath>!!", marks depth=1, and assigns
// the supplied id. We prefer the entry's own path (cleave's view), falling
// back to the child's stored path/filename so the tree shows something
// readable instead of a long upload temp path.
func rewriteChildEntry(entry json.RawMessage, parentPath, childPath, childFilename string, newID int) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(entry, &obj); err != nil {
		return nil, err
	}
	displayPath := ""
	if rawPath, ok := obj["path"]; ok {
		_ = json.Unmarshal(rawPath, &displayPath) //nolint:errcheck // best-effort; falls through to childPath/Filename below
	}
	if displayPath == "" {
		displayPath = childPath
	}
	if displayPath == "" {
		displayPath = childFilename
	}
	if displayPath == "" {
		displayPath = "(unnamed)"
	}
	// Strip any parentPath!! prefix the child may already carry, then add ours.
	if i := strings.LastIndex(displayPath, "!!"); i >= 0 {
		displayPath = displayPath[i+2:]
	}
	if b, err := json.Marshal(parentPath + "!!" + displayPath); err == nil {
		obj["path"] = b
	}
	if b, err := json.Marshal(1); err == nil {
		obj["dp"] = b
	}
	if b, err := json.Marshal(newID); err == nil {
		obj["id"] = b
	}
	return json.Marshal(obj)
}

// refreshFromHopper reloads a sample from hopper and writes it into the cache.
// Invoked in a goroutine when the cached entry has exceeded hopperCacheTTL so
// the serving path never blocks on the database. The caller should pass a
// context detached from the request via context.WithoutCancel so the refresh
// survives the request completing.
func refreshFromHopper(ctx context.Context, sha string, reqLogger *slog.Logger) {
	defer refreshInFlight.Delete(sha)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := fetchFromHopper(ctx, sha)
	if err != nil {
		reqLogger.Debug("background refresh from hopper failed", "error", err)
		return
	}
	if err := cache.SetAsync(ctx, sha, res); err != nil {
		reqLogger.Debug("background cache update failed", "error", err)
		return
	}
	reqLogger.Debug("background refresh from hopper completed")
}

func serveFileDownload(w http.ResponseWriter, r *http.Request, sha, ip string) {
	if !validSHA256(sha) {
		http.Error(w, "invalid sha256", http.StatusBadRequest)
		return
	}

	reqLogger := logger.With("sha256", sha, "client_ip", ip)

	// Gate downloads to button-driven flows. The token in ?t=<…> is
	// session-bound and short-lived (csrfMaxAge), so a copy-pasted URL,
	// a search-engine fetch, or a wayback capture all fail. Mirrors the
	// rescan/upload CSRF protection but on a GET, where the token rides
	// in the query string rather than a form body.
	if !csrfValid(r, "download", r.URL.Query().Get("t")) {
		reqLogger.Warn("download rejected: missing or invalid token")
		http.Error(w, "download is button-only; reload the file page and try again", http.StatusForbidden)
		return
	}

	if !downloadRateLimiter.allow(ip) {
		reqLogger.Warn("download rate limited")
		w.Header().Set("Retry-After", "360")
		http.Error(w, "rate limit reached: 25 downloads per hour", http.StatusTooManyRequests)
		return
	}

	_, res, err := lookupResult(r.Context(), sha, reqLogger)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			http.Error(w, "not found", http.StatusNotFound)
		} else {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	if err := apiBreaker.allow(); err != nil {
		reqLogger.Warn("hopper download skipped", "error", err)
		w.Header().Set("Retry-After", "10")
		http.Error(w, "download temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, hopperFileURL(sha), http.NoBody)
	if err != nil {
		http.Error(w, "failed to prepare download", http.StatusInternalServerError)
		return
	}
	resp, err := hopperClient.Do(req) //nolint:gosec // hopperFileURL builds from admin-configured hopper-api host + validated SHA path; no user-controlled URL
	if err != nil {
		apiBreaker.failure()
		reqLogger.Warn("hopper download request failed", "error", err, "hopper_api_addr", hopperAPIAddr)
		http.Error(w, "download unavailable", http.StatusBadGateway)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			reqLogger.Debug("hopper download body close failed", "error", err)
		}
	}()
	if resp.StatusCode >= http.StatusInternalServerError {
		apiBreaker.failure()
	} else {
		apiBreaker.success()
	}

	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusNotFound:
			http.Error(w, "not found", http.StatusNotFound)
		case http.StatusBadRequest:
			http.Error(w, "invalid sha256", http.StatusBadRequest)
		case http.StatusServiceUnavailable:
			http.Error(w, "download unavailable", http.StatusServiceUnavailable)
		default:
			reqLogger.Warn("hopper download returned unexpected status", "status", resp.StatusCode)
			http.Error(w, "download unavailable", http.StatusBadGateway)
		}
		return
	}

	// Defense in depth: the UI hides the button above maxDownloadSize, but
	// a determined client could still hit /file/<sha>.dl directly. Require
	// hopper to advertise a Content-Length we can trust and reject above
	// the cap before streaming a single byte.
	contentLength := resp.Header.Get("Content-Length")
	size, err := strconv.ParseInt(contentLength, 10, 64)
	if err != nil || size < 0 {
		reqLogger.Warn("hopper download missing Content-Length", "value", contentLength)
		http.Error(w, "download unavailable", http.StatusBadGateway)
		return
	}
	if size > maxDownloadSize {
		reqLogger.Info("download rejected: file too large", "size_bytes", size, "max_bytes", maxDownloadSize)
		http.Error(w, "file exceeds the 400 MB browser download limit; use the litmus CLI", http.StatusRequestEntityTooLarge)
		return
	}

	filename := sanitizeDownloadFilename(res.Filename, sha)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{
		"filename": filename,
	}))
	w.Header().Set("Content-Length", contentLength)
	if lastModified := resp.Header.Get("Last-Modified"); lastModified != "" {
		w.Header().Set("Last-Modified", lastModified)
	}

	// Cap the streamed body to maxDownloadSize even if hopper lied about
	// Content-Length, so a misbehaving backend can't blow past the limit.
	if _, err := io.Copy(w, io.LimitReader(resp.Body, maxDownloadSize)); err != nil {
		reqLogger.Debug("download write failed", "error", err)
	}
}

// writeJSONError writes a JSON-encoded error envelope so the client never
// has to guess whether a response body is plain text or JSON.
func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg, "code": code}) //nolint:errcheck,errchkjson // payload is a map[string]string (JSON-safe); response already failed
}

// handleRescan accepts any user's request to re-queue a sample for analysis,
// gated only by a valid CSRF token (so the request demonstrably came from a
// recently-rendered page) and a server-side cooldown enforced atomically in
// the UPDATE statement. The cooldown — rescanCooldown, currently 15
// minutes — prevents rapid-fire re-queues from one user or a coordinated
// click. On success the sample's analysis fields are cleared in hopper so
// the next worker poll picks it up, and prism's local result cache for that
// SHA is invalidated.
func handleRescan(w http.ResponseWriter, r *http.Request) {
	sha := strings.ToLower(r.PathValue("sha256"))
	ip := clientIP(r)
	reqLogger := logger.With("sha256", sha, "client_ip", ip, "action", "rescan")

	if !validSHA256(sha) {
		writeJSONError(w, http.StatusBadRequest, "invalid_sha", "invalid SHA256")
		return
	}
	// The legitimate body is `csrf_token=<~70 bytes>` — 4 KiB is generous
	// and bounds resource use against a malicious huge-form POST.
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_form", "malformed request")
		return
	}
	if !csrfValid(r, "rescan", r.FormValue("csrf_token")) {
		writeJSONError(w, http.StatusForbidden, "bad_csrf", "CSRF token missing or expired; reload the page and try again")
		return
	}
	if !rescanLimiter.Allow() {
		reqLogger.Warn("rescan rate-limited")
		w.Header().Set("Retry-After", "1")
		writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "too many rescan requests; please wait a moment")
		return
	}
	if err := requestRescan(r.Context(), sha); err != nil {
		if errors.Is(err, errSampleNotEligible) {
			writeJSONError(w, http.StatusTooManyRequests, "not_eligible", "sample is not eligible — either it's an archive child, skipped, or was analyzed within the last 15 minutes")
			return
		}
		reqLogger.Error("rescan: hopper update failed", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "rescan_failed", "failed to queue rescan")
		return
	}
	reqLogger.Info("rescan queued")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "queued"}) //nolint:errcheck,errchkjson // map[string]string is JSON-safe
}

// hopperDSNHost extracts the host:port from a postgres DSN for logging.
// Credentials and database name are dropped so log lines stay safe to
// share. Returns "unknown" if the DSN can't be parsed — never returns the
// raw DSN, which could leak a password.
func hopperDSNHost(dsn string) string {
	if dsn == "" {
		return "unknown"
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Host == "" {
		return "unknown"
	}
	return u.Host
}

// connectHopperWithRetry runs in a background goroutine after a startup-
// time hopper.Open failure. It retries with exponential backoff capped at
// 2 minutes per attempt (per project xreliable standards) and keeps trying
// until the parent context is canceled. On success it publishes the handle
// via atomic.Pointer and kicks off the feed cache loop.
func connectHopperWithRetry(ctx context.Context) {
	host := hopperDSNHost(hopperDBDSN)
	logger.Info("scheduling background hopper reconnect", "hopper_db_host", host)
	attempt := 0
	retryErr := retry.Do(
		func() error {
			attempt++
			db, err := hopper.Open(ctx, hopperDBDSN)
			if err != nil {
				logger.Warn("hopper reconnect attempt failed",
					"hopper_db_host", host,
					"attempt", attempt,
					"error", err,
				)
				return err
			}
			if !hopperDB.CompareAndSwap(nil, db) {
				// Another goroutine beat us to it (shouldn't happen — only
				// startup and this loop write — but be defensive so we don't
				// leak the second pool).
				db.Close()
				return nil
			}
			logger.Info("hopper reconnected",
				"hopper_db_host", host,
				"attempt", attempt,
			)
			go refreshFeedCacheLoop(ctx)
			return nil
		},
		retry.Context(ctx),
		retry.Attempts(0), // retry forever until ctx cancels
		retry.Delay(1*time.Second),
		retry.MaxDelay(2*time.Minute),
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
		retry.LastErrorOnly(true),
	)
	if retryErr != nil && !errors.Is(retryErr, context.Canceled) {
		logger.Warn("hopper reconnect loop exited", "hopper_db_host", host, "error", retryErr)
	}
}

func hopperFileURL(sha string) string {
	base := strings.TrimSpace(hopperAPIAddr)
	if base == "" {
		base = defaultHopperAPIAddr
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	u, err := url.Parse(base)
	if err != nil {
		return "http://" + defaultHopperAPIAddr + "/api/file/" + sha
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/file/" + sha
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
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

// pendingPageData feeds templates/pending.html. SHA256JSON is the same
// value as SHA256, JSON-encoded so it can be safely embedded inside the
// inline <script> as a JS string literal under the strict CSP nonce.
type pendingPageData struct {
	Nonce       string // script-src nonce
	StyleNonce  string // style-src nonce
	BuildCommit string
	Filename    string
	SHA256      string
	SHA256JSON  template.JS
}

// renderPending serves the "Analyzing…" wait page for a SHA whose sample
// row exists in hopper but has no cleave_result yet. The page opens an
// SSE connection to /file/<sha>/wait that flips to a result-page reload
// the moment a worker writes the cleave result.
func renderPending(w http.ResponseWriter, r *http.Request, sha, filename string) {
	if filename == "" {
		filename = sha[:12] + "…"
	}
	shaJSON, err := json.Marshal(sha)
	if err != nil {
		shaJSON = []byte(`""`)
	}
	data := pendingPageData{
		Nonce:       nonceFor(r),
		StyleNonce:  styleNonceFor(r),
		BuildCommit: buildCommit,
		Filename:    filename,
		SHA256:      sha,
		SHA256JSON:  template.JS(shaJSON), //nolint:gosec // sha is validated 64-hex
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Pending pages must never be cached: a CDN that pins this could
	// serve "Analyzing…" forever even after the real result lands.
	w.Header().Set("Cache-Control", "no-store")
	if err := pendingTemplate.Execute(w, data); err != nil {
		logger.Error("template execution failed", "template", "pending", "error", err)
	}
}

const (
	// waitPollInterval controls how often the SSE wait loop checks hopper
	// for a populated cleave_result. 500 ms is fast enough that the
	// worker→browser delay is imperceptible (typical analyses take seconds)
	// while keeping hopper QPS bounded under many concurrent waiters.
	waitPollInterval = 500 * time.Millisecond
	// waitMaxClientsTotal caps simultaneous SSE waiters across all clients;
	// past this point we 503 new connections so a coordinated browser swarm
	// can't pin hopper. Real concurrent waiters in normal use are dozens.
	waitMaxClientsTotal = 256
	// waitMaxClientsPerIP caps simultaneous waiters from one source. A
	// single user only needs as many as they have open pending tabs.
	waitMaxClientsPerIP = 4
	// waitMaxDuration bounds a single SSE connection. The browser auto-
	// reconnects on close, so we recycle the underlying DB poll loop
	// every five minutes — bounding goroutine lifetime if a tab is left
	// open indefinitely.
	waitMaxDuration = 5 * time.Minute
	// waitHeartbeatInterval keeps proxies that buffer streamed responses
	// (nginx, Cloudflare) from killing the connection during long waits.
	// SSE comments are syntactic no-ops on the client side.
	waitHeartbeatInterval = 15 * time.Second
)

// sanitizeDownloadFilename produces a Content-Disposition-safe filename from
// a sample's stored filename. Strips path components, control bytes (Cc), and
// Unicode format chars (Cf) — the latter covers directional overrides like
// RLO that can disguise a binary's extension in the browser download UI.
// Falls back to sha when nothing usable remains.
func sanitizeDownloadFilename(stored, sha string) string {
	name := filepath.Base(strings.TrimSpace(stored))
	if name == "." || name == "/" || name == "" {
		return sha
	}
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		return sha
	}
	return out
}

// readyPayload returns the JSON body for the SSE "ready" event. sha has
// already been validated as 64-hex by handleFileWait, but using json.Marshal
// keeps escaping correct if the input shape ever changes.
func readyPayload(sha string) string {
	b, err := json.Marshal(map[string]string{"sha256": sha})
	if err != nil {
		return `{"sha256":""}`
	}
	return string(b)
}

// handleFileWait is the SSE notification channel for the pending page.
// It tight-polls hopper for cleave_result every waitPollInterval and
// emits a `ready` event the instant the column is populated. After
// emitting (or after waitMaxDuration) it closes the stream; the browser
// reloads on `ready` and EventSource auto-reconnects on natural close.
//
// The handler returns immediately for SHAs that are either already
// analyzed (worker finished between handleFile and SSE open) or absent
// from hopper entirely (404-like state) so the browser doesn't sit
// staring at "Analyzing…" forever.
func handleFileWait(w http.ResponseWriter, r *http.Request) {
	sha := strings.ToLower(r.PathValue("sha256"))
	if !validSHA256(sha) {
		http.Error(w, "invalid sha256", http.StatusBadRequest)
		return
	}
	db := hopperDB.Load()
	if db == nil {
		http.Error(w, "hopper not connected", http.StatusServiceUnavailable)
		return
	}

	ip := clientIP(r)
	if !waitAcquire(ip) {
		w.Header().Set("Retry-After", "30")
		http.Error(w, "too many concurrent waiters", http.StatusTooManyRequests)
		return
	}
	defer waitRelease(ip)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no") // nginx: disable response buffering
	w.WriteHeader(http.StatusOK)

	ctx, cancel := context.WithTimeout(r.Context(), waitMaxDuration)
	defer cancel()

	emit := func(event, data string) {
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
			return
		}
		flusher.Flush()
	}
	heartbeat := func() bool {
		if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	pollTicker := time.NewTicker(waitPollInterval)
	defer pollTicker.Stop()
	heartbeatTicker := time.NewTicker(waitHeartbeatInterval)
	defer heartbeatTicker.Stop()

	// Optional ?after=<unix-ms> turns this into a "wait for a re-analysis"
	// stream: ready only fires when AnalyzedAt is strictly later than the
	// caller's snapshot. Used by the rescan flow so the browser doesn't
	// pick up the already-stale analysis the rescan was meant to replace.
	after := parseAfterMillis(r.URL.Query().Get("after"))

	check := func() (state string, payload string) {
		if after.IsZero() {
			switch uploadViewState(ctx, sha) {
			case "ready":
				return "ready", readyPayload(sha)
			case "missing":
				return "missing", `{"reason":"not found"}`
			}
			return "pending", ""
		}
		// Fresh-analysis mode: pull the full row so we can compare the
		// timestamp. This is a heavier query than SampleAnalyzed but
		// only fires once per poll, well within hopper's budget.
		sample, err := db.SampleBySHA256(ctx, sha)
		if err != nil || sample == nil {
			return "missing", `{"reason":"not found"}`
		}
		if sample.AnalyzedAt != nil && sample.AnalyzedAt.After(after) {
			return "ready", readyPayload(sha)
		}
		return "pending", ""
	}

	// Initial probe before the first tick — covers the worker-finishes-
	// before-SSE-open race so the browser doesn't wait an extra 50 ms
	// for a result that already exists.
	if state, payload := check(); state == "missing" || state == "ready" {
		emit(state, payload)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeatTicker.C:
			if !heartbeat() {
				return
			}
		case <-pollTicker.C:
			state, payload := check()
			if state == "missing" || state == "ready" {
				emit(state, payload)
				return
			}
		}
	}
}

// uploadViewState reports whether sha is viewable yet on the normal (non-
// rescan) wait/status path: "ready" once either prism has cached a verdict
// (the litmus fast path) or hopper has analyzed the sample, "pending" while
// ingestion is still in flight, "missing" otherwise. lookupResult checks
// prism's cache before hopper, so a litmus-only result (hopper upload failed)
// still flips the page to the result view.
func uploadViewState(ctx context.Context, sha string) string {
	_, _, err := lookupResult(ctx, sha, logger)
	if err == nil {
		return "ready"
	}
	var pend *pendingAnalysisError
	if errors.As(err, &pend) {
		return "pending"
	}
	return "missing"
}

// parseAfterMillis parses an ?after=<unix-ms> query value into a UTC
// time. Returns the zero time on missing / invalid input so callers can
// fall back to the "no threshold" branch.
func parseAfterMillis(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	ms, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

// handleFileStatus is the no-SSE fallback for the pending page: a single
// JSON poll the page falls back to if EventSource gives up (no SSE
// support, hostile proxy, etc.). Same backing query as handleFileWait.
func handleFileStatus(w http.ResponseWriter, r *http.Request) {
	sha := strings.ToLower(r.PathValue("sha256"))
	if !validSHA256(sha) {
		http.Error(w, "invalid sha256", http.StatusBadRequest)
		return
	}
	db := hopperDB.Load()
	if db == nil {
		http.Error(w, `{"error":"hopper not connected"}`, http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	// `?after=<unix-ms>` makes ready dependent on a strictly newer
	// analysis, matching handleFileWait. Same use case: post-rescan
	// polling that needs to ignore the pre-rescan result.
	after := parseAfterMillis(r.URL.Query().Get("after"))
	exists := false
	ready := false
	var analyzedAtMillis int64
	if !after.IsZero() {
		sample, err := db.SampleBySHA256(ctx, sha)
		if err != nil {
			http.Error(w, `{"error":"lookup failed"}`, http.StatusInternalServerError)
			return
		}
		if sample != nil {
			exists = true
			if sample.AnalyzedAt != nil {
				analyzedAtMillis = sample.AnalyzedAt.UnixMilli()
				ready = sample.AnalyzedAt.After(after)
			}
		}
	} else {
		switch uploadViewState(ctx, sha) {
		case "ready":
			exists, ready = true, true
		case "pending":
			exists = true
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	resp := map[string]any{"exists": exists, "ready": ready}
	if analyzedAtMillis > 0 {
		resp["analyzed_at"] = analyzedAtMillis
	}
	_ = json.NewEncoder(w).Encode(resp) //nolint:errcheck,errchkjson // map[string]any with primitive values is JSON-safe
}

// hopperUploadResponse mirrors hopper's POST /api/upload response shape.
type hopperUploadResponse struct {
	SHA256          string `json:"sha256"`
	AlreadyAnalyzed bool   `json:"already_analyzed"`
	Size            int64  `json:"size"`
}

// hopperUploadURL builds the absolute URL of hopper's POST /api/upload
// endpoint, with the optional filename hint URL-encoded. Mirrors the
// shape of hopperFileURL so both routes resolve from the same admin-
// configured hopper-api host.
func hopperUploadURL(filename string) string {
	base := strings.TrimSpace(hopperAPIAddr)
	if base == "" {
		base = defaultHopperAPIAddr
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	u, err := url.Parse(base)
	if err != nil {
		u = &url.URL{Scheme: "http", Host: defaultHopperAPIAddr}
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/upload"
	q := url.Values{}
	if filename != "" {
		q.Set("filename", filename)
	}
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String()
}

// handleUpload streams a browser upload directly to hopper's /api/upload
// without buffering. The browser sends a multipart/form-data body with two
// fields, csrf_token (first) and file (second); we iterate them with
// MultipartReader so the file bytes flow straight from the inbound
// connection to the outbound hopper connection. No temp file in prism, no
// in-memory copy of the payload, no synchronous analysis on the request
// path — hopper picks up the row via its upload-tier worker queue and
// prism's /file/<sha> page (with the SSE wait endpoint) shows the result
// the moment a worker finishes.
//
// uploadEnabled gates browser uploads. Controlled via the --uploads CLI
// flag or PRISM_UPLOADS env var (1/true/yes/on to enable); both default
// to off so a fresh deploy is closed-by-default. When false the handler
// short-circuits to a 503 and the UI greys out the button.
var uploadEnabled = false

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

	if !uploadEnabled {
		reqLogger.Info("upload rejected: feature temporarily disabled")
		renderError(w, r, http.StatusServiceUnavailable, errorData{
			Icon:    "⏸",
			Title:   "Upload temporarily disabled",
			Message: "Uploads are temporarily disabled while we rework this feature.",
		})
		return
	}

	// Global cap first: catches IP-rotating abuse that would otherwise
	// slip past the per-IP limiter. Per-IP cap second: protects against
	// a single noisy client hammering a fresh budget.
	if !uploadGlobalLimiter.Allow() {
		reqLogger.Warn("upload rate limited (global)")
		renderError(w, r, http.StatusTooManyRequests, errorData{
			Icon:    "⏳",
			Title:   "Rate limit reached",
			Message: "The upload queue is busy. Please wait a moment and try again.",
		})
		return
	}
	if !uploadRateLimiter.allow(ip) {
		reqLogger.Warn("upload rate limited")
		renderError(w, r, http.StatusTooManyRequests, errorData{
			Icon:    "⏳",
			Title:   "Rate limit reached",
			Message: "Too many uploads. Please wait 30 seconds before trying again.",
		})
		return
	}
	reqLogger.Info("upload request received")

	// 100 MB body cap (the multipart envelope adds a small overhead beyond
	// the file payload; pad so a 100 MB file with normal boundary/headers
	// still fits).
	const maxUploadSize = 100 * 1024 * 1024
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize+1<<20)

	// Outbound timeout to hopper — generous to cover a 100 MB upload over
	// slow links plus hopper's local fsync and DB insert.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	reader, err := r.MultipartReader()
	if err != nil {
		reqLogger.Warn("multipart reader init failed", "error", err)
		renderError(w, r, http.StatusBadRequest, errorData{
			Icon:    "⚠",
			Title:   "Upload failed",
			Message: "Something went wrong reading your file. Please try again.",
		})
		return
	}

	csrfChecked := false
	// Bound the number of multipart parts we'll process. Legitimate uploads
	// have two (csrf_token + file). Adversarial requests with thousands of
	// empty parts would otherwise consume CPU on header parsing under the
	// body-byte cap. 8 is generous headroom for browsers that might serialize
	// extras (e.g. a future "_charset_" field).
	const maxParts = 8
	parts := 0
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		parts++
		if parts > maxParts {
			reqLogger.Warn("upload rejected: too many multipart parts", "parts", parts)
			if part != nil {
				_ = part.Close() //nolint:errcheck // best-effort
			}
			renderError(w, r, http.StatusBadRequest, errorData{
				Icon:    "⚠",
				Title:   "Upload failed",
				Message: "Malformed upload. Please try again.",
			})
			return
		}
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				reqLogger.Warn("upload rejected: file too large", "max_bytes", maxUploadSize)
				renderError(w, r, http.StatusRequestEntityTooLarge, errorData{
					Icon:  "⚖",
					Title: "File too large",
					MessageHTML: `The web interface accepts files up to 100 MB. For larger files, use ` +
						`<a href="https://codeberg.org/atomdrift/litmus">litmus</a>, our open-source command-line tool — no size limits.`,
				})
				return
			}
			reqLogger.Warn("multipart next-part failed", "error", err)
			renderError(w, r, http.StatusBadRequest, errorData{
				Icon:    "⚠",
				Title:   "Upload failed",
				Message: "Something went wrong reading your file. Please try again.",
			})
			return
		}

		switch part.FormName() {
		case "csrf_token":
			buf, rerr := io.ReadAll(io.LimitReader(part, 1024))
			_ = part.Close() //nolint:errcheck // best-effort
			if rerr != nil || !csrfValid(r, "upload", string(buf)) {
				reqLogger.Warn("invalid or missing CSRF token", "read_err", rerr)
				renderError(w, r, http.StatusForbidden, errorData{
					Icon:    "🔒",
					Title:   "Session expired",
					Message: "Your form session has expired. Please reload the page and try again.",
				})
				return
			}
			csrfChecked = true

		case "file":
			if !csrfChecked {
				// Browsers serialize hidden inputs in DOM order, so csrf_token
				// (declared first in the upload template) always reaches the
				// server before the file field. Anything else is either a
				// hand-crafted client or tampering.
				_ = part.Close() //nolint:errcheck // best-effort
				reqLogger.Warn("file part arrived before csrf_token")
				renderError(w, r, http.StatusForbidden, errorData{
					Icon:    "🔒",
					Title:   "Session expired",
					Message: "Your form session has expired. Please reload the page and try again.",
				})
				return
			}
			serveUploadedFile(ctx, w, r, part, maxUploadSize, requestStart, reqLogger)
			return

		default:
			_ = part.Close() //nolint:errcheck // ignore unknown parts
		}
	}

	// Ran out of parts without seeing "file".
	reqLogger.Warn("upload missing file part")
	renderError(w, r, http.StatusBadRequest, errorData{
		Icon:    "⚠",
		Title:   "No file received",
		Message: "We didn't receive a file. Please select a file and try again.",
	})
}

// serveUploadedFile buffers the multipart file part, creates the sample row in
// hopper (which must exist before any result can be published to it), starts
// the litmus fast path, and redirects to the result page. On any failure it
// renders the matching error page. It closes part before returning.
func serveUploadedFile(ctx context.Context, w http.ResponseWriter, r *http.Request, part *multipart.Part, maxUploadSize int64, requestStart time.Time, reqLogger *slog.Logger) {
	filename := filepath.Base(part.FileName())
	reqLogger = reqLogger.With("filename", filename)

	// Buffer the file once and identify it by content hash — the same sha256
	// hopper and litmus derive from the bytes — so we never depend on a backend
	// to tell us where to send the user. Cap the part even though the whole
	// request is already behind MaxBytesReader: a malformed multipart with one
	// giant non-file leading part could otherwise waste memory first. A
	// MaxBytesError surfaces here as the body cap trips.
	buf, rerr := io.ReadAll(io.LimitReader(part, maxUploadSize))
	_ = part.Close() //nolint:errcheck // best-effort
	if rerr != nil {
		var maxErr *http.MaxBytesError
		if errors.As(rerr, &maxErr) {
			reqLogger.Warn("upload rejected: file too large", "max_bytes", maxUploadSize)
			renderError(w, r, http.StatusRequestEntityTooLarge, errorData{
				Icon:  "⚖",
				Title: "File too large",
				MessageHTML: `The web interface accepts files up to 100 MB. For larger files, use ` +
					`<a href="https://codeberg.org/atomdrift/litmus">litmus</a>, our open-source command-line tool — no size limits.`,
			})
			return
		}
		reqLogger.Warn("upload read failed", "error", rerr)
		renderError(w, r, http.StatusBadRequest, errorData{
			Icon:    "⚠",
			Title:   "Upload failed",
			Message: "Something went wrong reading your file. Please try again.",
		})
		return
	}

	sum := sha256.Sum256(buf)
	sha := hex.EncodeToString(sum[:])
	reqLogger = reqLogger.With("sha256", sha)
	reqLogger.Info("upload received; ingesting via litmus and hopper",
		"size", len(buf),
		"total_duration_ms", time.Since(requestStart).Milliseconds(),
	)

	// Ingest on litmus and hopper concurrently in the background; either path
	// alone makes /file/<sha> render. Mark the sha in-flight first so the page
	// shows an "analyzing" state (not a 404) during the window before either
	// backend has a result.
	uploadsInFlight.Store(sha, filename)
	go ingestUpload(context.WithoutCancel(ctx), buf, sha, filename)

	http.Redirect(w, r, "/file/"+sha, http.StatusSeeOther)
}

// errUploadTokenUnavailable means hopper hasn't yet provisioned the upload
// token (typically because the hopper service is still warming up). The
// upload handler surfaces this as a 503-equivalent UX to the user.
var errUploadTokenUnavailable = errors.New("hopper upload token unavailable")

// uploadTokenKey is the hopper KV key carrying the Bearer token for
// POST /api/upload. Rotations are signalled by hopper returning 401 to a
// previously-valid token; the next read picks up the new value.
const uploadTokenKey = "upload_token"

// uploadToHopper POSTs buf to hopper /api/upload with a Bearer token read
// from hopper's KV table. buf is already buffered by the caller so the
// request can be safely retried with backoff (and so the 401 rotation path
// can resend the same bytes). On a 401 (token rotation signal) we re-read the
// token from KV and retry the upload exactly once.
func uploadToHopper(ctx context.Context, buf []byte, filename string, log *slog.Logger) (*hopperUploadResponse, error) {
	db := hopperDB.Load()
	if db == nil {
		return nil, errUploadTokenUnavailable
	}
	target := hopperUploadURL(filename)

	token, err := fetchUploadToken(ctx, db, log)
	if err != nil {
		return nil, err
	}
	resp, err := postUploadWithRetry(ctx, target, buf, token, log)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		_ = resp.Body.Close() //nolint:errcheck // best-effort
		log.Warn("hopper rejected upload token; refetching and retrying once")
		token, err = fetchUploadToken(ctx, db, log)
		if err != nil {
			return nil, err
		}
		resp, err = postUploadWithRetry(ctx, target, buf, token, log) //nolint:bodyclose // closed by readUploadResponse below
		if err != nil {
			return nil, err
		}
	}
	return readUploadResponse(resp, log)
}

// fetchUploadToken reads the upload token from hopper's KV with exponential
// backoff and jitter. ErrNotFound is treated as terminal — it signals that
// hopper hasn't been provisioned yet, and no amount of retrying will help
// inside this request's lifetime; we map it to errUploadTokenUnavailable so
// the handler can render a clean "warming up" page.
func fetchUploadToken(ctx context.Context, db *hopper.DB, log *slog.Logger) (string, error) {
	var token string
	err := retry.Do(
		func() error {
			v, err := db.KVGet(ctx, uploadTokenKey)
			if errors.Is(err, hopper.ErrNotFound) {
				return retry.Unrecoverable(errUploadTokenUnavailable)
			}
			if err != nil {
				return err
			}
			token = v
			return nil
		},
		retry.Context(ctx),
		// Bound retry budget so a hopper outage doesn't keep an upload
		// request alive for the full 5-minute context window. 6 attempts
		// with 200 ms base + backoff caps total wait around 3–4 seconds,
		// which is fast enough for the user to see a "warming up" page.
		retry.Attempts(6),
		retry.Delay(200*time.Millisecond),
		retry.MaxDelay(10*time.Second),
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
		retry.LastErrorOnly(true),
		retry.OnRetry(func(n uint, err error) {
			log.Warn("upload token fetch retry", "attempt", n+1, "error", err)
		}),
	)
	if errors.Is(err, errUploadTokenUnavailable) {
		return "", errUploadTokenUnavailable
	}
	if err != nil {
		return "", fmt.Errorf("fetch upload token: %w", err)
	}
	return token, nil
}

// postUploadWithRetry POSTs to hopper /api/upload with exponential backoff
// and jitter. Only transport errors and 5xx responses trigger a retry —
// 4xx (including 401) is returned to the caller as-is so token-rotation
// handling stays in uploadToHopper. The retry budget is bounded by ctx.
func postUploadWithRetry(ctx context.Context, target string, buf []byte, token string, log *slog.Logger) (*http.Response, error) {
	var resp *http.Response
	err := retry.Do(
		func() error {
			r, err := postOnce(ctx, target, buf, token)
			if err != nil {
				// An open breaker means hopper-api is already known-down;
				// retrying would only add to the load. Stop immediately.
				if errors.Is(err, errBreakerOpen) {
					return retry.Unrecoverable(err)
				}
				return err
			}
			if r.StatusCode >= 500 {
				snippet, _ := io.ReadAll(io.LimitReader(r.Body, 1024)) //nolint:errcheck // diagnostics only
				_ = r.Body.Close()                                     //nolint:errcheck // best-effort
				return fmt.Errorf("hopper /api/upload status %d: %s", r.StatusCode, strings.TrimSpace(string(snippet)))
			}
			resp = r
			return nil
		},
		retry.Context(ctx),
		retry.Attempts(0),
		retry.Delay(500*time.Millisecond),
		retry.MaxDelay(30*time.Second),
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
		retry.LastErrorOnly(true),
		retry.OnRetry(func(n uint, err error) {
			log.Warn("hopper upload retry", "attempt", n+1, "error", err)
		}),
	)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// postOnce performs a single POST /api/upload with the given Bearer token.
// Body is read from buf so retries can replay it.
func postOnce(ctx context.Context, target string, buf []byte, token string) (*http.Response, error) {
	if err := apiBreaker.allow(); err != nil {
		return nil, fmt.Errorf("hopper-api upload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(buf))
	if err != nil {
		// Local build error: hopper was never contacted; don't move the breaker.
		return nil, fmt.Errorf("build hopper request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := hopperClient.Do(req) //nolint:gosec // hopperUploadURL builds from admin-configured hopper-api host; filename is URL-encoded
	if err != nil {
		apiBreaker.failure()
		return nil, fmt.Errorf("hopper request: %w", err)
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		apiBreaker.failure()
	} else {
		apiBreaker.success()
	}
	return resp, nil
}

// readUploadResponse closes resp and parses hopper's JSON envelope.
func readUploadResponse(resp *http.Response, log *slog.Logger) (*hopperUploadResponse, error) {
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Debug("hopper response body close failed", "error", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 4096)) //nolint:errcheck // diagnostics only
		return nil, fmt.Errorf("hopper /api/upload status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var ur hopperUploadResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&ur); err != nil {
		return nil, fmt.Errorf("decode hopper response: %w", err)
	}
	if !validSHA256(ur.SHA256) {
		return nil, fmt.Errorf("hopper returned invalid sha256: %q", ur.SHA256)
	}
	return &ur, nil
}

// Upload ingestion tuning.
const (
	// uploadIngestTimeout bounds the background ingestion of one upload across
	// both paths (litmus analyze + cache + publish, and the hopper store). The
	// user already has the result page; this is the patience budget before we
	// give up. Generous enough for a slow 100 MB hopper store or a full litmus
	// analyze of a large archive.
	uploadIngestTimeout = 10 * time.Minute
	// litmusWorkerName identifies prism when it publishes a result to hopper's
	// POST /api/result — the same channel hopper's pull workers use.
	litmusWorkerName = "prism"
	// maxLitmusResponseBytes bounds the /analyze response we'll read, matching
	// hopper's own result-body ceiling so a runaway report can't exhaust memory.
	maxLitmusResponseBytes = 256 << 20
	// maxConcurrentLitmus caps in-flight litmus analyses. Each holds a multipart
	// copy of the file (up to the upload cap) for the analysis duration, so
	// without a bound an upload burst could pin large amounts of memory and
	// overrun the litmus server. When all slots are busy a new upload skips the
	// fast path; hopper still stores it durably and its own worker analyzes it.
	maxConcurrentLitmus = 8
)

// litmusSlots is the maxConcurrentLitmus semaphore: a token per in-flight
// litmus analysis, acquired non-blocking so a saturated fast path degrades to
// hopper rather than queueing memory-heavy work.
var litmusSlots = make(chan struct{}, maxConcurrentLitmus)

// uploadsInFlight tracks shas whose upload is being ingested in the background
// (sha -> filename string). lookupResult renders a pending "analyzing" page for
// these instead of a 404 during the window before hopper has the sample row or
// litmus has cached a verdict.
var uploadsInFlight sync.Map

// litmusEnvelope is the subset of litmus /analyze's {"ml":…,"raw":…} response
// that prism forwards to hopper. Error is set when litmus reports a structured
// failure.
type litmusEnvelope struct {
	Error string          `json:"error"`
	ML    json.RawMessage `json:"ml"`
	Raw   json.RawMessage `json:"raw"`
}

// litmusAnalyzeURL builds the absolute URL of the litmus server's POST
// /analyze endpoint, or "" when litmus is disabled.
func litmusAnalyzeURL() string {
	base := strings.TrimSpace(litmusAddr)
	if base == "" {
		return ""
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/analyze"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// ingestUpload drives the two independent ingestion paths for a freshly
// uploaded sample, concurrently:
//
//   - litmus fast path: analyze on the dedicated litmus server and cache the
//     verdict in prism's own result cache, so /file/<sha> renders immediately
//     even if hopper never accepts the sample.
//   - hopper upload: store the bytes durably and queue the sample for hopper's
//     own worker pool.
//
// Either path alone lets the page render error-free. When BOTH succeed, prism
// publishes the litmus verdict to hopper's /api/result so its workers skip the
// re-analysis — gated on the upload, because /api/result is an UPDATE keyed by
// sha that silently no-ops (returns 200, writes nothing) for a sample that
// doesn't exist yet. If BOTH fail the sample is unviewable, which we log
// loudly. Runs detached from the request via the caller's WithoutCancel.
func ingestUpload(ctx context.Context, buf []byte, sha, filename string) {
	ctx, cancel := context.WithTimeout(ctx, uploadIngestTimeout)
	defer cancel()
	defer uploadsInFlight.Delete(sha)
	log := logger.With("sha256", sha, "filename", filename)

	var (
		wg                 sync.WaitGroup
		litmusOK, hopperOK bool
		env                *litmusEnvelope
		analyzeMs          int64
	)

	wg.Go(func() {
		if _, err := uploadToHopper(ctx, buf, filename, log); err != nil {
			log.Error("upload to hopper failed", "error", err)
			return
		}
		hopperOK = true
	})

	if target := litmusAnalyzeURL(); target != "" {
		wg.Go(func() {
			// Take a slot, or skip the fast path when saturated — hopper still
			// ingests durably, so the sample is never lost, just analyzed by
			// hopper's worker instead.
			select {
			case litmusSlots <- struct{}{}:
				defer func() { <-litmusSlots }()
			default:
				log.Warn("litmus fast path at capacity; leaving sample for hopper worker",
					"max_concurrent", maxConcurrentLitmus)
				return
			}
			start := time.Now()
			e, err := analyzeWithLitmus(ctx, target, buf, filename)
			if err != nil {
				log.Error("litmus analyze failed", "error", err)
				return
			}
			// Cache the verdict in prism immediately so the result page renders
			// even if the hopper upload never succeeds.
			cacheLitmusResult(ctx, sha, filename, e, int64(len(buf)), log)
			env, analyzeMs, litmusOK = e, time.Since(start).Milliseconds(), true
		})
	}
	wg.Wait()

	if litmusOK && hopperOK {
		if err := publishResultToHopper(ctx, sha, env, analyzeMs); err != nil {
			log.Warn("publishing litmus result to hopper failed; hopper worker will re-analyze", "error", err)
		}
	}

	switch {
	case litmusOK && hopperOK:
		log.Info("upload ingested via litmus and hopper")
	case litmusOK:
		log.Warn("upload ingested via litmus only; hopper upload failed (sample not durably stored in hopper)")
	case hopperOK:
		log.Warn("upload ingested via hopper only; litmus fast path failed (hopper worker will analyze)")
	default:
		log.Error("UPLOAD INGESTION FAILED: neither litmus nor hopper accepted the sample; it is not viewable")
	}
}

// cacheLitmusResult stores a litmus verdict in prism's result cache so
// /file/<sha> renders without waiting on (or needing) hopper. The litmus
// /analyze envelope is already the {ml,raw} shape prism stores as RawLitmus.
func cacheLitmusResult(ctx context.Context, sha, filename string, env *litmusEnvelope, size int64, log *slog.Logger) {
	// Synchronous Set (not SetAsync): the value must be visible in the cache
	// before the caller marks the litmus path done and the in-flight marker is
	// cleared, otherwise a poll could briefly 404 a result we already have.
	if err := cache.Set(ctx, sha, storedResultFromLitmus(filename, env, size)); err != nil {
		log.Warn("caching litmus result failed", "error", err)
	}
}

// storedResultFromLitmus builds a cacheable result from a litmus /analyze
// envelope. Mirrors storedResultFromHopperSample but sources everything from
// the envelope plus the known upload metadata (uploads carry no provenance).
func storedResultFromLitmus(filename string, env *litmusEnvelope, size int64) storedResult {
	envelope := map[string]json.RawMessage{}
	if json.Valid(env.ML) {
		envelope["ml"] = env.ML
	}
	if json.Valid(env.Raw) {
		envelope["raw"] = env.Raw
	}
	rawLitmus, err := json.Marshal(envelope)
	if err != nil {
		rawLitmus = []byte("{}")
	}
	classification := ""
	if len(env.ML) > 0 {
		var mlResp litmusMlResponse
		if json.Unmarshal(env.ML, &mlResp) == nil {
			classification = classificationName(mlResp.verdictClass())
		}
	}
	now := time.Now().UTC()
	return storedResult{
		Filename:       filename,
		RawLitmus:      string(rawLitmus),
		Classification: classification,
		CachedAt:       now,
		AnalyzedAt:     now,
		CreatedAt:      now,
		SizeBytes:      size,
	}
}

// analyzeWithLitmus POSTs buf to litmus POST /analyze as multipart/form-data
// (one part named "file") and returns the ml/raw sections of the response
// envelope. A non-200 status, a structured error body, or a missing ml
// section is reported as an error so the caller falls back to hopper's worker.
func analyzeWithLitmus(ctx context.Context, target string, buf []byte, filename string) (*litmusEnvelope, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return nil, fmt.Errorf("build multipart: %w", err)
	}
	if _, err := part.Write(buf); err != nil {
		return nil, fmt.Errorf("write multipart: %w", err)
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("close multipart: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, &body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := litmusClient.Do(req) //nolint:gosec // target built from admin-configured litmus host, not user input
	if err != nil {
		return nil, fmt.Errorf("litmus request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort
	rd := io.LimitReader(resp.Body, maxLitmusResponseBytes)
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(rd, 1024)) //nolint:errcheck // diagnostics only
		return nil, fmt.Errorf("litmus status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var env litmusEnvelope
	if err := json.NewDecoder(rd).Decode(&env); err != nil {
		return nil, fmt.Errorf("decode litmus response: %w", err)
	}
	if env.Error != "" {
		return nil, fmt.Errorf("litmus error: %s", env.Error)
	}
	if len(env.ML) == 0 {
		return nil, errors.New("litmus response missing ml section")
	}
	return &env, nil
}

// hopperResultRequest mirrors hopper's POST /api/result body — the same shape
// a litmus worker posts. prism uses it to publish a fast-path verdict for an
// already-uploaded sample.
type hopperResultRequest struct {
	SHA256     string          `json:"sha256"`
	Worker     string          `json:"worker"`
	ML         json.RawMessage `json:"ml"`
	Raw        json.RawMessage `json:"raw"`
	DurationMs int64           `json:"duration_ms"`
}

// hopperResultURL builds the absolute URL of hopper's POST /api/result
// endpoint from the same admin-configured hopper-api host as the other routes.
func hopperResultURL() string {
	base := strings.TrimSpace(hopperAPIAddr)
	if base == "" {
		base = defaultHopperAPIAddr
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	u, err := url.Parse(base)
	if err != nil {
		u = &url.URL{Scheme: "http", Host: defaultHopperAPIAddr}
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/result"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// publishResultToHopper POSTs a litmus verdict to hopper's /api/result so the
// sample is marked analyzed without hopper's worker pool repeating the work.
// The same per-dependency breaker that guards other hopper-api calls applies.
func publishResultToHopper(ctx context.Context, sha string, env *litmusEnvelope, durationMs int64) error {
	if err := apiBreaker.allow(); err != nil {
		return fmt.Errorf("hopper-api result: %w", err)
	}
	body, err := json.Marshal(hopperResultRequest{
		SHA256:     sha,
		Worker:     litmusWorkerName,
		ML:         env.ML,
		Raw:        env.Raw,
		DurationMs: durationMs,
	})
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hopperResultURL(), bytes.NewReader(body))
	if err != nil {
		// Local build error: hopper was never contacted; don't move the breaker.
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hopperClient.Do(req) //nolint:gosec // hopperResultURL built from admin-configured hopper-api host
	if err != nil {
		apiBreaker.failure()
		return fmt.Errorf("hopper request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort
	if resp.StatusCode >= http.StatusInternalServerError {
		apiBreaker.failure()
	} else {
		apiBreaker.success()
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // diagnostics only
		return fmt.Errorf("hopper /api/result status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
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

	if !res.CachedAt.IsZero() {
		analyzedAt := res.AnalyzedAt
		if analyzedAt.IsZero() {
			analyzedAt = res.CachedAt
		}
		data.AnalyzedAt = analyzedAt.Format("2 Jan 2006 15:04 UTC")
		data.AnalyzedAgo = timeAgo(time.Since(analyzedAt))
		data.AnalyzedAtMillis = analyzedAt.UnixMilli()
		data.RescanAllowed = time.Since(analyzedAt) >= rescanCooldown
	}
	data.SourceURL, data.SourceLabel = sourceDisplay(res.SourceURL, res.SourceDomain)
	if res.Ecosystem != "" {
		data.Ecosystem = res.Ecosystem
		data.EcosystemURL = ecosystemURL(res.Ecosystem)
	}
	if !res.CreatedAt.IsZero() {
		data.FirstSeenAt = res.CreatedAt.Format("2 Jan 2006 15:04 UTC")
		data.FirstSeenAgo = timeAgo(time.Since(res.CreatedAt))
	}
	// Provenance draws only on the stored sample fields above, so it is
	// built here — before the litmus parse — and survives the parse-failure
	// early return below. filename is passed raw; the template escapes it.
	data.Provenance = provenanceGroups(sha256Hex, filename, res)

	// Parse raw litmus response envelope: {"ml": {...}, "raw": {...}}.
	var fullResp litmusFullResponse
	if err := json.Unmarshal([]byte(res.RawLitmus), &fullResp); err != nil {
		logger.Debug("failed to parse raw litmus response", "sha256", sha256Hex, "error", err)
		data.Formula = template.HTML("?")
		return data
	}
	var mlResp litmusMlResponse
	if err := json.Unmarshal(fullResp.ML, &mlResp); err != nil {
		logger.Debug("failed to parse ml section", "sha256", sha256Hex, "error", err)
	}

	// Use thresholds from litmus response, with sensible defaults.
	data.SuspiciousT = mlResp.suspiciousT()
	data.HostileT = mlResp.hostileT()
	if data.SuspiciousT == 0 {
		data.SuspiciousT = 0.65
	}
	if data.HostileT == 0 {
		data.HostileT = 0.887
	}
	// v=5 exact-rendering path: Threshold > 0 makes templates branch to
	// bandGradient2; Level surfaces the FPR severity that selected the
	// threshold (nil when manual thresholds were used).
	//
	// v=6/v7 have no envelope-level threshold or class on the wire; the level
	// marker carries both the verdict (-1 = benign) and the FPR level when known.
	// Templates fall back to the legacy two-edge gradient when Threshold is
	// zero, so we only populate Threshold/Class for v=5.
	switch mlResp.V {
	case "5":
		data.Threshold = mlResp.Threshold
		data.Class = mlResp.Classification
		data.Level = mlResp.Level
	case "6", "7":
		data.Level = mlResp.L
		data.LevelConfidence = mlResp.Confidence
	}

	report := &cleaveReport{}
	if len(fullResp.Raw) > 0 {
		if err := json.Unmarshal(fullResp.Raw, report); err != nil {
			logger.Debug("failed to parse cleave data", "sha256", sha256Hex, "error", err)
		}
	}

	// Normalize paths: replace the temp file path with the real uploaded filename
	// for any top-level file (depth=0, no archive separator). Cleave reports the
	// path it analyzed on the server, which may be a tmp path.
	for i := range report.Files {
		if report.Files[i].Depth == 0 && !strings.Contains(report.Files[i].Path, "!!") {
			report.Files[i].Path = filename
		}
	}

	// Merge ML classifications from ml.files into cleave report files (matched by id).
	// Threshold is per-file in v=5 envelopes; zero for v=4 inputs. v6/v7 entries
	// carry a level marker instead of class/threshold, so the class is derived from it.
	mlByID := make(map[int]struct {
		L         *int
		Class     int
		Prob      float64
		Threshold float64
	}, len(mlResp.Files))
	for _, f := range mlResp.Files {
		class := f.Class
		if mlResp.V == "6" || mlResp.V == "7" {
			class = classFromLevel(f.L)
		}
		mlByID[f.ID] = struct {
			L         *int
			Class     int
			Prob      float64
			Threshold float64
		}{f.L, class, f.Prob, f.Threshold}
	}
	for i := range report.Files {
		ml, ok := mlByID[report.Files[i].ID]
		if !ok {
			continue
		}
		report.Files[i].Classification = classificationName(ml.Class)
		report.Files[i].Probability = ml.Prob
		report.Files[i].Threshold = ml.Threshold
		report.Files[i].Class = ml.Class
		// Envelope-level threshold/class/band edges with this file's own
		// probability and level, matching the prior per-file template logic.
		report.Files[i].Gradient = stampGradient(mlResp.V, ml.L, ml.Prob, data.Threshold, data.SuspiciousT, data.HostileT, data.Class)
	}

	if len(report.Files) == 0 {
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
			data.SizeBytes = file.Size
			break
		}
	}
	// Fallback to first file if no depth=0 found
	if data.FileType == "" && len(report.Files) > 0 {
		data.FileType = strings.ToUpper(report.Files[0].FileType)
		data.Size = formatBytes(report.Files[0].Size)
		data.SizeBytes = report.Files[0].Size
	}

	// Prefer hopper's authoritative size over anything derived from the
	// cleave report: compacted and pre-v7 root entries carry no entry-level
	// size, so the report alone yields 0 bytes for those samples.
	if res.SizeBytes > 0 {
		data.SizeBytes = res.SizeBytes
		data.Size = formatBytes(res.SizeBytes)
	}

	// Extract findings for formula generation
	var findings []FindingForFormula
	var totalFindings int

	for i := range report.Files {
		file := &report.Files[i]
		for _, f := range file.Findings {
			totalFindings++
			findings = append(findings, FindingForFormula{
				ID:       f.ID,
				Severity: critIntToSeverity(f.Crit),
			})
		}
	}

	data.FindingCount = strconv.Itoa(totalFindings)

	// Build traits lookup for molecule info panel (trait ID → description + evidence).
	traitDetails := make(map[string]*TraitDetail)
	for i := range report.Files {
		for _, f := range report.Files[i].Findings {
			if _, exists := traitDetails[f.ID]; exists {
				continue // deduplicate
			}
			td := &TraitDetail{Desc: f.Desc, Crit: critIntToString(f.Crit)}
			td.Evidence = append(td.Evidence, f.Evidence...)
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

	// Verdict-stamp gradient for the top-level file. v6/v7 color by level; older
	// envelopes fall back to the threshold-based band.
	data.StampGradient = stampGradient(mlResp.V, data.Level, data.Probability, data.Threshold, data.SuspiciousT, data.HostileT, data.Class)
	if mlResp.V != "6" && mlResp.V != "7" {
		data.LevelConfidence = levelConfidence(data.Level)
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

	// Sort archive files by ML probability so all tabs show the most interesting
	// files at the top. Depth-0 (the archive container itself) stays first
	// regardless of score.
	sort.SliceStable(report.Files, func(i, j int) bool {
		if report.Files[i].Depth == 0 {
			return true
		}
		if report.Files[j].Depth == 0 {
			return false
		}
		return report.Files[i].Probability > report.Files[j].Probability
	})

	// For large archives, truncate to the top 100 most critical files.
	// The depth-0 container is always first (guaranteed by the sort above).
	const maxArchiveFiles = 100
	if len(report.Files) > maxArchiveFiles {
		report.Files = report.Files[:maxArchiveFiles]
	}

	// Build structured data for table display
	data.FileFindings = buildStructuredFindings(report.Files)
	data.FileStrings = buildStructuredStrings(report.Files)
	data.FileSymbols = buildStructuredSymbols(report.Files)
	data.FileSections = buildStructuredSections(report.Files)
	data.FileMetrics = buildStructuredMetrics(report.Files)
	data.FileKVs = buildStructuredKV(report.Files)
	data.ArchiveCategories, data.ArchiveTraitTotal, data.ArchiveTraitShown = aggregateArchiveCategories(report.Files)

	// The File tab renders cleave's per-file context view and, when present,
	// becomes the default tab. It is populated only for reports carrying
	// current-format context, so legacy samples keep Traits as the default.
	data.FileViews = buildFileViews(report.Files)
	if src, hex := contentLocCh(data.FileViews); src > 0 || hex > 0 {
		data.ContentLocStyle = template.HTMLAttr(fmt.Sprintf(`style="--ctx-loc-src-ch:%d;--ctx-loc-hex-ch:%d"`, src, hex))
	}

	// IsArchive reflects the underlying file set, not the findings count: an
	// archive whose children are all clean still has multiple files and
	// should render the aggregated archive Traits tab.
	data.IsArchive = len(report.Files) > 1

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
	data.FormulaQuery = desubscriptFormula(formula)

	// Generate molecule/galaxy data for 3D visualization
	// For archives with multiple files, build a galaxy
	if len(report.Files) > 1 {
		var fileFindings []FileFindings
		for i := range report.Files {
			file := &report.Files[i]
			var ff []FindingForFormula
			for _, f := range file.Findings {
				ff = append(ff, FindingForFormula{
					ID:       f.ID,
					Severity: critIntToSeverity(f.Crit),
				})
			}

			if len(ff) > 0 {
				fileFindings = append(fileFindings, FileFindings{
					Path:           file.Path,
					Risk:           critIntToString(maxCritInFile(file)),
					Classification: file.Classification,
					Probability:    file.Probability,
					Formula:        file.Formula,
					Findings:       ff,
					Strings:        galaxyStrings(file),
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

// maxCritInFile returns the highest criticality ordinal from a file's traits.
func maxCritInFile(f *cleaveFile) int {
	best := 0
	for _, t := range f.Findings {
		if t.Crit > best {
			best = t.Crit
		}
	}
	return best
}

// parseStringTupleValue extracts the value from a v4 string tuple.
// Format: [offset, value] or [offset, encoding, value]. Errors are
// silently swallowed: a malformed tuple just yields an empty result.
// galaxyStrings gathers the strings from a cleave file that BuildGalaxy scans
// for dropper relationships. That scan is O(files² × strings × len) and
// file.Strings comes straight from the attacker-influenced analysis envelope,
// so a crafted archive (many long strings) could turn every render of the file
// page into seconds of CPU. The count and per-string length are capped here;
// real dropper references are short path/filename strings, so the bound does
// not change normal detection.
func galaxyStrings(file *cleaveFile) []string {
	const (
		maxGalaxyStrings   = 2000
		maxGalaxyStringLen = 4096
	)
	var strs []string
	add := func(v string) {
		if len(strs) < maxGalaxyStrings && len(v) <= maxGalaxyStringLen {
			strs = append(strs, v)
		}
	}
	for _, s := range file.Strings {
		if len(strs) >= maxGalaxyStrings {
			break
		}
		for _, v := range parseStringTupleValue(s) {
			add(v)
		}
	}
	for _, f := range file.Findings {
		if len(strs) >= maxGalaxyStrings {
			break
		}
		for _, e := range f.Evidence {
			add(e)
		}
	}
	return strs
}

func parseStringTupleValue(raw json.RawMessage) []string {
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil || len(arr) < 2 {
		return nil
	}
	var val string
	switch {
	case len(arr) == 2:
		_ = json.Unmarshal(arr[1], &val) //nolint:errcheck // tuple shape known; bad data → empty val handled below
	case len(arr) >= 3:
		_ = json.Unmarshal(arr[2], &val) //nolint:errcheck // tuple shape known; bad data → empty val handled below
	}
	if val == "" {
		return nil
	}
	return []string{val}
}

// canonicalCategoryOrder is the preferred display order for top-level
// trait categories across the result page (both archive aggregation and
// per-file views). Categories not listed here render after all known
// ones, sorted alphabetically by key for determinism.
var canonicalCategoryOrder = []string{"well-known", "objectives", "micro-behaviors", "metadata", "third_party"}

// maxSampleTraits caps how many trait cards a single sample's Traits tab
// renders. The survivors are the highest criticality*confidence traits;
// callers surface the dropped count as a "N of M traits shown" note.
const maxSampleTraits = 20

// minTraitConfidence is the floor below which a finding is hidden entirely:
// low-confidence matches are too noisy to surface even as baseline traits.
// Every cleave finding carries a confidence score (its `c` field), so the
// comparison is a straight threshold.
const minTraitConfidence = 0.65

// confPct converts a 0..1 confidence score into a whole-number percentage,
// rounded to nearest (conf is never negative, so the +0.5 truncation rounds
// correctly without pulling in math.Round).
func confPct(conf float64) int {
	return int(conf*100 + 0.5)
}

// scoredTrait pairs a display-ready trait with the numeric criticality and
// confidence used to rank it against the top-N cap.
type scoredTrait struct {
	topLevel string
	display  FindingDisplay
	crit     int
	conf     float64
}

// selectTopTraits keeps the highest criticality*confidence traits up to
// maxSampleTraits and groups the survivors into canonically-ordered
// categories. It returns the grouped categories, the total number of traits
// before the cap, and how many survived. Within each category traits stay
// ordered by criticality (desc) then ID, matching the rest of the report.
func selectTopTraits(scored []scoredTrait, displayNames map[string]string) (groups []CategoryGroup, total, shown int) {
	total = len(scored)
	// A total order keeps the top-N cut and display order deterministic
	// across runs: the source bucket is a map (randomized iteration), so
	// without the topLevel/ID tie-breakers an equal-score tie at the cap
	// boundary could keep different traits on different runs and bust the
	// page cache.
	sort.Slice(scored, func(i, j int) bool {
		si := float64(scored[i].crit) * scored[i].conf
		sj := float64(scored[j].crit) * scored[j].conf
		if si != sj {
			return si > sj
		}
		if scored[i].crit != scored[j].crit {
			return scored[i].crit > scored[j].crit
		}
		if scored[i].display.ID != scored[j].display.ID {
			return scored[i].display.ID < scored[j].display.ID
		}
		return scored[i].topLevel < scored[j].topLevel
	})
	if len(scored) > maxSampleTraits {
		scored = scored[:maxSampleTraits]
	}
	shown = len(scored)

	byCat := make(map[string][]scoredTrait)
	for _, s := range scored {
		byCat[s.topLevel] = append(byCat[s.topLevel], s)
	}
	categoryMap := make(map[string][]FindingDisplay, len(byCat))
	for cat, items := range byCat {
		sort.SliceStable(items, func(i, j int) bool {
			if items[i].crit != items[j].crit {
				return items[i].crit > items[j].crit
			}
			return items[i].display.ID < items[j].display.ID
		})
		fds := make([]FindingDisplay, len(items))
		for i, it := range items {
			fds[i] = it.display
		}
		categoryMap[cat] = fds
	}
	return orderCategories(categoryMap, displayNames), total, shown
}

// orderCategories assembles categoryMap's entries into a []CategoryGroup
// in the canonical order defined by canonicalCategoryOrder, with empty
// findings dropped and unknown categories appended alphabetically.
func orderCategories(categoryMap map[string][]FindingDisplay, displayNames map[string]string) []CategoryGroup {
	known := make(map[string]struct{}, len(canonicalCategoryOrder))
	for _, k := range canonicalCategoryOrder {
		known[k] = struct{}{}
	}
	var out []CategoryGroup
	for _, cat := range canonicalCategoryOrder {
		findings := categoryMap[cat]
		if len(findings) == 0 {
			continue
		}
		name, ok := displayNames[cat]
		if !ok {
			name = cat
		}
		out = append(out, CategoryGroup{Name: name, Findings: findings})
	}
	var unknown []string
	for cat, findings := range categoryMap {
		if _, k := known[cat]; k {
			continue
		}
		if len(findings) == 0 {
			continue
		}
		unknown = append(unknown, cat)
	}
	sort.Strings(unknown)
	for _, cat := range unknown {
		name, ok := displayNames[cat]
		if !ok {
			name = cat
		}
		out = append(out, CategoryGroup{Name: name, Findings: categoryMap[cat]})
	}
	return out
}

// resolveMatchFile maps cleave's compact `loc` location string to the
// inner file it refers to. Returns nil when the location is empty, isn't
// a file reference (semantic labels like "import", plain byte offsets), or
// doesn't resolve to any known inner file (nested archives we didn't extract).
// Callers use the result to set Path/SHA256 on a FindingMatch; when nil
// the match falls back to either the current file (when not the
// archive container) or a path-less evidence row.
//
// Two location shapes are accepted for backward compatibility:
//   - v7/current: "<file-id>[:<offset>]" — a digit-led token; the member path
//     is resolved once via the file's id instead of being embedded per entry.
//   - v5 (legacy/cached): "archive:<member-path>[:<offset>]".
func resolveMatchFile(location string, pathToFile map[string]*cleaveFile, idToFile map[int]*cleaveFile) *cleaveFile {
	if location == "" {
		return nil
	}
	if id, ok := parseLocationID(location); ok {
		return idToFile[id]
	}
	const prefix = "archive:"
	member := strings.TrimPrefix(location, prefix)
	if member == location {
		return nil
	}
	if f, ok := pathToFile[member]; ok {
		return f
	}
	// Archives-in-archives: cleave uses "outer.tgz!inner.go" with a
	// single `!`; our flat file list stores those as "outer.tgz!!inner.go".
	return pathToFile[strings.ReplaceAll(member, "!", "!!")]
}

// parseLocationID parses the v7 `loc` form "<file-id>[:<offset>]" and returns the
// file id. Reports false for the legacy "archive:…" / "offset:…" strings and
// anything whose leading token isn't a plain non-negative integer — the
// "archive:" prefix keeps a member literally named with digits from being
// misread as an id.
func parseLocationID(location string) (int, bool) {
	tok := location
	if i := strings.IndexByte(tok, ':'); i >= 0 {
		tok = tok[:i]
	}
	if tok == "" {
		return 0, false
	}
	id, err := strconv.Atoi(tok)
	if err != nil || id < 0 {
		return 0, false
	}
	return id, true
}

// chromaStylesheet is the chroma syntax-highlighting CSS. Built once at
// startup so every result page can inline it without re-running the
// formatter.
var chromaStylesheet = func() template.CSS {
	s := styles.Get("github")
	if s == nil {
		s = styles.Fallback
	}
	var sb strings.Builder
	formatter := chromahtml.New(chromahtml.WithClasses(true))
	if err := formatter.WriteCSS(&sb, s); err != nil {
		return ""
	}
	return template.CSS(sb.String()) //nolint:gosec // chroma CSS is library output, no user input
}()

// highlightEvidence renders an evidence fragment as chroma tokens, picking
// the lexer from the source filename. Returns nil when the inputs are empty
// or no lexer matches; the template then falls back to plain text.
func highlightEvidence(evidence, filename string) []EvidenceToken {
	if evidence == "" || filename == "" {
		return nil
	}
	lexer := lexers.Match(filename)
	if lexer == nil {
		return nil
	}
	lexer = chroma.Coalesce(lexer)
	iter, err := lexer.Tokenise(nil, evidence)
	if err != nil {
		return nil
	}
	var out []EvidenceToken
	for tok := iter(); tok != chroma.EOF; tok = iter() {
		out = append(out, EvidenceToken{Class: chroma.StandardTypes[tok.Type], Text: tok.Value})
	}
	return out
}

// locationOffset extracts the within-file position from a `loc` entry: the
// "<offset>" of the v7 "<file-id>:<offset>" form or of the legacy
// "offset:<n>" form. Returns "" for entries that carry no position (bare
// file ids and "archive:…" member paths).
func locationOffset(location string) string {
	if after, ok := strings.CutPrefix(location, "offset:"); ok {
		return after
	}
	if _, ok := parseLocationID(location); !ok {
		return ""
	}
	if _, after, ok := strings.Cut(location, ":"); ok {
		return after
	}
	return ""
}

// evidenceRow is one resolved match for a finding before file attribution:
// the snippet text, its within-file offset, whether it is a hex dump (so the
// caller skips source highlighting), and locRef — the raw legacy `loc` string
// (e.g. "1:0x3718c0" or "archive:pkg/x.go") used to back-attribute a rolled-up
// match to an inner archive member. ctx-sourced rows leave locRef empty
// because they already belong to the file that carries them.
type evidenceRow struct {
	text   string
	offset string
	locRef string
	hex    bool
}

// contextIndex maps each full trait ID to the evidence rows the file's v7
// `ctx` array attributes to it. Returns nil for pre-v7 files with no ctx.
func contextIndex(file *cleaveFile) map[string][]evidenceRow {
	if len(file.Ctx) == 0 {
		return nil
	}
	idx := make(map[string][]evidenceRow)
	for w := range file.Ctx {
		win := &file.Ctx[w]
		for _, n := range win.Notes {
			idx[n.ID] = append(idx[n.ID], evidenceRow{
				text:   win.Text,
				offset: formatOffset(n.Offset, win.Hex),
				hex:    win.Hex,
			})
		}
	}
	return idx
}

// evidenceRows returns the match rows for a finding, preferring v7 `ctx`
// attribution (via idx) and falling back to the finding's inline `ev`/`loc`
// so older reports still expand.
func evidenceRows(f finding, idx map[string][]evidenceRow) []evidenceRow {
	if rows := idx[f.ID]; len(rows) > 0 {
		return rows
	}
	rows := make([]evidenceRow, len(f.Evidence))
	for i, ev := range f.Evidence {
		rows[i] = evidenceRow{text: ev}
		if i < len(f.Locations) {
			rows[i].locRef = f.Locations[i]
		}
	}
	return rows
}

// formatOffset renders a byte offset for display: hex (matching the hex-dump
// convention) for binary context, decimal otherwise.
func formatOffset(off int64, isHex bool) string {
	if isHex {
		return fmt.Sprintf("0x%x", off)
	}
	return strconv.FormatInt(off, 10)
}

// matchTokens highlights ev as source unless it is a hex dump, which is not
// lexable as code.
func matchTokens(ev, filename string, isHex bool) []EvidenceToken {
	if isHex {
		return nil
	}
	return highlightEvidence(ev, filename)
}

// aggregateArchiveCategories merges every file's findings into one category
// list, deduped by trait-ID directory prefix. Used by the archive Traits tab.
// Unlike per-file aggregation, this version attributes every aggregated trait
// back to the files that contributed, so the UI can expand a trait into
// "filename — location — evidence" rows.
//
//nolint:gocognit // inherently complex: trait bucketing plus per-evidence file back-attribution
func aggregateArchiveCategories(files []cleaveFile) (groups []CategoryGroup, total, shown int) {
	categoryNames := map[string]string{
		"objectives":      "Objectives",
		"micro-behaviors": "Micro-behaviors",
		"metadata":        "Metadata",
		"well-known":      "Well-known",
		"third_party":     "Third-party",
	}

	type aggregated struct {
		matches  map[string]*FindingMatch
		dirPath  string
		topLevel string
		desc     string
		order    []string
		crit     int
		conf     float64
	}
	bucket := make(map[string]*aggregated)
	// Track which SHAs are archive containers (depth 0). When a trait fires
	// inside the archive as well as on the container itself, the container
	// entry is just a rollup of inner-file findings — link to the actual
	// file the trait was inherited from, not the wrapping archive.
	containerSHAs := make(map[string]bool)
	// Maps used to back-attribute container-level findings to the inner file
	// that actually produced the match. Cleave's compact `el` carries one
	// reference per evidence item: v6 reports use a numeric "<fs-id>" we look
	// up in idToFile; legacy v5 reports use an "archive:<member-path>" string
	// we resolve against the same `displayPath` form used elsewhere.
	pathToFile := make(map[string]*cleaveFile)
	idToFile := make(map[int]*cleaveFile)
	for i := range files {
		if files[i].Depth == 0 {
			containerSHAs[files[i].SHA256] = true
			continue
		}
		pathToFile[displayPath(files[i].Path)] = &files[i]
		idToFile[files[i].ID] = &files[i]
	}

	for i := range files {
		file := &files[i]
		ctxIdx := contextIndex(file)
		for _, f := range file.Findings {
			if f.Crit < 1 || f.Conf < minTraitConfidence {
				continue
			}
			parts := strings.Split(f.ID, "/")
			if len(parts) < 2 {
				continue
			}
			topLevel := parts[0]
			var dirPath string
			if len(parts) > 2 {
				dirPath = strings.Join(parts[1:len(parts)-1], "/")
			} else {
				dirPath = parts[1]
			}
			key := topLevel + "/" + dirPath

			agg, ok := bucket[key]
			if !ok {
				agg = &aggregated{
					dirPath:  dirPath,
					topLevel: topLevel,
					crit:     f.Crit,
					conf:     f.Conf,
					desc:     f.Desc,
					matches:  make(map[string]*FindingMatch),
				}
				bucket[key] = agg
			} else if f.Crit > agg.crit || (f.Crit == agg.crit && f.Conf > agg.conf) {
				agg.crit = f.Crit
				agg.conf = f.Conf
				agg.desc = f.Desc
			}
			// Resolve each match into a (filename, location, evidence) row.
			// v7 ctx rows belong to this file directly; legacy inline rows
			// may carry a `loc` hint that back-attributes a container rollup
			// to the inner file that produced it. Container-as-source is
			// dropped: it's a rollup, not a real source file.
			for _, row := range evidenceRows(f, ctxIdx) {
				ev := row.text
				path, sha, loc := "", "", row.offset
				if row.locRef != "" {
					loc = locationOffset(row.locRef)
					if target := resolveMatchFile(row.locRef, pathToFile, idToFile); target != nil {
						path = displayPath(target.Path)
						sha = target.SHA256
					}
				}
				if sha == "" && file.Depth > 0 {
					// No cleave hint, but we know the finding lives on
					// this inner file directly — use it as the source.
					path = displayPath(file.Path)
					sha = file.SHA256
				}
				if containerSHAs[sha] {
					// Drop the archive container as a source. Keep the
					// evidence text; the row just has no filename column.
					path, loc = "", ""
				}
				mk := ev + "\x00" + path + "\x00" + loc
				if m, ok := agg.matches[mk]; ok {
					m.Count++
				} else {
					base := extractBasename(path)
					agg.matches[mk] = &FindingMatch{
						Evidence: ev,
						Path:     path,
						Filename: base,
						Location: loc,
						Tokens:   matchTokens(ev, base, row.hex),
						Count:    1,
					}
					agg.order = append(agg.order, mk)
				}
			}
		}
	}
	if len(bucket) == 0 {
		return nil, 0, 0
	}

	scored := make([]scoredTrait, 0, len(bucket))
	for _, agg := range bucket {
		matches := make([]FindingMatch, 0, len(agg.matches))
		for _, k := range agg.order {
			matches = append(matches, *agg.matches[k])
		}
		sort.SliceStable(matches, func(i, j int) bool {
			if matches[i].Count != matches[j].Count {
				return matches[i].Count > matches[j].Count
			}
			// Matches with file attribution sort ahead of bare evidence
			// so fully-described rows are visually grouped at the top.
			if (matches[i].Path != "") != (matches[j].Path != "") {
				return matches[i].Path != ""
			}
			if matches[i].Evidence != matches[j].Evidence {
				return matches[i].Evidence < matches[j].Evidence
			}
			if matches[i].Path != matches[j].Path {
				return matches[i].Path < matches[j].Path
			}
			return matches[i].Location < matches[j].Location
		})
		const maxMatches = 24
		if len(matches) > maxMatches {
			matches = matches[:maxMatches]
		}
		scored = append(scored, scoredTrait{
			topLevel: agg.topLevel,
			crit:     agg.crit,
			conf:     agg.conf,
			display: FindingDisplay{
				ID:      agg.dirPath,
				Crit:    critIntToString(agg.crit),
				Desc:    agg.desc,
				ConfPct: confPct(agg.conf),
				Matches: matches,
			},
		})
	}

	return selectTopTraits(scored, categoryNames)
}

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

	for i := range files {
		file := &files[i]
		if len(file.Findings) == 0 {
			continue
		}
		ctxIdx := contextIndex(file)
		base := extractBasename(file.Path)

		// Aggregate findings by directory path (everything except last component)
		// Key: "topLevel/dirPath", Value: best finding for that directory
		type aggregatedFinding struct {
			matches  map[string]*FindingMatch
			dirPath  string
			topLevel string
			desc     string
			order    []string
			fullIDs  []string
			crit     int
			conf     float64
		}
		aggregated := make(map[string]*aggregatedFinding)

		// addMatch records one evidence row under a trait, deduping identical
		// (text, offset) pairs and bumping the repeat count instead. Per-file
		// findings don't carry path attribution — we're already in this file's
		// context — but its name still picks the syntax-highlighting lexer.
		addMatch := func(agg *aggregatedFinding, row evidenceRow) {
			if row.text == "" {
				return
			}
			mk := row.text + "\x00" + row.offset
			if m, ok := agg.matches[mk]; ok {
				m.Count++
				return
			}
			agg.matches[mk] = &FindingMatch{
				Evidence: row.text,
				Location: row.offset,
				Tokens:   matchTokens(row.text, base, row.hex),
				Count:    1,
			}
			agg.order = append(agg.order, mk)
		}

		for _, f := range file.Findings {
			// Include everything down to component (1) above the confidence
			// floor; the top-N cap below decides which traits actually render.
			if f.Crit < 1 || f.Conf < minTraitConfidence {
				continue
			}

			// Split into parts: topLevel / rest
			parts := strings.Split(f.ID, "/")
			if len(parts) < 2 {
				continue
			}

			topLevel := parts[0]

			// Directory path is everything except the last component, excluding top-level
			var dirPath string
			if len(parts) > 2 {
				dirPath = strings.Join(parts[1:len(parts)-1], "/")
			} else {
				dirPath = parts[1]
			}

			key := topLevel + "/" + dirPath

			agg, ok := aggregated[key]
			if !ok {
				agg = &aggregatedFinding{
					dirPath:  dirPath,
					topLevel: topLevel,
					crit:     f.Crit,
					conf:     f.Conf,
					desc:     f.Desc,
					matches:  make(map[string]*FindingMatch),
				}
				aggregated[key] = agg
			} else if f.Crit > agg.crit || (f.Crit == agg.crit && f.Conf > agg.conf) {
				agg.crit = f.Crit
				agg.conf = f.Conf
				agg.desc = f.Desc
			}
			agg.fullIDs = append(agg.fullIDs, f.ID)
			for _, row := range evidenceRows(f, ctxIdx) {
				addMatch(agg, row)
			}
		}

		// Score each aggregated trait so the top-N cap can keep the highest
		// criticality*confidence ones across every category.
		scored := make([]scoredTrait, 0, len(aggregated))
		for _, agg := range aggregated {
			matches := make([]FindingMatch, 0, len(agg.matches))
			for _, k := range agg.order {
				matches = append(matches, *agg.matches[k])
			}
			sort.SliceStable(matches, func(i, j int) bool {
				if matches[i].Count != matches[j].Count {
					return matches[i].Count > matches[j].Count
				}
				if matches[i].Evidence != matches[j].Evidence {
					return matches[i].Evidence < matches[j].Evidence
				}
				return matches[i].Location < matches[j].Location
			})
			if len(matches) > 8 {
				matches = matches[:8]
			}

			scored = append(scored, scoredTrait{
				topLevel: agg.topLevel,
				crit:     agg.crit,
				conf:     agg.conf,
				display: FindingDisplay{
					ID:      agg.dirPath, // Show directory path without top-level
					Crit:    critIntToString(agg.crit),
					Desc:    agg.desc,
					ConfPct: confPct(agg.conf),
					Matches: matches,
					Context: contextForTraits(file, agg.fullIDs),
				},
			})
		}

		categories, traitTotal, traitShown := selectTopTraits(scored, categoryNames)

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
				Risk:           critIntToString(maxCritInFile(file)),
				Classification: file.Classification,
				Probability:    file.Probability,
				SHA256:         file.SHA256,
				Formula:        file.Formula,
				FileType:       strings.ToUpper(file.FileType),
				Categories:     categories,
				TraitTotal:     traitTotal,
				TraitShown:     traitShown,
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
					end:   *sec.Offset + uint64(sec.Size), //nolint:gosec // sec.Size guarded > 0 above; cleave never emits negative section sizes
				})
			}
		}

		var strs []StringDisplay
		for _, raw := range file.Strings {
			// v4 string tuples: [offset, value] or [offset, encoding, value].
			// Sub-element parse errors degrade to zero values — bad tuples
			// just render with an empty string or offset 0.
			var arr []json.RawMessage
			if json.Unmarshal(raw, &arr) != nil || len(arr) < 2 {
				continue
			}
			var offset uint64
			_ = json.Unmarshal(arr[0], &offset) //nolint:errcheck // offset 0 fallback acceptable
			var value string
			if len(arr) == 2 {
				_ = json.Unmarshal(arr[1], &value) //nolint:errcheck // empty-string fallback acceptable
			} else {
				_ = json.Unmarshal(arr[2], &value) //nolint:errcheck // empty-string fallback acceptable
			}

			// Compute section from offset
			section := ""
			if len(sectionRanges) > 0 {
				for _, sr := range sectionRanges {
					if offset >= sr.start && offset < sr.end {
						section = sr.name
						break
					}
				}
			}
			strs = append(strs, StringDisplay{
				Value:   value,
				Section: section,
				Offset:  fmt.Sprintf("0x%x", offset),
			})
		}

		// Sort by offset. Parse failures sort as 0, which is fine — the
		// offset string was produced by fmt.Sprintf("0x%x", uint64) above
		// so this is effectively unreachable.
		sort.Slice(strs, func(i, j int) bool {
			oi, _ := strconv.ParseUint(strings.TrimPrefix(strs[i].Offset, "0x"), 16, 64) //nolint:errcheck // self-produced format; parse won't fail
			oj, _ := strconv.ParseUint(strings.TrimPrefix(strs[j].Offset, "0x"), 16, 64) //nolint:errcheck // self-produced format; parse won't fail
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
			Risk:           critIntToString(maxCritInFile(file)),
			Classification: file.Classification,
			Probability:    file.Probability,
			SHA256:         file.SHA256,
			Formula:        file.Formula,
			FileType:       strings.ToUpper(file.FileType),
			Strings:        strs,
			Sections:       sections,
			Gradient:       file.Gradient,
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
			imports = append(imports, SymbolDisplay{
				Name: s,
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
			Risk:           critIntToString(maxCritInFile(file)),
			Classification: file.Classification,
			Probability:    file.Probability,
			SHA256:         file.SHA256,
			Formula:        file.Formula,
			FileType:       strings.ToUpper(file.FileType),
			Imports:        imports,
			Exports:        exports,
			Gradient:       file.Gradient,
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
			Risk:           critIntToString(maxCritInFile(file)),
			Classification: file.Classification,
			Probability:    file.Probability,
			SHA256:         file.SHA256,
			Formula:        file.Formula,
			FileType:       strings.ToUpper(file.FileType),
			Sections:       sections,
			Gradient:       file.Gradient,
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
			Risk:           critIntToString(maxCritInFile(file)),
			Classification: file.Classification,
			Probability:    file.Probability,
			SHA256:         file.SHA256,
			Formula:        file.Formula,
			FileType:       strings.ToUpper(file.FileType),
			Groups:         groups,
			Gradient:       file.Gradient,
		})
	}

	return result
}

// buildStructuredKV converts each file's flat structural kv map into
// sorted display rows. Values are rendered as plain strings — strings keep
// their text, numbers/bools format directly, and arrays/objects fall back
// to their compact JSON form so callers can still see the shape.
func buildStructuredKV(files []cleaveFile) []FileKVDisplay {
	var result []FileKVDisplay
	for i := range files {
		file := &files[i]
		if len(file.KV) == 0 {
			continue
		}
		keys := make([]string, 0, len(file.KV))
		for k := range file.KV {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		pairs := make([]KVPair, 0, len(keys))
		for _, k := range keys {
			pairs = append(pairs, KVPair{Key: k, Value: kvValueString(file.KV[k])})
		}
		result = append(result, FileKVDisplay{
			Basename:       extractBasename(file.Path),
			Risk:           critIntToString(maxCritInFile(file)),
			Classification: file.Classification,
			Probability:    file.Probability,
			SHA256:         file.SHA256,
			Formula:        file.Formula,
			FileType:       strings.ToUpper(file.FileType),
			Pairs:          pairs,
		})
	}
	return result
}

// kvValueString renders a JSON-encoded leaf as a human-friendly string.
// Strings unwrap; integers and floats stringify; booleans become
// "true"/"false"; null becomes the empty string. Arrays and objects fall
// through to the compact JSON form so the shape is still visible.
func kvValueString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return strings.TrimSpace(string(raw))
	}
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		return strings.TrimSpace(string(raw))
	}
}

// timeAgo returns a human-readable relative time string (e.g. "5 minutes ago").
func timeAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
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

// displayPath strips archive-container prefixes ("foo.tar!!bar.tgz!!path/x")
// so users see the inner file path they'd see if the archive were unpacked.
// Falls back to the input unchanged when no separator is present.
func displayPath(p string) string {
	if i := strings.LastIndex(p, "!!"); i >= 0 {
		return p[i+2:]
	}
	return p
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
// litmusAPIResponse matches the v4 compact litmus JSON output.
// Fields like formula, file_type, sha256 are embedded in cleave files[0],
// not at the top level.
// litmusFullResponse matches the top-level {"ml": {...}, "raw": {...}} envelope.
type litmusFullResponse struct {
	ML  json.RawMessage `json:"ml"`
	Raw json.RawMessage `json:"raw"`
}

// litmusMlResponse matches the ml section of the litmus response. Accepts
// v=4 (Thresholds pair), v=5 (single Threshold + Level), and v=6/v7 (L plus
// optional Conf; `class` and `threshold` removed; benign signaled by L == -1).
// Parsing goes through a custom UnmarshalJSON that tries the v7 shape first and falls
// back to v6/v5 fields when `lvl` is absent.
//
// Field semantics after parse:
//   - L (v=6/v7): nullable i32. -1 = benign; otherwise the per-100M-benigns level
//     that selected the firing hostile threshold; nil = hostile via manual
//     --threshold-hostile (no level applies).
//   - Classification (back-compat): integer 0/1/2 derived consumer-side via
//     envelopeClass(L) for v=6/v7 inputs; carried from JSON for v=4/v=5.
//   - Confidence (v=6/v7): ml.conf when present, otherwise derived from L for
//     cached envelopes produced before litmus exported conf.
//   - Threshold (back-compat): only populated by v=4/v=5 envelopes. Zero
//     for v=6/v7 — templates fall back to the legacy two-edge gradient.
//
//nolint:govet // field order mirrors litmus's emitted JSON for readability
type litmusMlResponse struct {
	V          string `json:"-"`
	Version    string `json:"-"`
	AnalyzedAt string `json:"-"`
	Files      []struct {
		L         *int    `json:"lvl"`  // v=6/v7 only; per-member verdict-and-level marker
		Conf      *int    `json:"conf"` // v=6/v7 only; per-member display/export confidence
		ID        int     `json:"id"`
		Class     int     `json:"class"` // v=4/v=5 only
		Prob      float64 `json:"prob"`
		Threshold float64 `json:"threshold"` // v=5 only
	} `json:"-"`
	Thresholds     [2]float64 `json:"-"` // v=4 only
	Threshold      float64    `json:"-"` // v=5 only
	L              *int       `json:"-"` // v=6/v7: -1 benign / hostile@level / nil hostile@manual
	Confidence     int        `json:"-"` // v=6/v7: ml.conf when present, else derived from L
	Level          *int       `json:"-"` // v=5 only; kept for back-compat parsing
	Classification int        `json:"-"`
	Probability    float64    `json:"-"`
}

// UnmarshalJSON parses a litmus ml-section envelope. It accepts v=7 (the
// current wire format: `lvl`/`conf`, no `class`/`threshold`) and falls back to
// v=6 (`l`/`conf`) and then
// v=4/v=5 (`class`, `threshold`, `level`) for cached results produced before
// the v7 rename. The fallback path is the reason the type holds both `L` and
// `Level` / `Threshold` / `Classification` simultaneously.
func (r *litmusMlResponse) UnmarshalJSON(data []byte) error {
	// v7 wire shape. `lvl` is nullable i32: -1 (benign), grid level (hostile at
	// that FPR level), or null (hostile via manual threshold). `conf` is the
	// optional level-derived display/export confidence.
	var current struct {
		Conf       *int   `json:"conf"`
		L          *int   `json:"lvl"`
		OldL       *int   `json:"l"`
		V          string `json:"v"`
		Version    string `json:"version"`
		AnalyzedAt string `json:"analyzed_at"`
		Files      []struct {
			Conf *int    `json:"conf"`
			L    *int    `json:"lvl"`
			OldL *int    `json:"l"`
			ID   int     `json:"id"`
			Prob float64 `json:"prob"`
		} `json:"files"`
		OldFiles []struct {
			Conf *int    `json:"conf"`
			L    *int    `json:"l"`
			ID   int     `json:"id"`
			Prob float64 `json:"prob"`
		} `json:"fs"`
		Prob float64 `json:"prob"` // raw model score used for the top-level decision
	}
	if err := json.Unmarshal(data, &current); err != nil {
		return err
	}
	if current.L == nil {
		current.L = current.OldL
	}
	if len(current.Files) == 0 {
		for _, f := range current.OldFiles {
			current.Files = append(current.Files, struct {
				Conf *int    `json:"conf"`
				L    *int    `json:"lvl"`
				OldL *int    `json:"l"`
				ID   int     `json:"id"`
				Prob float64 `json:"prob"`
			}{Conf: f.Conf, L: f.L, ID: f.ID, Prob: f.Prob})
		}
	}
	for i := range current.Files {
		if current.Files[i].L == nil {
			current.Files[i].L = current.Files[i].OldL
		}
	}
	// v5/v4 back-compat shape. Read independently so cached envelopes that
	// still carry `class`/`threshold`/`level` continue to parse.
	var legacy struct {
		Level *int `json:"level"`
		Files []struct {
			ID        int     `json:"id"`
			Class     int     `json:"class"`
			Prob      float64 `json:"prob"`
			Threshold float64 `json:"threshold"`
		} `json:"fs"`
		Thresholds     [2]float64 `json:"thresholds"`
		Threshold      float64    `json:"threshold"`
		Classification int        `json:"class"`
	}
	_ = json.Unmarshal(data, &legacy) //nolint:errcheck // best-effort; ignore type mismatches

	r.V = current.V
	r.Version = current.Version
	r.AnalyzedAt = current.AnalyzedAt
	r.Probability = current.Prob
	r.L = current.L
	r.Level = legacy.Level
	r.Thresholds = legacy.Thresholds
	r.Threshold = legacy.Threshold
	if isCurrentWire(current.V, current.L) {
		r.Confidence = confidenceFromWire(current.Conf, current.L)
	} else {
		r.Confidence = levelConfidence(legacy.Level)
	}

	// Derive Classification from v6/v7 `L` when available; fall back to the
	// legacy `class` JSON field for older envelopes.
	switch {
	case isCurrentWire(current.V, current.L):
		r.Classification = envelopeClass(current.L)
	default:
		r.Classification = legacy.Classification
	}

	// Merge per-file entries. v6/v7 files[] entries carry id+prob+level; per-member
	// `lvl` is fully resolved by litmus — a benign member inside a hostile
	// archive emits `lvl: -1`, a hostile member without its own level
	// inherits the envelope's level (or `null` for manual). Derive Class
	// per-member from each member's level, falling back to the envelope-level
	// classification if a member omitted it entirely (defensive — current
	// litmus always emits it). v5/v4 fs[] entries carry id+class+prob
	// (+threshold for v5); keep those values when this is a legacy envelope.
	isCurrent := isCurrentWire(current.V, current.L)
	r.Files = r.Files[:0]
	if isCurrent {
		for _, f := range current.Files {
			memberClass := r.Classification
			if f.L != nil {
				memberClass = envelopeClass(f.L)
			}
			r.Files = append(r.Files, struct {
				L         *int    `json:"lvl"`
				Conf      *int    `json:"conf"`
				ID        int     `json:"id"`
				Class     int     `json:"class"`
				Prob      float64 `json:"prob"`
				Threshold float64 `json:"threshold"`
			}{ID: f.ID, Class: memberClass, Prob: f.Prob, L: f.L, Conf: confidencePointerFromWire(f.Conf, f.L)})
		}
		return nil
	}
	for _, lf := range legacy.Files {
		r.Files = append(r.Files, struct {
			L         *int    `json:"lvl"`
			Conf      *int    `json:"conf"`
			ID        int     `json:"id"`
			Class     int     `json:"class"`
			Prob      float64 `json:"prob"`
			Threshold float64 `json:"threshold"`
		}{ID: lf.ID, Class: lf.Class, Prob: lf.Prob, Threshold: lf.Threshold})
	}
	return nil
}

// CriticalLevel is prism's consumer-side cutoff between hostile and suspicious
// on the per-100M-benigns scale. A v6/v7 envelope's level is the strictest grid
// level at which the file fires; level <= CriticalLevel means it fires at or
// below our critical line (hostile), higher levels mean it only fires
// in the noisier tail (suspicious), and `-1` means it never fires (benign).
// Mirrors DefaultSeverityLevel in collimator/litmus/autocollie/promoter; see
// collimator/src/collimator/thresholds/__init__.py for the cross-repo group.
const CriticalLevel = 4

// envelopeClass derives the legacy 0/1/2 classification from a v6/v7 envelope's
// level field. -1 → benign (0); 0..=CriticalLevel → hostile (2); above
// CriticalLevel → suspicious (1); nil/null (manual mode, no level info) →
// hostile (2), fail-safe.
func envelopeClass(l *int) int {
	if l == nil {
		return 2
	}
	switch {
	case *l < 0:
		return 0
	case *l <= CriticalLevel:
		return 2
	default:
		return 1
	}
}

// classificationNames maps integer classification to display string.
var classificationNames = [3]string{"benign", "suspicious", "hostile"}

func classificationName(c int) string {
	if c >= 0 && c < len(classificationNames) {
		return classificationNames[c]
	}
	return "unknown"
}

// verdictClass returns prism's integer verdict class (0=benign, 1=suspicious,
// 2=hostile) for the envelope, bridging the wire-format versions. v=4/v=5
// carry `class` directly. v=6/v7 collapse verdict-and-level into `l`/`lvl` and no
// longer wire-encodes a suspicious band, so the suspicious cutoff is
// consumer-side; see classFromLevel.
func (r *litmusMlResponse) verdictClass() int {
	if r.V == "6" || r.V == "7" {
		return classFromLevel(r.L)
	}
	return r.Classification
}

// classFromLevel applies prism's consumer-side level policy to a v6/v7 level
// marker (../litmus/docs/JSON.md). The sentinel -1 is benign; a nil marker is
// hostile produced under manual thresholds (no level table applies); levels
// 0..=50 are hostile; 51 and above are suspicious. Lower levels fire at
// stricter false-positive cutoffs, so they carry higher confidence.
func classFromLevel(l *int) int {
	if l == nil {
		return 2 // hostile under manual thresholds
	}
	switch v := *l; {
	case v == -1:
		return 0 // benign sentinel
	case v <= 50:
		return 2 // hostile
	default:
		return 1 // suspicious
	}
}

// suspiciousT returns the suspicious-band cutoff for rendering. For v=5
// envelopes, only the deciding threshold is published; the other band edge is
// estimated so the existing two-stop gradient still renders sensibly. Switch
// templates to a class+threshold-aware band function if exact rendering matters.
func (r *litmusMlResponse) suspiciousT() float64 {
	if r.V == "5" {
		s, _ := r.v5BandEdges()
		return s
	}
	return r.Thresholds[0]
}

// hostileT returns the hostile-band cutoff for rendering. See suspiciousT.
func (r *litmusMlResponse) hostileT() float64 {
	if r.V == "5" {
		_, h := r.v5BandEdges()
		return h
	}
	return r.Thresholds[1]
}

// v5BandEdges derives (suspiciousT, hostileT) from a v=5 envelope's single
// Threshold + Classification. Heuristics; precise rendering requires switching
// the template to a class+threshold band function.
func (r *litmusMlResponse) v5BandEdges() (suspiciousT, hostileT float64) {
	t := r.Threshold
	switch r.Classification {
	case 2: // hostile: Threshold is the hostile cutoff
		return t * 0.7, t
	case 1: // suspicious: Threshold is the suspicious cutoff
		return t, t + (1-t)*0.5
	default: // benign: Threshold is the suspicious cutoff (line not crossed)
		return t, t + (1-t)*0.5
	}
}

// bandRGB is one stop of the two-color band gradient.
type bandRGB struct{ r, g, b float64 }

func mixRGB(a, b bandRGB, t float64) bandRGB {
	return bandRGB{a.r + t*(b.r-a.r), a.g + t*(b.g-a.g), a.b + t*(b.b-a.b)}
}

func cssRGB(c bandRGB) string {
	return fmt.Sprintf("rgb(%d,%d,%d)", int(c.r), int(c.g), int(c.b))
}

// renderBandGradient builds the linear-gradient CSS for one indicator using
// the band's two color stops at the given within-band progress.
func renderBandGradient(_ float64, t float64, class int) template.CSS {
	if t < 0 {
		t = 0
	}
	if t > 1 {
		t = 1
	}
	var left, right bandRGB
	switch class {
	case 2: // hostile: orange-red → saturated red
		left = mixRGB(bandRGB{255, 135, 40}, bandRGB{255, 50, 65}, t)
		right = mixRGB(bandRGB{255, 95, 35}, bandRGB{255, 35, 35}, t)
	case 1: // suspicious: greenish-yellow → orange
		left = mixRGB(bandRGB{170, 190, 45}, bandRGB{255, 180, 40}, t)
		right = mixRGB(bandRGB{235, 220, 65}, bandRGB{255, 125, 20}, t)
	default: // benign: teal-green → yellow-green
		left = mixRGB(bandRGB{25, 170, 120}, bandRGB{120, 190, 40}, t)
		right = mixRGB(bandRGB{70, 215, 135}, bandRGB{195, 210, 60}, t)
	}
	return template.CSS(fmt.Sprintf( //nolint:gosec // rgb derived from in-package floats, no user content
		"linear-gradient(90deg, %s, %s)", cssRGB(left), cssRGB(right),
	))
}

// levelStops anchor the v6/v7 verdict-stamp spectrum to the per-100M-benigns level
// (../litmus JSON.md). The level reads like a normalized confidence scale:
// lower levels fired at stricter false-positive cutoffs (higher-confidence
// hostile), so they sit at the hot end and cool toward green as the level
// loosens. Anchors are spaced to match the level table's own non-linear feel.
var levelStops = []struct {
	at int
	c  bandRGB
}{
	{0, bandRGB{150, 50, 225}},    // violet — strictest cutoff, off-the-charts confident
	{1, bandRGB{235, 55, 55}},     // red
	{50, bandRGB{250, 140, 35}},   // orange — litmus's default operating level
	{150, bandRGB{240, 205, 60}},  // yellow
	{500, bandRGB{150, 200, 80}},  // greenish
	{1000, bandRGB{85, 195, 115}}, // green — loosest cutoff
}

// levelColor interpolates the spectrum at a clamped level.
func levelColor(level int) bandRGB {
	if level <= levelStops[0].at {
		return levelStops[0].c
	}
	last := levelStops[len(levelStops)-1]
	if level >= last.at {
		return last.c
	}
	for i := range len(levelStops) - 1 {
		lo, hi := levelStops[i], levelStops[i+1]
		if level <= hi.at {
			t := float64(level-lo.at) / float64(hi.at-lo.at)
			return mixRGB(lo.c, hi.c, t)
		}
	}
	return last.c
}

// levelGradient renders the verdict stamp directly from a v6/v7 level marker,
// independent of the discrete verdict class. The benign sentinel (-1) is a
// solid green; a level 0..1000 walks the violet→red→orange→yellow→green
// spectrum; a nil marker (hostile via manual thresholds, no level table)
// renders red. The two stops add a light→dark sheen matching the band style.
func levelGradient(level *int) template.CSS {
	switch {
	case level == nil:
		return levelGradientCSS(bandRGB{235, 55, 55}, false) // manual-threshold hostile
	case *level < 0:
		return levelGradientCSS(bandRGB{45, 175, 100}, true) // benign sentinel: solid green
	default:
		return levelGradientCSS(levelColor(*level), false)
	}
}

// levelGradientCSS turns a base color into the two-stop gradient. solid emits
// the same color for both stops (a flat fill) for the benign verdict.
func levelGradientCSS(base bandRGB, solid bool) template.CSS {
	left, right := base, base
	if !solid {
		left = mixRGB(base, bandRGB{255, 255, 255}, 0.14)
		right = mixRGB(base, bandRGB{0, 0, 0}, 0.10)
	}
	return template.CSS(fmt.Sprintf( //nolint:gosec // rgb derived from in-package ints, no user content
		"linear-gradient(90deg, %s, %s)", cssRGB(left), cssRGB(right),
	))
}

func isCurrentWire(version string, level *int) bool {
	return version == "6" || version == "7" || level != nil
}

func confidenceFromWire(conf *int, level *int) int {
	if conf != nil {
		return *conf
	}
	return levelConfidence(level)
}

func confidencePointerFromWire(conf *int, level *int) *int {
	if conf != nil {
		return conf
	}
	if level == nil {
		return nil
	}
	v := levelConfidence(level)
	return &v
}

// levelConfidence maps a v6/v7 level marker to the pessimistic integer confidence
// percentage emitted by litmus as ml.conf. Keep this fallback in lockstep with
// litmus::scan::level_confidence so cached pre-conf envelopes render the same
// way as fresh envelopes.
func levelConfidence(level *int) int {
	switch {
	case level == nil:
		return 100
	case *level < 0:
		return 0
	case *level == 0:
		return 100
	case *level == 1:
		return 99
	case *level == 2:
		return 98
	case *level == 3:
		return 97
	case *level == 4:
		return 96
	case *level == 5:
		return 95
	case *level <= 10:
		return 94
	case *level <= 20:
		return 93
	case *level <= 30:
		return 92
	case *level <= 40:
		return 91
	case *level <= 50:
		return 90
	case *level <= 60:
		return 89
	case *level <= 70:
		return 88
	case *level <= 80:
		return 87
	case *level <= 90:
		return 86
	case *level <= 100:
		return 85
	case *level <= 200:
		return 82
	case *level <= 300:
		return 80
	case *level <= 500:
		return 78
	case *level <= 1000:
		return 75
	case *level <= 2000:
		return 66
	case *level <= 5000:
		return 54
	case *level <= 7500:
		return 49
	case *level <= 10000:
		return 45
	case *level <= 15000:
		return 38
	case *level <= 20000:
		return 33
	case *level <= 25000:
		return 29
	case *level == 25001:
		return 28
	case *level == 25002:
		return 27
	case *level < 50000:
		return 26
	case *level == 50000:
		return 17
	case *level == 50001:
		return 16
	default:
		return 15
	}
}

// stampGradient picks the verdict-stamp gradient for one file, dispatching on
// the envelope version so the choice lives in one place rather than the
// template. v=6/v7 color by level; v=5 uses the single deciding threshold; v=4
// uses both band edges. prob/level are per-file; the threshold/class/band edges
// are the envelope-level values, mirroring the prior template behavior.
func stampGradient(version string, level *int, prob, threshold, suspT, hostT float64, class int) template.CSS {
	if version == "6" || version == "7" {
		return levelGradient(level)
	}
	if threshold > 0 {
		return renderBandGradient(prob, bandProgressV5(prob, threshold, class), class)
	}
	return renderBandGradient(prob, bandProgressV4(prob, suspT, hostT), classifyByThresholds(prob, suspT, hostT))
}

// classifyByThresholds maps (prob, suspT, hostT) to the v=4 integer class.
func classifyByThresholds(p, suspT, hostT float64) int {
	switch {
	case p >= hostT:
		return 2
	case p >= suspT:
		return 1
	default:
		return 0
	}
}

// bandProgressV4 returns within-band progress [0,1] using both band edges.
func bandProgressV4(p, suspT, hostT float64) float64 {
	switch {
	case p >= hostT:
		if hostT >= 1 {
			return 1
		}
		return (p - hostT) / (1.0 - hostT)
	case p >= suspT:
		if hostT <= suspT {
			return 0
		}
		return (p - suspT) / (hostT - suspT)
	default:
		if suspT <= 0 {
			return 0
		}
		return p / suspT
	}
}

// bandProgressV5 returns within-band progress [0,1] using the single deciding
// threshold from a v=5 envelope. For non-benign bands progress is measured
// over (threshold, 1.0); for benign over (0, threshold).
func bandProgressV5(p, threshold float64, class int) float64 {
	switch class {
	case 2, 1: // hostile or suspicious: prob >= threshold
		if threshold >= 1 {
			return 1
		}
		return (p - threshold) / (1.0 - threshold)
	default: // benign: prob < threshold
		if threshold <= 0 {
			return 0
		}
		return p / threshold
	}
}

// v4 cleave types are defined above: cleaveReport, cleaveFile, finding.

// v4: cleave output deserializes directly into cleaveReport via json tags.
// parseAPIResponse and uploadToGCS removed.
