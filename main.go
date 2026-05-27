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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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
	cache              *fido.TieredCache[string, storedResult]
	feedCache          *fido.TieredCache[string, cachedFeedSnapshot]
	contentCache       *fido.TieredCache[string, cachedContent]
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
	// feedCacheTTL is the absolute lifetime of any cached feed query
	// (frontpage default, criticality variants, ecosystem/domain/formula
	// filtered). Every feed query goes through the cache — even untyped
	// filter combinations — to avoid thundering-herd hopper hits when
	// many users request the same view at once.
	feedCacheTTL = 3 * time.Minute
	// feedPrecacheInterval is how often the background goroutine
	// re-warms the pre-cached variants (frontpage default + three
	// criticality views). Shorter than feedCacheTTL so high-traffic
	// keys never serve a fully cold loader to a real request.
	feedPrecacheInterval = 90 * time.Second
	// auxCacheTTL is the TTL for ancillary per-SHA caches (report, parent
	// archives, etc.) — same 3-minute envelope as feedCacheTTL so all
	// derived views age together.
	auxCacheTTL = 3 * time.Minute
	// rescanCooldown is the minimum age of the most recent analysis
	// before another rescan request is accepted. Enforced both
	// client-side (button hidden) and server-side (atomic check in the
	// UPDATE statement), so a race or hand-crafted POST can't bypass.
	rescanCooldown = 15 * time.Minute
)

// csrfKey is a random 32-byte key generated at startup for HMAC-signing CSRF tokens.
// Tokens are stateless: HMAC(cookie || action || ts) verified on POST. Key rotates
// on restart, which is fine — an in-flight form simply needs resubmission after a
// deploy.
var csrfKey = func() [32]byte {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		panic("csrf: failed to generate key: " + err.Error())
	}
	return k
}()

const (
	// csrfCookieName is the per-browser session marker used to bind a CSRF
	// token to the visitor who received it. Cookies set by ensureCSRFCookie
	// carry HttpOnly, SameSite=Strict, and (in --public) Secure.
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
		Secure:   publicMode, // --public implies TLS termination upstream
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(24 * time.Hour / time.Second),
	})
	return r.WithContext(context.WithValue(r.Context(), csrfSessionKey, val))
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
const maxDownloadSize int64 = 150 * 1024 * 1024

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
}

// FindingMatch is one row in an expandable trait card. It carries the
// evidence string (always) plus, when the producing file is known, the
// inner-file path + SHA so the row can become a clickable link. For
// archive aggregations evidence and file are populated from cleave's
// parallel `e` / `el` arrays; for per-file findings the evidence stands
// on its own (the file is implied by the surrounding view).
type FindingMatch struct {
	Evidence string
	Path     string
	SHA256   string
	Count    int
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
}

// FileStringsDisplay represents strings for a single file.
type FileStringsDisplay struct {
	Basename       string
	Risk           string
	Classification string
	SHA256         string
	Formula        string
	FileType       string
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

// FileTreeEntry is a single row in the archive Files tab tree. It carries
// just enough info to render the left-pane row (risk dot, basename, size,
// formula, sha) and identify which detail block to swap into the right pane.
type FileTreeEntry struct {
	Path           string // full path within the archive (e.g. "archive.tgz!!package/index.js")
	Display        string // path stripped of the archive prefix, used for tree building
	Basename       string // last path segment
	SHA256         string // 64-char lowercase hex
	SHA256Short    string // first 8 chars, for compact display
	Classification string // "hostile", "suspicious", "benign", or ""
	Risk           string // critIntToString of max trait crit ("hostile"/"suspicious"/"notable"/"")
	Formula        string // chemical formula chip
	FileType       string // "JS", "PE", "TAR.GZ", ...
	SizeStr        string // human-readable, e.g. "2.0 KB"
	Size           int64
	Probability    float64
	Depth          int
	IsContainer    bool // true for the archive container (depth 0)
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
	SHA256Short    string
	Filename       string
	SHA256         string
	Verdict        string
	Formula        template.HTML
	FormulaQuery   string // raw formula with subscript digits desubscripted, for ?m=… links
	CSRFToken      string // signed CSRF token for operator actions (rescan)
	// DownloadToken is a separate CSRF token bound to the "download" action.
	// Rendered into the download button's href as `?t=…` so /file/<sha>.dl is
	// gated to button-driven flows: the token only validates for the browser
	// session that fetched the page, within csrfMaxAge. Bots, link previews,
	// pasted URLs from another browser, and stale wayback captures all fail.
	DownloadToken string
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
	RiskLabel      string
	FirstSeenAgo   string
	FirstSeenAt    string
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
	BuildCommit string
	Files       []FileTreeEntry
	// FileTreeJSON is the hierarchical tree of archive contents, JSON-encoded
	// for the client-side Miller-column renderer. Empty string for non-archive
	// pages.
	FileTreeJSON template.JS
	// TraitOccurrenceJSON maps each full trait ID seen in this archive to its
	// archive-wide occurrence count and the matching archive-Traits-tab card
	// ID. Powers the "also in N other files" pivot from a file's source-view
	// trait sidebar back into the archive Traits tab.
	TraitOccurrenceJSON template.JS
	FileMetrics         []FileMetricsDisplay
	FileSections        []FileSectionsDisplay
	FileSymbols         []FileSymbolsDisplay
	FileStrings         []FileStringsDisplay
	FileFindings        []FileFindingsDisplay
	FileKVs             []FileKVDisplay
	// Parents lists archives that contain this file. Populated only on
	// standalone child pages (non-archive views) so the user can navigate
	// up to the archive context the file came from.
	Parents []ParentArchive
	// ArchiveCategories is the aggregated trait categories across every
	// file in an archive (deduped by trait ID). The archive Traits tab
	// shows this summary; per-file breakdowns live behind the Files tab.
	ArchiveCategories []CategoryGroup
	HostileT          float64
	SuspiciousT       float64
	TotalFiles        int
	ShownFiles        int
	Probability       float64
	IsArchive         bool
	IsText            bool // file_type indicates a text/script file — show Contents tab instead of Strings, hide Metadata
	LimitedInfo       bool
	RescanAllowed     bool // last analysis is older than rescanCooldown — the rescan button is hidden when false
	// Contents holds the rendered text body of a text file, broken into
	// annotated lines. Empty for non-text files and archives.
	Contents []ContentLine
	// ContentTooLarge is set when the file is text but exceeds
	// maxContentBytes; the template shows a download link instead.
	ContentTooLarge bool
	// ContentSizeStr is the human-readable size of an oversized content,
	// shown alongside the "too large" message.
	ContentSizeStr string
}

// ContentLine is one rendered line of a text file's body. Risk and Traits
// power the per-line crit dots and hover tooltips on the Contents tab.
// Tokens carries chroma syntax-highlighted segments when a lexer matched
// the file; the client constructs DOM nodes from these (textContent only,
// no innerHTML) so there is no path for attacker-controlled markup.
type ContentLine struct {
	Text string
	// Tokens are the chroma-classified spans for this line. Empty when no
	// lexer matched the file (caller falls back to plain Text).
	Tokens []ContentToken `json:"Tokens,omitempty"`
	// Risk is "hostile"/"suspicious"/"notable"/"baseline"/"component"/"".
	// Computed from the highest-crit finding whose evidence appears on
	// this line.
	Risk string
	// Traits is the dedup'd list of finding IDs whose evidence appears
	// on this line, used for the hover tooltip.
	Traits []string
	Number int
}

// ContentToken is one chroma-classified slice of a source line. Class is
// the chroma standard-type CSS class (always a fixed identifier from the
// chroma library, never attacker-controlled); empty means render Text as
// a bare text node with no wrapping span.
type ContentToken struct {
	Class string `json:"c,omitempty"`
	Text  string `json:"t"`
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
	HostileT       float64
	SuspiciousT    float64
	Probability    float64
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
	Domains         []string
	Ecosystems      []string
	Rows            []feedRow
	TotalCount      int
	FilteredCount   int
	Refresh         bool
	HasHopper       bool
	// UploadEnabled mirrors the package-level toggle so the template can
	// pick the real upload form vs. the disabled placeholder.
	UploadEnabled bool
}

type cachedFeedSnapshot struct {
	GeneratedAt time.Time
	Rows        []cachedFeedSample
	Ecosystems  []string
	Domains     []string
	TotalCount  int
}

type cachedFeedSample struct {
	CreatedAt      time.Time
	SHA256         string
	Filename       string
	Classification string
	Formula        string
	FileType       string
	Source         string
	Ecosystem      string
	Probability    float64
	SuspiciousT    float64
	HostileT       float64
}

// cleaveReport is constructed from JSONL output (multiple lines).
type cleaveReport struct {
	Files []cleaveFile `json:"fs"`
}

// cleaveFile represents a file entry in cleave compact output.
// Litmus injects "class" and "prob" into each fs[] entry.
type cleaveFile struct {
	Metrics        json.RawMessage            `json:"ms,omitempty"`
	KV             map[string]json.RawMessage `json:"k,omitempty"`  // flat kv: "a.b[0].c" → leaf value (cleave's structural output)
	Facts          cleaveFacts                `json:"ff,omitempty"` //nolint:modernize // omitzero would change marshal output (empty Facts becomes omitted instead of "ff":{}); kept for downstream-consumer compatibility
	Path           string                     `json:"path"`
	FileType       string                     `json:"type"`
	SHA256         string                     `json:"sha"`
	Classification string                     `json:"-"` // populated from ml.fs after parsing
	Formula        string                     `json:"f,omitempty"`
	Findings       []finding                  `json:"ts,omitempty"`
	Strings        []json.RawMessage          `json:"ss,omitempty"` // v4 tuples: [offset, value] or [offset, enc, value]
	Imports        []string                   `json:"is,omitempty"` // v4: bare symbol strings
	Exports        []symbolInfo               `json:"exports,omitempty"`
	Sections       []sectionInfo              `json:"sections,omitempty"`
	Probability    float64                    `json:"-"` // populated from ml.fs after parsing
	Size           int64                      `json:"sz"`
	ID             int                        `json:"id"`
	Depth          int                        `json:"dp"`
}

type cleaveFacts struct {
	Metrics   json.RawMessage            `json:"m,omitempty"`
	KV        map[string]json.RawMessage `json:"v,omitempty"`
	Strings   []json.RawMessage          `json:"s,omitempty"`
	Imports   []json.RawMessage          `json:"i,omitempty"`
	Exports   []json.RawMessage          `json:"x,omitempty"`
	Functions []json.RawMessage          `json:"fn,omitempty"`
	Sections  []json.RawMessage          `json:"sc,omitempty"`
}

func (f *cleaveFile) UnmarshalJSON(data []byte) error {
	type alias cleaveFile
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*f = cleaveFile(a)
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

type finding struct {
	ID   string `json:"i"`
	Desc string `json:"d,omitempty"`
	// Evidence values (cleave's compact `e`). Parallel to Locations when
	// the latter is non-empty; same index = same match.
	Evidence []string `json:"e,omitempty"`
	// Locations is cleave's compact `el` — one entry per Evidence item,
	// or empty when the finding was never rolled up through an archive
	// member. Archive-attributed entries look like
	// "archive:<member-path>", with optional "!" nesting for archives
	// inside archives. Used by aggregateArchiveCategories to point the
	// user at the inner file a container-level trait actually matched.
	Locations []string `json:"el,omitempty"`
	Crit      int      `json:"l"`
	Conf      float64  `json:"c,omitempty"`
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
		contentCache = openNullCache[cachedContent]("content cache")
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
		feedCache = openLocalFSCache[cachedFeedSnapshot]("prism-feed", cacheDir, "feed cache")
		contentCache = openLocalFSCache[cachedContent]("prism-content", cacheDir, "content cache")
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
		"ecoColor":         ecosystemColor,
		"chromaCSS":        func() template.CSS { return chromaStylesheet },
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

			return template.CSS(fmt.Sprintf( //nolint:gosec // input is rgb derived from in-package floats, no user content
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
		if contentCache != nil {
			if err := contentCache.Close(); err != nil {
				logger.Error("failed to close fido content cache", "error", err)
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
	mux.HandleFunc("GET /file/{sha256}/contents", handleFileContents)
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

	logger.Debug("configuration loaded",
		"HOPPER_API_ADDR", hopperAPIAddr,
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

const feedLimit = 100

// feedCacheKey produces a deterministic cache key from the four feed-query
// dimensions. Stable across reorderings (so swapping argument order can't
// silently fragment the cache) and never empty.
func feedCacheKey(ecosystem, domain, criticality, formula string) string {
	return "feed-v2:eco=" + ecosystem + ":dom=" + domain + ":crit=" + criticality + ":formula=" + formula
}

// loadFeedRows fetches a feed page, caching every query for feedCacheTTL.
// All concurrent requests for the same filter set share one hopper round-
// trip via fido's built-in singleflight. Pre-cached variants (default +
// criticality) stay hot via feedPrecacheLoop so high-traffic views never
// hit a cold loader on the request path.
func loadFeedRows(ctx context.Context, ecosystem, domain, criticality, formula string, reqLogger *slog.Logger) (rows []feedRow, ecosystems, domains []string, total int, err error) {
	if feedCache == nil {
		return loadFeedRowsFromHopper(ctx, ecosystem, domain, criticality, formula, reqLogger)
	}
	key := feedCacheKey(ecosystem, domain, criticality, formula)
	snapshot, err := feedCache.FetchTTL(ctx, key, feedCacheTTL, func(lctx context.Context) (cachedFeedSnapshot, error) {
		return buildFeedSnapshot(lctx, ecosystem, domain, criticality, formula, reqLogger)
	})
	if err != nil {
		return nil, nil, nil, 0, err
	}
	return feedRowsFromSnapshot(snapshot), snapshot.Ecosystems, snapshot.Domains, snapshot.TotalCount, nil
}

// buildFeedSnapshot runs the live hopper queries and packages the result
// into a cache-friendly snapshot (stable raw fields, no rendered relative-
// time strings — those re-derive at request time from CreatedAt).
func buildFeedSnapshot(ctx context.Context, ecosystem, domain, criticality, formula string, reqLogger *slog.Logger) (cachedFeedSnapshot, error) {
	rows, ecosystems, domains, total, err := loadFeedRowsFromHopper(ctx, ecosystem, domain, criticality, formula, reqLogger)
	if err != nil {
		return cachedFeedSnapshot{}, err
	}
	return cachedFeedSnapshot{
		GeneratedAt: time.Now(),
		Rows:        cachedFeedSamplesFromRows(rows),
		Ecosystems:  ecosystems,
		Domains:     domains,
		TotalCount:  total,
	}, nil
}

func loadFeedRowsFromHopper(ctx context.Context, ecosystem, domain, criticality, formula string, reqLogger *slog.Logger) (rows []feedRow, ecosystems, domains []string, total int, err error) {
	db := hopperDB.Load()
	if db == nil {
		return nil, nil, nil, 0, errors.New("hopper not connected")
	}
	// Source="" spans every Source value (legacy "harvest" rows from
	// before the rename, new "forager" rows, manual "upload"s) so the
	// dropdowns and the result set both work across the transition.
	ecosystems, err = db.FeedEcosystems(ctx, "", "")
	if err != nil {
		return nil, nil, nil, 0, err
	}
	domains, err = db.FeedDomains(ctx, "", "")
	if err != nil {
		return nil, nil, nil, 0, err
	}

	q := hopper.FeedQuery{
		OrderBy:      "created_at",
		Formula:      formula,
		TopLevelOnly: true,
		Limit:        feedLimit,
	}
	if ecosystem != "" {
		q.Ecosystems = []string{ecosystem}
	}
	if domain != "" {
		q.Domains = []string{domain}
	}
	if classes, ok := criticalityClasses(criticality); ok {
		q.LitmusClasses = classes
	} else {
		q.RequireLitmus = true
	}

	samples, err := db.FeedSamples(ctx, q)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	total, err = db.FeedSamplesCount(ctx, q)
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
		if criticality != "" && classification != criticality {
			continue
		}
		if formula != "" && firstNonEmpty(res.Formula, sample.Formula) != formula {
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
			Ecosystem:      sample.Ecosystem,
			EcosystemURL:   ecosystemURL(sample.Ecosystem),
			AnalyzedAt:     sample.CreatedAt,
			AnalyzedDate:   feedDate(sample.CreatedAt, now),
			TimeAgo:        timeAgo(now.Sub(sample.CreatedAt)),
		})
	}
	return rows
}

// feedPrecacheVariants enumerates the high-traffic feed views kept hot by
// the background refresher. The default (all empty) handles unfiltered
// frontpage; the three criticality views handle the most common filter
// pivots. Everything else is cached on demand by loadFeedRows.
var feedPrecacheVariants = []struct{ ecosystem, domain, criticality, formula string }{
	{"", "", "", ""},
	{"", "", "hostile", ""},
	{"", "", "suspicious", ""},
	{"", "", "suspicious_plus", ""},
	{"", "", "benign", ""},
}

// refreshFeedCacheLoop keeps the pre-cached variants warm. Each tick
// rebuilds any variant older than feedPrecacheInterval and writes it
// back with feedCacheTTL — so steady-state, every pre-cached key has a
// snapshot under feedPrecacheInterval seconds old, well inside its TTL.
// Variants are refreshed sequentially per tick so a slow hopper doesn't
// pile up concurrent queries.
func refreshFeedCacheLoop(ctx context.Context) {
	if feedCache == nil {
		return
	}
	refreshAll := func() {
		for _, v := range feedPrecacheVariants {
			if err := refreshFeedCacheEntry(ctx, v.ecosystem, v.domain, v.criticality, v.formula); err != nil {
				logger.Warn("feed pre-cache refresh failed",
					"criticality", v.criticality, "error", err)
			}
		}
	}
	refreshAll()
	ticker := time.NewTicker(feedPrecacheInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshAll()
		}
	}
}

// refreshFeedCacheEntry no-ops when the cached entry is younger than
// feedPrecacheInterval. Otherwise it runs the live hopper query and
// writes a fresh snapshot. On-demand requests for the same key may race
// this loader through their own fido.Fetch path; both calls produce
// consistent snapshots, so the rare duplicate hopper query is benign.
func refreshFeedCacheEntry(ctx context.Context, ecosystem, domain, criticality, formula string) error {
	key := feedCacheKey(ecosystem, domain, criticality, formula)
	if snapshot, found, err := feedCache.Get(ctx, key); err == nil && found {
		if time.Since(snapshot.GeneratedAt) <= feedPrecacheInterval {
			return nil
		}
	}
	snapshot, err := buildFeedSnapshot(ctx, ecosystem, domain, criticality, formula, logger)
	if err != nil {
		return err
	}
	if err := feedCache.SetTTL(ctx, key, snapshot, feedCacheTTL); err != nil {
		return err
	}
	logger.Debug("feed pre-cache refreshed",
		"criticality", criticality, "rows", len(snapshot.Rows), "total", snapshot.TotalCount)
	return nil
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
	// Invalidate prism's local result cache so the next GET /file/<sha>
	// doesn't serve the stale rendered view. Failure is not fatal — the
	// next refresh window picks up the new state — but worth logging.
	if delErr := cache.Delete(ctx, sha); delErr != nil {
		logger.Debug("rescan: cache invalidation failed", "sha256", sha, "error", delErr)
	}
	return nil
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
// class integers the feed query filters on. Single-band tokens return a
// one-element slice; "suspicious_plus" is the union of suspicious + hostile,
// which is the filter operators ask for most often — "show me anything that
// isn't benign". Unrecognized tokens return (nil, false).
func criticalityClasses(criticality string) ([]int, bool) {
	switch criticality {
	case "benign":
		return []int{0}, true
	case "suspicious":
		return []int{1}, true
	case "hostile":
		return []int{2}, true
	case "suspicious_plus":
		return []int{1, 2}, true
	default:
		return nil, false
	}
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
			classification = classificationName(mlResp.Classification)
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

	return storedResult{
		Filename:       firstNonEmpty(sample.Filename, filepath.Base(sample.Path)),
		RawLitmus:      string(rawLitmus),
		Classification: classification,
		Formula:        sample.Formula,
		FileType:       sample.FileType,
		CachedAt:       cachedAt,
		CreatedAt:      sample.CreatedAt,
		AnalyzedAt:     analyzedAt,
		SourceURL:      sample.URL,
		SourceDomain:   sample.Domain,
		Ecosystem:      sample.Ecosystem,
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

// knownEcosystems is the allowlist for the Fallout ecosystem dropdown.
// Hopper normalizes registry/classifier names to canonical runtimes
// (npm → javascript, homebrew → macos, etc.), so this list holds those
// runtime names. Anything else hopper emits (file extensions, malware-
// corpus repo names, OS version strings) is filtered out of the dropdown.
var knownEcosystems = map[string]bool{
	// Languages.
	"javascript": true, "python": true, "ruby": true, "rust": true,
	"go": true, "java": true, "dotnet": true, "powershell": true,
	"php": true, "erlang": true, "perl": true, "r": true,
	"haskell": true, "dart": true, "lua": true, "wordpress": true,
	// OS targets.
	"linux": true, "bsd": true, "macos": true, "windows": true,
	"android": true,
	// Application hosts.
	"vscode": true, "chrome": true, "edge": true, "firefox": true,
	// Containers, agent skills, source hosts.
	"container": true, "agent": true, "openclaw": true, "github": true,
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

// filterRowsBySearch is the in-memory text filter behind ?q=. Matches
// filename substring (case-insensitive) or SHA-256 prefix. The structured
// filters (crit/eco/domain/m) are already applied at the hopper layer.
func filterRowsBySearch(rows []feedRow, q string) []feedRow {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return rows
	}
	out := rows[:0]
	for _, row := range rows {
		if strings.Contains(strings.ToLower(row.Filename), q) ||
			strings.HasPrefix(row.SHA256, q) {
			out = append(out, row)
		}
	}
	return out
}

func formulaFromQuery(values url.Values) string {
	if formula := strings.TrimSpace(values.Get("m")); formula != "" {
		return resubscriptFormula(formula)
	}
	return strings.TrimSpace(values.Get("formula"))
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
	eco := strings.Trim(r.PathValue("ecosystem"), "/")
	if !validEcosystem(eco) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	renderFeed(w, r, eco)
}

func handleEcosystemRedirect(w http.ResponseWriter, r *http.Request) {
	eco := strings.Trim(r.PathValue("ecosystem"), "/")
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

func renderFeed(w http.ResponseWriter, r *http.Request, ecosystem string) {
	rawQ := strings.TrimSpace(r.URL.Query().Get("q"))
	// Server-side fallback for ?q=sha256:<hex> / ?q=<64-hex> deep links —
	// JS already short-circuits these before sending, but a pasted URL or
	// a no-JS client still gets the redirect.
	if sha, ok := shaFromSearchQuery(rawQ); ok {
		http.Redirect(w, r, "/file/"+sha, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := feedPageData{
		CSRFToken:       csrfToken(r, "upload"),
		UploadEnabled:   uploadEnabled,
		Nonce:           nonceFor(r),
		StyleNonce:      styleNonceFor(r),
		BuildCommit:     buildCommit,
		Refresh:         r.URL.Query().Get("refresh") == "1",
		SelectedEco:     ecosystem,
		SelectedDomain:  strings.TrimSpace(r.URL.Query().Get("domain")),
		SelectedCrit:    normalizeCriticality(r.URL.Query().Get("criticality")),
		SelectedFormula: formulaFromQuery(r.URL.Query()),
		SelectedQ:       rawQ,
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

	if hopperDB.Load() != nil {
		var err error
		data.Rows, data.Ecosystems, data.Domains, data.TotalCount, err = loadFeedRows(
			r.Context(),
			data.SelectedEco, data.SelectedDomain, data.SelectedCrit, data.SelectedFormula,
			logger,
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
		filtered := data.Ecosystems[:0:0]
		for _, e := range data.Ecosystems {
			if knownEcosystems[strings.ToLower(e)] {
				filtered = append(filtered, e)
			}
		}
		data.Ecosystems = filtered
		if data.SelectedQ != "" {
			data.Rows = filterRowsBySearch(data.Rows, data.SelectedQ)
		}
		data.FilteredCount = len(data.Rows)
	}
	if err := uploadTemplate.Execute(w, data); err != nil {
		logger.Error("template execution failed",
			"template", "feed",
			"error", err,
		)
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
	data := prepareResultData(r.Context(), res.Filename, sha, &res)
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
				entry.Classification = classificationName(ml.Classification)
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

// Content fetch budgets. hopper-api now resolves archive members on its
// side (extracts inner files from parent archives), so prism just fetches
// what hopper returns and caches that — never the parent.
const (
	maxContentBytes     = 256 * 1024       // displayable inline content
	maxContentLines     = 4000             // line cap to keep the DOM tractable
	contentFetchTimeout = 10 * time.Second // per-request bound; the upstream client's 5-min default is too lenient for the page-render path
	parentLookupTimeout = 2 * time.Second  // budget for the N+1 SampleBySHA256 lookups behind ParentArchives
)

// cachedContent wraps file bytes for fido's JSON-encoded localfs store.
// Body is base64-encoded by the JSON layer.
type cachedContent struct {
	FetchedAt time.Time
	Body      []byte
}

// fetchFileBytes returns up to maxContentBytes for a sample SHA, going
// through the fido cache. hopper-api handles both top-level samples and
// archive members behind one URL; we treat them identically here.
//
// Errors degrade gracefully: callers in the page-render path log and fall
// back to a "no contents" message rather than failing the whole page.
// Recognisable error substrings: "sample not found", "too large".
func fetchFileBytes(ctx context.Context, sha string) ([]byte, error) {
	c, err := contentCache.Fetch(ctx, sha, func(lctx context.Context) (cachedContent, error) {
		body, err := downloadFromHopperAPI(lctx, sha, maxContentBytes)
		if err != nil {
			return cachedContent{}, err
		}
		return cachedContent{Body: body, FetchedAt: time.Now().UTC()}, nil
	})
	if err != nil {
		return nil, err
	}
	return c.Body, nil
}

// downloadFromHopperAPI streams up to maxBytes of the sample identified by
// sha from the hopper-api file endpoint. The endpoint resolves archive
// members on its side, so we don't need to know whether sha is a top-level
// sample or an inner file.
func downloadFromHopperAPI(ctx context.Context, sha string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hopperFileURL(sha), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("prepare request: %w", err)
	}
	resp, err := hopperClient.Do(req) //nolint:gosec // hopperFileURL builds from admin-configured hopper-api host + validated SHA path; no user-controlled URL
	if err != nil {
		return nil, fmt.Errorf("hopper-api request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort close on a response body we've already drained
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("sample bytes not found: status %d", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		return nil, fmt.Errorf("file too large: status %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hopper-api status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("file too large (>%d bytes)", maxBytes)
	}
	return body, nil
}

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
	sample, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		if errors.Is(err, hopper.ErrNotFound) {
			return storedResult{}, fmt.Errorf("sample not found in hopper: %w", err)
		}
		return storedResult{}, fmt.Errorf("hopper lookup (host=%s): %w", hopperDSNHost(hopperDBDSN), err)
	}

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
// child entries are spliced back into raw.fs[] and ml.fs[]. The returned
// envelope drops the truncated/omitted_files markers because they are no
// longer accurate after reassembly.
//
// Each child contributes its own top-level fs entry (depth 0 in the child's
// own report) which is appended to the parent's fs[] with depth bumped to 1
// and Path prefixed by parentPath + "!!". Child IDs are renumbered so they
// stay unique across the merged report; the same renumbering is mirrored
// into the merged ml.fs entries so per-file ML stays correctly attributed.
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
		parentRaw["fs"] = b
	}
	if b, err := json.Marshal(parentRaw); err == nil {
		env["raw"] = b
	}
	if b, err := json.Marshal(parentMLFS); err == nil {
		parentML["fs"] = b
	}
	if b, err := json.Marshal(parentML); err == nil {
		env["ml"] = b
	}
	return json.Marshal(env)
}

// extractFS pulls env[key] (a JSON object) and the "fs" array within it.
// Missing values yield empty results so callers can append unconditionally.
func extractFS(env map[string]json.RawMessage, key string) (map[string]json.RawMessage, []json.RawMessage, error) {
	inner := map[string]json.RawMessage{}
	if blob, ok := env[key]; ok && len(blob) > 0 {
		if err := json.Unmarshal(blob, &inner); err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", key, err)
		}
	}
	var entries []json.RawMessage
	if blob, ok := inner["fs"]; ok && len(blob) > 0 {
		if err := json.Unmarshal(blob, &entries); err != nil {
			return nil, nil, fmt.Errorf("parse %s.fs: %w", key, err)
		}
	}
	return inner, entries, nil
}

// mergeChildren splices each child's top-level fs entry (and its mirrored
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
// representative fs entry — preferring sha-match, then depth-0, then the
// first entry — along with the entry's original id.
func childTopEntry(child *hopper.Sample) (entry json.RawMessage, id int, ok bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(child.CleaveResult, &raw); err != nil {
		logger.Debug("reassemble: parse child cleave failed", "sha", child.SHA256, "error", err)
		return nil, 0, false
	}
	var entries []json.RawMessage
	if blob, ok := raw["fs"]; ok && len(blob) > 0 {
		if err := json.Unmarshal(blob, &entries); err != nil {
			logger.Debug("reassemble: parse child fs failed", "sha", child.SHA256, "error", err)
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

// renumberedMLEntry locates the child's own ml.fs[] row for oldID and
// rewrites its id to newID. The boolean reports whether the row was
// found and successfully re-marshalled.
func renumberedMLEntry(litmus []byte, oldID, newID int) (json.RawMessage, bool) {
	if len(litmus) == 0 {
		return nil, false
	}
	var ml struct {
		Files []json.RawMessage `json:"fs"`
	}
	if json.Unmarshal(litmus, &ml) != nil || len(ml.Files) == 0 {
		return nil, false
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

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, hopperFileURL(sha), http.NoBody)
	if err != nil {
		http.Error(w, "failed to prepare download", http.StatusInternalServerError)
		return
	}
	resp, err := hopperClient.Do(req) //nolint:gosec // hopperFileURL builds from admin-configured hopper-api host + validated SHA path; no user-controlled URL
	if err != nil {
		reqLogger.Warn("hopper download request failed", "error", err, "hopper_api_addr", hopperAPIAddr)
		http.Error(w, "download unavailable", http.StatusBadGateway)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			reqLogger.Debug("hopper download body close failed", "error", err)
		}
	}()

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
		http.Error(w, "file exceeds the 150 MB browser download limit; use the litmus CLI", http.StatusRequestEntityTooLarge)
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

// writeJSON writes a successful JSON response with a stable cache header.
// The cache is private + short-lived because the body depends on the
// underlying SHA's analysis, which is itself immutable for that SHA.
func writeJSON(w http.ResponseWriter, body any, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=300")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		logger.Debug("contents: encode failed", "error", err)
	}
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

// handleFileContents returns rendered source-line JSON for a file SHA. Used
// by the archive Files tab's inline source viewer. All responses (success
// and error) carry a JSON body so the client can parse uniformly.
func handleFileContents(w http.ResponseWriter, r *http.Request) {
	sha := strings.ToLower(r.PathValue("sha256"))
	reqLogger := logger.With("sha256", sha, "client_ip", clientIP(r))
	if !validSHA256(sha) {
		writeJSONError(w, http.StatusBadRequest, "invalid_sha", "invalid SHA256")
		return
	}
	_, res, err := lookupResult(r.Context(), sha, reqLogger)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSONError(w, http.StatusNotFound, "not_found", "result not found")
			return
		}
		reqLogger.Warn("contents lookup failed", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}

	// Parse the cleave report so we can read findings for the requested SHA.
	var fullResp litmusFullResponse
	if err := json.Unmarshal([]byte(res.RawLitmus), &fullResp); err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "no_analysis", "no analysis available for this file")
		return
	}
	report := &cleaveReport{}
	if len(fullResp.Raw) > 0 {
		if err := json.Unmarshal(fullResp.Raw, report); err != nil {
			reqLogger.Debug("contents: failed to parse cleave data", "error", err)
		}
	}

	var file *cleaveFile
	for i := range report.Files {
		if strings.EqualFold(report.Files[i].SHA256, sha) {
			file = &report.Files[i]
			break
		}
	}
	if file == nil && len(report.Files) > 0 {
		// Fallback to the depth-0 entry: this SHA was looked up directly
		// (standalone-file route), and the report has just one entry.
		file = &report.Files[0]
	}
	if file == nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "no_file", "no file in report")
		return
	}

	if !isTextFileType(file.FileType) {
		writeJSON(w, map[string]any{
			"sha":      sha,
			"fileType": file.FileType,
			"isText":   false,
		}, reqLogger)
		return
	}

	fetchCtx, cancel := context.WithTimeout(r.Context(), contentFetchTimeout)
	body, err := fetchFileBytes(fetchCtx, sha)
	cancel()
	if err != nil {
		if strings.Contains(err.Error(), "too large") {
			writeJSON(w, map[string]any{
				"sha":      sha,
				"fileType": file.FileType,
				"isText":   true,
				"tooLarge": true,
				"sizeStr":  formatBytes(file.Size),
			}, reqLogger)
			return
		}
		reqLogger.Debug("contents fetch failed", "error", err)
		writeJSONError(w, http.StatusBadGateway, "fetch_failed", "couldn't fetch file body")
		return
	}

	lines := renderTextContent(body, file.Findings, file.Path)
	writeJSON(w, map[string]any{
		"sha":       sha,
		"fileType":  file.FileType,
		"isText":    true,
		"lineCount": len(lines),
		"lines":     lines,
	}, reqLogger)
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

	emit := func(event, data string) bool {
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
			return false
		}
		flusher.Flush()
		return true
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
			exists, analyzed, err := db.SampleAnalyzed(ctx, sha)
			if err != nil {
				return "", ""
			}
			switch {
			case !exists:
				return "missing", `{"reason":"not found"}`
			case analyzed:
				return "ready", readyPayload(sha)
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
		var (
			analyzed bool
			err      error
		)
		exists, analyzed, err = db.SampleAnalyzed(ctx, sha)
		if err != nil {
			http.Error(w, `{"error":"lookup failed"}`, http.StatusInternalServerError)
			return
		}
		ready = analyzed
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
//
//nolint:revive // renderError calls are more verbose than http.Error but worth it for UX
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
			filename := filepath.Base(part.FileName())
			reqLogger = reqLogger.With("filename", filename)
			reqLogger.Info("forwarding upload to hopper")

			// Cap the file part's body even though the whole request is already
			// behind MaxBytesReader: a malformed multipart with one giant
			// non-file leading part could otherwise waste outbound bandwidth
			// to hopper before MaxBytesReader fires.
			res, uerr := uploadToHopper(ctx, io.LimitReader(part, maxUploadSize), filename, reqLogger)
			_ = part.Close() //nolint:errcheck // best-effort
			if uerr != nil {
				var maxErr *http.MaxBytesError
				switch {
				case errors.As(uerr, &maxErr):
					renderError(w, r, http.StatusRequestEntityTooLarge, errorData{
						Icon:    "⚖",
						Title:   "File too large",
						Message: "The web interface accepts files up to 100 MB.",
					})
				case errors.Is(uerr, errUploadTokenUnavailable):
					reqLogger.Warn("upload rejected: hopper token unavailable", "error", uerr)
					renderError(w, r, http.StatusServiceUnavailable, errorData{
						Icon:    "⏳",
						Title:   "Service warming up",
						Message: "The analysis service isn't ready yet. Please try again in a moment.",
					})
				default:
					reqLogger.Error("hopper upload failed", "error", uerr)
					renderError(w, r, http.StatusBadGateway, errorData{
						Icon:    "⚠",
						Title:   "Upload failed",
						Message: "Couldn't reach the analysis service. Please try again shortly.",
					})
				}
				return
			}
			reqLogger.Info("upload accepted by hopper",
				"sha256", res.SHA256,
				"size", res.Size,
				"already_analyzed", res.AlreadyAnalyzed,
				"total_duration_ms", time.Since(requestStart).Milliseconds(),
			)
			http.Redirect(w, r, "/file/"+res.SHA256, http.StatusSeeOther)
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

// errUploadTokenUnavailable means hopper hasn't yet provisioned the upload
// token (typically because the hopper service is still warming up). The
// upload handler surfaces this as a 503-equivalent UX to the user.
var errUploadTokenUnavailable = errors.New("hopper upload token unavailable")

// uploadTokenKey is the hopper KV key carrying the Bearer token for
// POST /api/upload. Rotations are signalled by hopper returning 401 to a
// previously-valid token; the next read picks up the new value.
const uploadTokenKey = "upload_token"

// uploadToHopper POSTs body to hopper /api/upload with a Bearer token read
// from hopper's KV table. The body is buffered up front so the request can
// be safely retried with backoff (and so the 401 rotation path can resend
// the same bytes). The buffer is bounded by the request-level
// MaxBytesReader plus the per-part io.LimitReader the caller wraps around
// the multipart part. On a 401 (token rotation signal) we re-read the
// token from KV and retry the upload exactly once.
func uploadToHopper(ctx context.Context, body io.Reader, filename string, log *slog.Logger) (*hopperUploadResponse, error) {
	db := hopperDB.Load()
	if db == nil {
		return nil, errUploadTokenUnavailable
	}
	buf, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read upload body: %w", err)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("build hopper request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := hopperClient.Do(req) //nolint:gosec // hopperUploadURL builds from admin-configured hopper-api host; filename is URL-encoded
	if err != nil {
		return nil, fmt.Errorf("hopper request: %w", err)
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

// prepareResultData converts raw cleave output to template data.
//
//nolint:gocognit,maintidx // inherently complex data assembly
func prepareResultData(ctx context.Context, filename, sha256Hex string, res *storedResult) resultData {
	data := resultData{
		Filename:            html.EscapeString(filename),
		SHA256:              sha256Hex,
		SHA256Short:         sha256Hex[:12] + "...",
		FileType:            "UNKNOWN",
		RiskLevel:           "",
		RiskLabel:           "",
		Size:                "0 B",
		FindingCount:        "0",
		Duration:            "0ms",
		MoleculeJSON:        template.JS("{}"),
		FileTreeJSON:        template.JS("null"),
		TraitOccurrenceJSON: template.JS("{}"),
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

	// Merge ML classifications from ml.fs into cleave report files (matched by id).
	mlByID := make(map[int]struct {
		Class int
		Prob  float64
	}, len(mlResp.Files))
	for _, f := range mlResp.Files {
		mlByID[f.ID] = struct {
			Class int
			Prob  float64
		}{f.Class, f.Prob}
	}
	for i := range report.Files {
		if ml, ok := mlByID[report.Files[i].ID]; ok {
			report.Files[i].Classification = classificationName(ml.Class)
			report.Files[i].Probability = ml.Prob
		}
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
	data.TotalFiles = len(report.Files)
	if len(report.Files) > maxArchiveFiles {
		report.Files = report.Files[:maxArchiveFiles]
	}
	data.ShownFiles = len(report.Files)

	// Build structured data for table display
	data.FileFindings = buildStructuredFindings(report.Files)
	data.FileStrings = buildStructuredStrings(report.Files)
	data.FileSymbols = buildStructuredSymbols(report.Files)
	data.FileSections = buildStructuredSections(report.Files)
	data.FileMetrics = buildStructuredMetrics(report.Files)
	data.FileKVs = buildStructuredKV(report.Files)
	data.Files = buildFileTree(report.Files, filename)
	if root := buildFileTreeNodes(report.Files); root != nil {
		if treeJSON, err := json.Marshal(root); err == nil {
			data.FileTreeJSON = template.JS(treeJSON) //nolint:gosec // JSON-marshalled data is safe for JS embedding
		}
	}
	if occ := buildTraitOccurrenceMap(report.Files); len(occ) > 0 {
		if occJSON, err := json.Marshal(occ); err == nil {
			data.TraitOccurrenceJSON = template.JS(occJSON) //nolint:gosec // JSON-marshalled data is safe for JS embedding
		}
	}
	data.ArchiveCategories = aggregateArchiveCategories(report.Files)

	// IsArchive reflects the underlying file set, not the findings count: an
	// archive whose children are all clean still has multiple files and
	// should render the file-tree view.
	data.IsArchive = len(report.Files) > 1

	// Contents tab: for non-archive text files, fetch the body and render
	// it with per-line trait annotations. fido caches the bytes by SHA so
	// repeat views (and parent-archive recursion for inner children) are
	// cheap. The fetch is bounded so a slow or down hopper-api degrades
	// gracefully — the page renders without contents instead of hanging.
	if !data.IsArchive && len(report.Files) > 0 && isTextFileType(report.Files[0].FileType) {
		data.IsText = true
		fetchCtx, cancel := context.WithTimeout(ctx, contentFetchTimeout)
		body, err := fetchFileBytes(fetchCtx, sha256Hex)
		cancel()
		switch {
		case err == nil:
			data.Contents = renderTextContent(body, report.Files[0].Findings, filename)
		case strings.Contains(err.Error(), "too large"):
			data.ContentTooLarge = true
			data.ContentSizeStr = formatBytes(report.Files[0].Size)
		default:
			logger.Debug("contents fetch failed", "sha256", sha256Hex, "error", err)
		}
	}

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

			// Extract string values for dropper detection
			var strs []string
			for _, s := range file.Strings {
				strs = append(strs, parseStringTupleValue(s)...)
			}

			// Also scan evidence for dropper detection
			for _, f := range file.Findings {
				strs = append(strs, f.Evidence...)
			}

			if len(ff) > 0 {
				fileFindings = append(fileFindings, FileFindings{
					Path:           file.Path,
					Risk:           critIntToString(maxCritInFile(file)),
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

// traitOccurrence records archive-wide stats for a single full trait ID:
// how many files it fired in, and the archive-Traits-tab card it maps to so
// the source-view sidebar can pivot back into that card.
type traitOccurrence struct {
	Category  string `json:"c"`
	ArchiveID string `json:"d"`
	Count     int    `json:"n"`
}

// buildTraitOccurrenceMap counts the distinct files where each full trait ID
// fires across the archive, keyed by the full ID. Only includes
// notable-or-higher findings (matches aggregateArchiveCategories).
func buildTraitOccurrenceMap(files []cleaveFile) map[string]traitOccurrence {
	perTraitFiles := make(map[string]map[string]struct{})
	perTraitArchive := make(map[string]traitOccurrence)
	for i := range files {
		f := &files[i]
		for _, t := range f.Findings {
			if t.Crit < 3 {
				continue
			}
			parts := strings.Split(t.ID, "/")
			if len(parts) < 2 {
				continue
			}
			cat := parts[0]
			var dir string
			if len(parts) > 2 {
				dir = strings.Join(parts[1:len(parts)-1], "/")
			} else {
				dir = parts[1]
			}
			if perTraitFiles[t.ID] == nil {
				perTraitFiles[t.ID] = make(map[string]struct{})
			}
			perTraitFiles[t.ID][f.SHA256] = struct{}{}
			perTraitArchive[t.ID] = traitOccurrence{Category: cat, ArchiveID: dir}
		}
	}
	out := make(map[string]traitOccurrence, len(perTraitFiles))
	for id, set := range perTraitFiles {
		a := perTraitArchive[id]
		a.Count = len(set)
		out[id] = a
	}
	return out
}

// aggregateArchiveCategories merges every file's findings into one category
// list, deduped by trait-ID directory prefix. Used by the archive Traits tab.
// Unlike per-file aggregation, this version attributes every aggregated trait
// back to the files that contributed, so the UI can expand a trait to show
// "fired in N files" and link to each.
// canonicalCategoryOrder is the preferred display order for top-level
// trait categories across the result page (both archive aggregation and
// per-file views). Categories not listed here render after all known
// ones, sorted alphabetically by key for determinism.
var canonicalCategoryOrder = []string{"well-known", "objectives", "micro-behaviors", "metadata", "third_party"}

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

// resolveMatchFile maps cleave's compact `el` location string to the
// inner file it refers to. Returns nil when the location is empty, isn't
// an archive-prefixed entry (semantic labels like "import"), or doesn't
// resolve to any known inner file (nested archives we didn't extract).
// Callers use the result to set Path/SHA256 on a FindingMatch; when nil
// the match falls back to either the current file (when not the
// archive container) or a path-less evidence row.
func resolveMatchFile(location string, pathToFile map[string]*cleaveFile) *cleaveFile {
	if location == "" {
		return nil
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

func aggregateArchiveCategories(files []cleaveFile) []CategoryGroup {
	categoryNames := map[string]string{
		"objectives":      "Objectives",
		"micro-behaviors": "Micro-behaviors",
		"metadata":        "Metadata",
		"well-known":      "Well-known",
		"third_party":     "Third-party",
	}

	type aggregated struct {
		// matches keyed by (evidence, fileSHA) so the same evidence value
		// matched in the same file collapses into one entry with a count.
		// Entries with empty fileSHA are evidence-only rows (no file
		// attribution available).
		matches  map[string]*FindingMatch
		// Insertion order so we can sort consistently when emitting.
		order    []string
		dirPath  string
		topLevel string
		desc     string
		crit     int
		conf     float64
	}
	bucket := make(map[string]*aggregated)
	// Track which SHAs are archive containers (depth 0). When a trait fires
	// inside the archive as well as on the container itself, the container
	// entry is just a rollup of inner-file findings — link to the actual
	// file the trait was inherited from, not the wrapping archive.
	containerSHAs := make(map[string]bool)
	// Path → file map used to back-attribute container-level findings to
	// the inner file that actually produced the match. Cleave's compact
	// `el` carries an "archive:<member-path>" string per evidence item;
	// we resolve that member-path against the same `displayPath` form
	// we already use elsewhere so existing inner files line up directly.
	pathToFile := make(map[string]*cleaveFile)
	for i := range files {
		if files[i].Depth == 0 {
			containerSHAs[files[i].SHA256] = true
			continue
		}
		pathToFile[displayPath(files[i].Path)] = &files[i]
	}

	for i := range files {
		file := &files[i]
		for _, f := range file.Findings {
			if f.Crit < 3 {
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
			// Walk evidence and locations in parallel. When cleave has
			// roll-up attribution (`el` populated), each evidence value
			// carries its source-file hint at the same index. We resolve
			// each pair into a (evidence, file?) match. Container-as-source
			// is dropped here: it's almost always a rollup that we can't
			// navigate to, so it would render as a dead link.
			for ei, ev := range f.Evidence {
				var (
					path string
					sha  string
				)
				if ei < len(f.Locations) {
					if target := resolveMatchFile(f.Locations[ei], pathToFile); target != nil {
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
					// Drop the archive container as a source — the file
					// tree skips depth-0 entries so the link wouldn't
					// resolve. Keep the evidence text; the row just
					// won't be clickable.
					path, sha = "", ""
				}
				mk := ev + "\x00" + sha
				if m, ok := agg.matches[mk]; ok {
					m.Count++
				} else {
					agg.matches[mk] = &FindingMatch{
						Evidence: ev,
						Path:     path,
						SHA256:   sha,
						Count:    1,
					}
					agg.order = append(agg.order, mk)
				}
			}
		}
	}
	if len(bucket) == 0 {
		return nil
	}

	categoryMap := make(map[string][]FindingDisplay)
	for _, agg := range bucket {
		matches := make([]FindingMatch, 0, len(agg.matches))
		for _, k := range agg.order {
			matches = append(matches, *agg.matches[k])
		}
		sort.SliceStable(matches, func(i, j int) bool {
			if matches[i].Count != matches[j].Count {
				return matches[i].Count > matches[j].Count
			}
			// Matches with a file link sort ahead of bare evidence so
			// clickable rows are visually grouped at the top.
			if (matches[i].SHA256 != "") != (matches[j].SHA256 != "") {
				return matches[i].SHA256 != ""
			}
			if matches[i].Evidence != matches[j].Evidence {
				return matches[i].Evidence < matches[j].Evidence
			}
			return matches[i].Path < matches[j].Path
		})
		const maxMatches = 24
		if len(matches) > maxMatches {
			matches = matches[:maxMatches]
		}
		categoryMap[agg.topLevel] = append(categoryMap[agg.topLevel], FindingDisplay{
			ID:      agg.dirPath,
			Crit:    critIntToString(agg.crit),
			Desc:    agg.desc,
			Matches: matches,
		})
	}

	critRank := map[string]int{"hostile": 3, "suspicious": 2, "notable": 1}
	for _, findings := range categoryMap {
		sort.SliceStable(findings, func(i, j int) bool {
			return critRank[findings[i].Crit] > critRank[findings[j].Crit]
		})
	}
	return orderCategories(categoryMap, categoryNames)
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

		// Aggregate findings by directory path (everything except last component)
		// Key: "topLevel/dirPath", Value: best finding for that directory
		type aggregatedFinding struct {
			evidence map[string]bool
			dirPath  string
			topLevel string
			desc     string
			crit     int
			conf     float64
		}
		aggregated := make(map[string]*aggregatedFinding)

		for _, f := range file.Findings {
			// Only show notable (3) or higher
			if f.Crit < 3 {
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

			existing, ok := aggregated[key]
			if !ok {
				evidenceSet := make(map[string]bool)
				for _, e := range f.Evidence {
					evidenceSet[e] = true
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
				shouldReplace := f.Crit > existing.crit ||
					(f.Crit == existing.crit && f.Conf > existing.conf)

				if shouldReplace {
					existing.crit = f.Crit
					existing.conf = f.Conf
					existing.desc = f.Desc
				}

				for _, e := range f.Evidence {
					existing.evidence[e] = true
				}
			}
		}

		// Group by top-level category
		categoryMap := make(map[string][]FindingDisplay)

		for _, agg := range aggregated {
			// Convert evidence map to sorted slice. Per-file findings
			// don't carry path attribution (we're already in that file's
			// context), so each match is an evidence-only row.
			var evidence []string
			for e := range agg.evidence {
				evidence = append(evidence, e)
			}
			sort.Strings(evidence)
			if len(evidence) > 8 {
				evidence = evidence[:8]
			}
			matches := make([]FindingMatch, 0, len(evidence))
			for _, e := range evidence {
				matches = append(matches, FindingMatch{Evidence: e, Count: 1})
			}

			fd := FindingDisplay{
				ID:      agg.dirPath, // Show directory path without top-level
				Crit:    critIntToString(agg.crit),
				Desc:    agg.desc,
				Matches: matches,
			}

			categoryMap[agg.topLevel] = append(categoryMap[agg.topLevel], fd)
		}

		critRank := map[string]int{"hostile": 3, "suspicious": 2, "notable": 1}

		// Sort findings within each category by criticality (desc), then alphabetically
		for cat := range categoryMap {
			findings := categoryMap[cat]
			sort.Slice(findings, func(i, j int) bool {
				ci, cj := critRank[findings[i].Crit], critRank[findings[j].Crit]
				if ci != cj {
					return ci > cj
				}
				return findings[i].ID < findings[j].ID
			})
			categoryMap[cat] = findings
		}

		categories := orderCategories(categoryMap, categoryNames)

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

// chromaCSSOnce-generated chroma stylesheet. Built once at startup so every
// result page can inline it without re-running the formatter.
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

// highlightLines tokenises body with the lexer matching filename and returns
// per-line chroma tokens. Returns nil if no lexer matches; callers then
// fall back to plain text rendering. The client renders each token as a
// span with the Class as its className and Text as textContent — no HTML
// is constructed server-side, so there is no innerHTML attack surface.
func highlightLines(body, filename string) [][]ContentToken {
	if filename == "" || body == "" {
		return nil
	}
	lexer := lexers.Match(filename)
	if lexer == nil {
		return nil
	}
	lexer = chroma.Coalesce(lexer)
	iter, err := lexer.Tokenise(nil, body)
	if err != nil {
		return nil
	}
	var lines [][]ContentToken
	var current []ContentToken
	emit := func() {
		lines = append(lines, current)
		current = nil
	}
	for tok := iter(); tok != chroma.EOF; tok = iter() {
		class := chroma.StandardTypes[tok.Type]
		// Walk the token's value, splitting on '\n'. A newline ends the
		// current line buffer; subsequent characters land in the next line.
		parts := strings.Split(tok.Value, "\n")
		for j, part := range parts {
			if j > 0 {
				emit()
			}
			if part == "" {
				continue
			}
			current = append(current, ContentToken{Class: class, Text: part})
		}
	}
	emit() // final line, even if empty
	return lines
}

// renderTextContent splits body into lines and tags each with the highest-
// crit finding whose evidence appears on that line. Multiple matching
// findings contribute their IDs to the line's hover tooltip; the dot color
// reflects only the worst hit so the visual stays readable.
//
// Evidence matching is plain substring search — cleave's evidence strings
// are usually exact line fragments, so this catches most cases without
// pulling in regex. Empty evidence strings are skipped to avoid matching
// every line.
//
// The output is capped at maxContentLines so a pathological 256KB file of
// 1-byte lines doesn't blow up the rendered DOM. A truncation marker tells
// the user the body was cut off.
//
// When filename matches a chroma lexer, each ContentLine also carries
// pre-rendered syntax-highlighted HTML in ContentLine.HTML. Callers should
// prefer HTML when set and fall back to Text.
func renderTextContent(body []byte, findings []finding, filename string) []ContentLine {
	rawLines := strings.Split(string(body), "\n")
	truncated := false
	if len(rawLines) > maxContentLines {
		rawLines = rawLines[:maxContentLines]
		truncated = true
	}
	highlights := highlightLines(strings.Join(rawLines, "\n"), filename)
	out := make([]ContentLine, 0, len(rawLines)+1)
	for i, line := range rawLines {
		// Strip trailing CR so Windows-style CRLF files don't render
		// stray glyphs and substring matching against evidence (which
		// usually doesn't carry CR) still works.
		line = strings.TrimRight(line, "\r")
		cl := ContentLine{Number: i + 1, Text: line}
		if i < len(highlights) {
			cl.Tokens = highlights[i]
		}
		if line == "" {
			out = append(out, cl)
			continue
		}
		bestCrit := 0
		seen := make(map[string]bool)
		for _, f := range findings {
			matched := false
			for _, e := range f.Evidence {
				if e == "" {
					continue
				}
				if strings.Contains(line, e) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			if f.Crit > bestCrit {
				bestCrit = f.Crit
			}
			if !seen[f.ID] {
				seen[f.ID] = true
				cl.Traits = append(cl.Traits, f.ID)
			}
		}
		if bestCrit > 0 {
			cl.Risk = critIntToString(bestCrit)
		}
		out = append(out, cl)
	}
	if truncated {
		out = append(out, ContentLine{
			Number: maxContentLines + 1,
			Text:   fmt.Sprintf("… file truncated to first %d lines; download to see the rest", maxContentLines),
		})
	}
	return out
}

// textFileTypes is the set of cleave file_type values whose content is
// displayable as plain text. The Contents tab shows the file body for these
// types; the Metadata tab is hidden because most don't carry useful kv yet.
var textFileTypes = map[string]bool{
	"javascript": true, "python": true, "ruby": true, "perl": true,
	"php": true, "go": true, "rust": true, "c": true, "cpp": true,
	"csharp": true, "java": true, "kotlin": true, "scala": true,
	"swift": true, "elixir": true, "shell": true, "powershell": true,
	"lua": true, "r": true, "haskell": true, "ocaml": true, "clojure": true,
	"erlang": true, "dart": true, "objective-c": true, "groovy": true,
	"makefile": true, "dockerfile": true, "cmake": true, "yaml": true,
	"toml": true, "ini": true, "xml": true, "html": true, "css": true,
	"text": true, "markdown": true, "package.json": true, "pkg-info": true,
	"json": true, "sql": true, "vue": true, "svelte": true, "typescript": true,
}

// isTextFileType reports whether cleave's file_type names a body the
// Contents tab can render directly.
func isTextFileType(t string) bool {
	return textFileTypes[strings.ToLower(strings.TrimSpace(t))]
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

// fileTreeNode is a single node in the hierarchical archive-contents tree
// emitted to the client. Compact JSON tags keep page weight low for big
// archives.
// Fields are ordered for fieldalignment: strings (2-word pointer-bearing
// headers) first, then the slice (3-word header — placed last among
// pointer fields so its trailing len/cap sit outside the GC scan area),
// then non-pointer fields. Within the strings, shared → file-only → dir-only.
type fileTreeNode struct {
	Name string `json:"n"`
	Path string `json:"p"`
	// File-only string fields.
	SHA      string `json:"sha,omitempty"`
	FileType string `json:"ty,omitempty"`
	SizeStr  string `json:"sz,omitempty"`
	Risk     string `json:"r,omitempty"`
	// Dir-only string field, rolled up from descendants.
	MaxRisk  string          `json:"mr,omitempty"`
	Children []*fileTreeNode `json:"c,omitempty"`
	// Non-pointer fields last (no GC scan past this point).
	Prob      float64 `json:"pr,omitempty"` // file-only
	MaxProb   float64 `json:"mp,omitempty"` // dir-only, rolled up
	FileCount int     `json:"fc,omitempty"` // dir-only, rolled up
	Dir       bool    `json:"d,omitempty"`
}

// buildFileTreeNodes constructs a directory tree from the archive's files,
// rolls up severity/probability for each directory, and collapses long
// single-child directory chains so a path like
// "github.com/benedict-erwin/gqm@v0.1.2/internal/foo.go" renders as one
// breadcrumb pill rather than three wasted Miller columns.
func buildFileTreeNodes(files []cleaveFile) *fileTreeNode {
	root := &fileTreeNode{Dir: true}
	for i := range files {
		f := &files[i]
		if f.Depth == 0 {
			continue // skip archive container itself
		}
		path := displayPath(f.Path)
		path = strings.TrimPrefix(path, "./")
		path = strings.TrimPrefix(path, "/")
		if path == "" {
			continue
		}
		segments := strings.Split(path, "/")
		cur := root
		for si, seg := range segments {
			isLeaf := si == len(segments)-1
			child := findChild(cur, seg)
			if child == nil {
				child = &fileTreeNode{
					Name: seg,
					Path: strings.Join(segments[:si+1], "/"),
					Dir:  !isLeaf,
				}
				cur.Children = append(cur.Children, child)
			}
			if isLeaf {
				child.Dir = false
				child.SHA = f.SHA256
				child.FileType = strings.ToUpper(f.FileType)
				child.SizeStr = formatBytes(f.Size)
				child.Risk = critIntToString(maxCritInFile(f))
				child.Prob = f.Probability
				if child.Risk == "" && f.Classification != "" && f.Classification != "benign" {
					child.Risk = f.Classification
				}
			}
			cur = child
		}
	}
	rollupTree(root)
	collapseChains(root)
	sortTree(root)
	return root
}

// findChild locates an immediate child of n by name, or returns nil.
func findChild(n *fileTreeNode, name string) *fileTreeNode {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// rollupTree fills MaxRisk / MaxProb / FileCount on every directory by
// recursing into descendants.
func rollupTree(n *fileTreeNode) {
	if !n.Dir {
		return
	}
	rank := map[string]int{"hostile": 3, "suspicious": 2, "notable": 1}
	worstRank := 0
	var maxProb float64
	count := 0
	for _, c := range n.Children {
		rollupTree(c)
		if c.Dir {
			count += c.FileCount
			if r := rank[c.MaxRisk]; r > worstRank {
				worstRank = r
				n.MaxRisk = c.MaxRisk
			}
			if c.MaxProb > maxProb {
				maxProb = c.MaxProb
			}
		} else {
			count++
			if r := rank[c.Risk]; r > worstRank {
				worstRank = r
				n.MaxRisk = c.Risk
			}
			if c.Prob > maxProb {
				maxProb = c.Prob
			}
		}
	}
	n.FileCount = count
	n.MaxProb = maxProb
}

// collapseChains squashes runs of single-child directories so that
// `a -> b -> c -> leaves` becomes one node named `a/b/c` whose children are
// the leaves. Cosmetic only — Path stays intact, so #file=<sha> still works.
func collapseChains(n *fileTreeNode) {
	if !n.Dir {
		return
	}
	for len(n.Children) == 1 && n.Children[0].Dir {
		only := n.Children[0]
		if n.Name == "" {
			n.Name = only.Name
		} else {
			n.Name = n.Name + "/" + only.Name
		}
		n.Path = only.Path
		n.Children = only.Children
	}
	for _, c := range n.Children {
		collapseChains(c)
	}
}

// sortTree orders directory contents: dirs first (alpha), then files sorted
// by Probability desc so risky ones lead.
func sortTree(n *fileTreeNode) {
	if !n.Dir {
		return
	}
	sort.SliceStable(n.Children, func(i, j int) bool {
		a, b := n.Children[i], n.Children[j]
		if a.Dir != b.Dir {
			return a.Dir
		}
		if a.Dir {
			return a.Name < b.Name
		}
		if a.Prob != b.Prob {
			return a.Prob > b.Prob
		}
		return a.Name < b.Name
	})
	for _, c := range n.Children {
		sortTree(c)
	}
}

// buildFileTree converts cleave files into FileTreeEntry rows for the
// archive Files tab. Order matches the input (already sorted by severity in
// prepareResultData), so the left-pane tree shows risky files first within
// each directory's group.
func buildFileTree(files []cleaveFile, archiveFilename string) []FileTreeEntry {
	out := make([]FileTreeEntry, 0, len(files))
	for i := range files {
		f := &files[i]
		display := displayPath(f.Path)
		isContainer := f.Depth == 0
		if isContainer {
			display = archiveFilename
		}
		risk := critIntToString(maxCritInFile(f))
		short := f.SHA256
		if len(short) > 8 {
			short = short[:8]
		}
		out = append(out, FileTreeEntry{
			Path:           f.Path,
			Display:        display,
			Basename:       extractBasename(f.Path),
			SHA256:         f.SHA256,
			SHA256Short:    short,
			Classification: f.Classification,
			Risk:           risk,
			Formula:        f.Formula,
			FileType:       strings.ToUpper(f.FileType),
			Size:           f.Size,
			SizeStr:        formatBytes(f.Size),
			Probability:    f.Probability,
			Depth:          f.Depth,
			IsContainer:    isContainer,
		})
	}
	return out
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
// Fields like formula, file_type, sha256 are embedded in cleave.fs[0],
// not at the top level.
// litmusFullResponse matches the top-level {"ml": {...}, "raw": {...}} envelope.
type litmusFullResponse struct {
	ML  json.RawMessage `json:"ml"`
	Raw json.RawMessage `json:"raw"`
}

// litmusMlResponse matches the ml section of the litmus response.
type litmusMlResponse struct {
	V          string `json:"v"`
	Version    string `json:"version"`
	AnalyzedAt string `json:"analyzed_at"`
	Files      []struct {
		ID    int     `json:"id"`
		Class int     `json:"class"`
		Prob  float64 `json:"prob"`
	} `json:"fs"`
	Thresholds     [2]float64 `json:"thresholds"`
	Classification int        `json:"class"`
	Probability    float64    `json:"prob"`
}

// classificationNames maps integer classification to display string.
var classificationNames = [3]string{"benign", "suspicious", "hostile"}

func classificationName(c int) string {
	if c >= 0 && c < len(classificationNames) {
		return classificationNames[c]
	}
	return "unknown"
}

func (r *litmusMlResponse) suspiciousT() float64 { return r.Thresholds[0] }
func (r *litmusMlResponse) hostileT() float64    { return r.Thresholds[1] }

// v4 cleave types are defined above: cleaveReport, cleaveFile, finding.

// v4: cleave output deserializes directly into cleaveReport via json tags.
// parseAPIResponse and uploadToGCS removed.
