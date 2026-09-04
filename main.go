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
	"net/http/pprof"
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
	_ "time/tzdata" // embeds the IANA database so viewerLocation works on hosts carrying no zoneinfo
	"unicode"
	"unicode/utf8"

	"github.com/alecthomas/chroma/v2"
	chromahtml "github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/atomdrift-project/hopper"
	"github.com/atomdrift-project/hopper/pkgparse"
	"github.com/atomdrift-project/obs"
	"github.com/codeGROOVE-dev/fido"
	"github.com/codeGROOVE-dev/fido/pkg/store/localfs"
	"github.com/codeGROOVE-dev/fido/pkg/store/null"
	"github.com/codeGROOVE-dev/retry"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// faviconSVG is served at the well-known /favicon.ico path. Browsers request
// that path unprompted; without a route it falls through to GET /{ecosystem}
// and runs a bogus feed query (ecosystem="favicon.ico"). Serving the SVG here
// gives the tab its icon and stops that stray database hit.
//
//go:embed static/favicon.svg
var faviconSVG []byte

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
	uploadTemplate    *template.Template
	falloutTemplate   *template.Template
	resultTemplate    *template.Template
	errorTemplate     *template.Template
	formatsTemplate   *template.Template
	poweredByTemplate *template.Template
	helpQueryTemplate *template.Template
	pendingTemplate   *template.Template
	hopperAPIAddr     string       // Address of hopper API server (e.g., "hopper-api:8081")
	hopperClient      *http.Client // HTTP client for hopper API server
	litmusAddr        string       // Address of the dedicated litmus analysis server; empty disables it
	litmusClient      *http.Client // HTTP client for the litmus analysis server
	cache             *fido.TieredCache[string, storedResult]
	feedCache         *fido.TieredCache[string, cachedFeedSnapshot]
	// feedStaleCache holds the last-known-good snapshot per feed key with a long
	// TTL (feedStaleTTL), separate from feedCache's 30-min working entries. It is
	// the graceful-degradation fallback: when a live feed query fails (hopper-db
	// timeout, circuit breaker open, replica blip) loadFeedSnapshot serves the
	// stale snapshot from here instead of returning a 500. Memory-only and
	// bounded by the same s3fifo tier as feedCache.
	feedStaleCache     *fido.TieredCache[string, cachedFeedSnapshot]
	feedDropdownCache  *fido.TieredCache[string, feedDropdowns]
	reportCache        *fido.TieredCache[string, cachedReport]
	parentArchiveCache *fido.TieredCache[string, cachedParents]
	membersCache       *fido.TieredCache[string, cachedMembers]
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
	// Reads go to the logical replica (hopper-replica) to offload the master;
	// prism's own pool is read-only — all writes route through hopper's HTTP
	// API (hopperAPIAddr), which still targets the master, so a read-only
	// subscriber is safe here. application_name tags the connection for
	// server-side attribution in pg_stat_activity.
	defaultHopperDSN     = "postgres://hopper@hopper-replica:5432/hopper?sslmode=disable&application_name=prism"
	defaultHopperAPIAddr = "hopper-api:8081"
	// defaultLitmusAddr is the dedicated analysis server (atomscan serve's
	// default listen port), reachable as "scan" — "litmus" is the service's
	// former name and no longer resolves. Uploads are analyzed here first; when
	// it returns, prism publishes the result to hopper so hopper's own worker
	// pool doesn't duplicate the work. Optional — when unreachable, hopper
	// analyzes instead.
	defaultLitmusAddr = "scan:49999"
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
	// feedStaleTTL is how long a last-known-good snapshot stays servable as the
	// degraded-mode fallback (feedStaleCache). It is much longer than
	// feedCacheTTL on purpose: the working entry expires after 30 minutes, but
	// the fallback must outlive a multi-hour hopper outage so the index page can
	// keep serving slightly-stale rows the whole time instead of a 500.
	feedStaleTTL = 24 * time.Hour
	// feedArchiveTTL is the lifetime of a snapshot of a closed window — a
	// fallout week that has already ended. Its rows cannot change, so the only
	// reason to rebuild it is memory: long enough that browsing the archive
	// (or a crawler walking it) re-queries nothing, short enough that a week
	// nobody has looked at since breakfast does not hold its rows all day.
	feedArchiveTTL = 6 * time.Hour
	// feedDropdownTTL bounds how long the cached ecosystem/domain filter
	// options are reused before a rebuild re-queries them. They are identical
	// for every feed filter and change slowly (a new ecosystem or domain shows
	// up a handful of times a day), so one refresh every few minutes backs
	// every uncached rebuild in that window instead of two DISTINCT-over-the-
	// corpus scans per request.
	feedDropdownTTL = 5 * time.Minute
	// feedRebuildTimeout bounds a single feed-snapshot rebuild. The rebuild
	// runs under this deadline on a context detached from the caller's
	// request (see loadFeedSnapshot): in a singleflight cache the loader is
	// shared by every coalesced waiter, so it must outlive any one client
	// disconnecting. A generous ceiling that still guarantees the loader
	// can't hang forever and wedge the feed (the 2026-06-18 outage).
	feedRebuildTimeout = 60 * time.Second
	// hopperQueryTimeout bounds a single hopper-db read (feed query or
	// sample lookup) independently of the caller's context. Some legitimate
	// queries are slow, so the ceiling is generous; its job is to guarantee
	// a degraded hopper-db can't pin a request goroutine indefinitely, and
	// to give the circuit breaker a timely failure to trip on.
	hopperQueryTimeout = 60 * time.Second
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

// loadCSRFKey resolves the CSRF HMAC key from PRISM_CSRF_KEY_FILE (preferred)
// or PRISM_CSRF_KEY. The file form lets service managers provide the key as a
// credential instead of exposing it in the process environment. The secret is
// run through SHA-256 so any encoding (hex, base64, raw) yields a full-width
// 256-bit key; a >=32-character minimum is a coarse entropy floor. Absent or
// too-short, it keeps the per-process random key and warns — fine for a single
// instance or local dev, but a multi-instance deployment will otherwise see
// intermittent "session expired" failures on upload/rescan/download.
func loadCSRFKey() [32]byte {
	secret := strings.TrimSpace(os.Getenv("PRISM_CSRF_KEY"))
	if path := strings.TrimSpace(os.Getenv("PRISM_CSRF_KEY_FILE")); path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // service-operator configuration, not request input
		if err != nil {
			logger.Warn("failed to read PRISM_CSRF_KEY_FILE; falling back to PRISM_CSRF_KEY", "error", err)
		} else {
			secret = strings.TrimSpace(string(data))
		}
	}
	if len(secret) < 32 {
		if secret != "" {
			logger.Warn("configured CSRF key too short (need >=32 chars); using per-process CSRF key")
		} else {
			logger.Warn("CSRF key unset; using per-process CSRF key — tokens will not validate across instances or restarts")
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
	//nolint:gosec // G124: HttpOnly and SameSite are set; Secure is conditional only so plaintext local dev works.
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

// Upload: 1 every 10 seconds per IP, burst of 5. A burst of 2 rejected anyone
// comparing a handful of samples back to back, which is ordinary use, not abuse
// — the real capacity backstop is the litmusSlots semaphore, which sheds to
// hopper-only analysis rather than failing.
var uploadRateLimiter = newTokenLimiter(5, 1.0/10.0)

// uploadGlobalLimiter caps the total upload rate across all clients so a
// botnet rotating IPs can't bypass the per-IP limiter and overwhelm the
// analyzer pipeline. 15/min sustained, burst of 20 absorbs a small crowd of
// legitimate users without queueing, and leaves enough headroom that one
// active uploader isn't throttled by the global budget alone. Bypassing both
// this and the per-IP limiter requires both a botnet *and* patience.
var uploadGlobalLimiter = newTokenBucket(15.0/60.0, 20)

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

// ParentArchive is one archive that contains the currently-viewed file. It
// powers the "found in" backlinks shown on standalone child pages so users
// can navigate up to the archive context they came from.
type ParentArchive struct {
	SHA256      string
	SHA256Short string
	Filename    string
	// ChildSHA is the child this backlink was looked up for, so the row's
	// link can deep-link the archive view at that member (#file=<child>).
	ChildSHA string
	Path     string // path of this child within the parent (from sample_locations)
	// Rel is the edge type from sample_locations: "" for a contained member,
	// "fetched" for content the parent references and litmus retrieved (never
	// actually inside it), "unpacked" for a transform product, "registry" for
	// a provenance sidecar. Decides which backlinks panel the row renders in.
	Rel            string
	Classification string // "hostile" / "suspicious" / "benign" / ""
	AnalyzedAt     string // human-readable UTC date
	AnalyzedAgo    string // relative time
	// Parent identity, for members whose headline names their source (OS images):
	// feed distinguishes an image container, and ecosystem/version/package give the
	// clean "netbsd 10.1 (amd64)" without parsing the filename.
	Feed      string
	Ecosystem string
	Version   string
	Package   string
}

// containsChild reports whether this parent physically contains the child
// (an extracted or unpacked member) as opposed to merely referencing it (a
// fetched payload or registry lookup). Splits the backlinks into the
// "Found in N archives" and "Referenced by N samples" panels — the former is
// a containment claim and must never be made for fetched content. Value
// receiver on purpose: html/template calls it on {{range}} copies.
//
//nolint:gocritic // hugeParam — a pointer receiver breaks template rendering
func (p ParentArchive) containsChild() bool {
	return p.Rel == "" || p.Rel == "unpacked"
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

// cachedMembers holds the fully-rendered GET /file/{sha}/members response. The
// archive analysis is immutable once stored, so this is deterministic per sha:
// caching it lets a hit skip the member DB fetch, hopper.Reassemble, and both
// template executions, leaving only a cheap re-encode of the finished strings.
// The json tags are the client-facing field names. Dropped by
// invalidateSampleCaches on rescan.
type cachedMembers struct {
	ContentHTML string `json:"content_html"`
	TraitsHTML  string `json:"traits_html"`
	HasContent  bool   `json:"has_content"`
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
	DownloadToken string
	FileType      string
	// DeferredMembers marks a compacted-archive page whose member Content and
	// galaxy are lazy-loaded by the browser from /file/{sha}/members. The
	// template renders loading placeholders for those regions; a non-archive or
	// a fully-inlined archive leaves it false and renders everything up front.
	DeferredMembers bool
	// MembersHTML/MembersTraits carry the already-built member evidence when the
	// payload was in cache at render time. The page then ships complete and the
	// browser makes no second request at all; DeferredMembers stays false.
	MembersHTML     template.HTML
	MembersTraits   template.HTML
	Duration        string
	FindingCount    string
	Nonce           string // script-src nonce
	StyleNonce      string // style-src nonce
	Size            string
	SizeBytes       int64 // raw size of the top-level (or first) file; gates the download button
	DownloadEnabled bool  // false when the shared hopper-api liveness probe is down
	RiskLevel       string
	ReportCreated   string
	ReportProvider  string
	ReportContent   string
	AnalyzedAgo     string
	AnalyzedAt      string
	// AnalyzedAtMillis is the unix-ms timestamp of the most recent
	// analysis, exposed to JS via a data-attribute on the rescan button
	// so the rescan-then-wait flow can ask the server "tell me when a
	// fresh analysis lands AFTER this point" instead of accepting the
	// already-stale result.
	AnalyzedAtMillis int64
	RiskLabel        string
	// LLMInterpretation is the one-sentence rationale from the optional LLM
	// interpretation pass (litmus `llm.interpretation`), shown in the hero when
	// present — typically only on suspicious/hostile samples. LLMConfidence is
	// the blended confidence as a percentage. Both empty/zero when no
	// interpretation ran (the common case). An ML/LLM disagreement is surfaced
	// through VerdictTip rather than a separate badge.
	LLMInterpretation string
	LLMConfidence     int
	// Headline is the hero's identity line, sharing the feed rows' grammar
	// (marketplace title → package → filename, plus attributed version) so
	// the name the user clicked in the feed is the name on the page.
	// RegistryDesc and Users are the marketplace listing description and
	// formatted install count; both empty when no registry record exists.
	// MetaDesc is the social-preview description (og:description): the LLM
	// rationale, else the strongest trait's description, else empty.
	Headline     string
	RegistryDesc string
	Users        string
	MetaDesc     string
	FirstSeenAgo string
	FirstSeenAt  string
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
	// PURL is the full versioned Package URL shown in the hero, using the
	// human-readable UI spelling for npm scopes (e.g. "pkg:npm/@scope/pkg") —
	// hopper's version-less PURLBase with the version appended. Empty for
	// uploads and ecosystems without a PURL type; the template hides the meta
	// row when empty.
	PURL string
	// PURLIndexURL makes the hero's Package row a link to the package's
	// version index — normally the coordinate's rooted path (/npm/lodash),
	// see purlIndexURL. Empty when the sample has no purl_base, which leaves
	// the row plain text.
	PURLIndexURL string
	// DetectedBy lists the external sources that have also cited this sample
	// (hopper's sightings ledger, keyed by sha256 + purl_base), filtered to
	// the sources we name publicly: open databases (osv, opensourcemalware) and blogs
	// (cyclotron:*). Commercial vendors and scanners are not name-dropped;
	// they are rolled up into MoreSources, a pre-formatted count chip ("+2
	// more", "3 sources"; empty when zero). Both empty hides the "also
	// detected by" row. Populated at render time from a live SightingsFor
	// read, so a newly-arrived citation shows without a rescan.
	DetectedBy   []Citation
	MoreSources  string
	Layout       string
	BuildCommit  string
	FileFindings []FileFindingsDisplay
	// FileViews is the per-file context view shown in the File tab. When
	// non-empty the File tab renders and is the page's default tab; empty for
	// legacy reports without current-format context, which keep Traits default.
	FileViews []fileView
	// Tree is the containment/provenance hierarchy built from the members'
	// `pid` edges — the archive → member → fetched-dependency structure shown
	// in the Structure tab. Its single root has children only for an archive;
	// a lone file yields a one-node tree, and the tab stays hidden.
	Tree []*treeNode
	// FlaggedDeps are the fetched dependencies whose own scan classified
	// suspicious or hostile, shown in a panel between the hero and the tabs
	// (same placement as "Found in"/"Referenced by"). Benign dependencies are
	// deliberately absent — the panel exists to explain an elevated verdict,
	// not to inventory every reference (the Structure tab does that).
	FlaggedDeps []flaggedDep
	// FlaggedDepsHidden is how many flagged dependencies the panel's cap
	// dropped, so a sample with hundreds of them says so rather than
	// presenting the first two dozen as the whole set.
	FlaggedDepsHidden int
	// TopTraits is the Content tab's headline: the few most significant traits
	// (highest crit×confidence, suspicious+), each linking to its evidence
	// section. Empty when nothing reaches the suspicious bar.
	TopTraits []topTrait
	// ContentLocStyle sets the --ctx-loc-ch CSS variable (the widest loc string
	// across every window) on the Content tab, so each window's line-number /
	// hex-offset column shares one width and the columns line up within and
	// between files. Empty when there are no file views.
	ContentLocStyle template.HTMLAttr
	// FilesOmitted / ResultsOmitted count the files and the results (windows +
	// composites) the Content tab dropped to stay legible; FilesShownLimit is
	// the per-page file cap. When FilesOmitted > 0 the tab shows a "results
	// limited" note tallying both.
	FilesOmitted    int
	ResultsOmitted  int
	FilesShownLimit int
	// Provenance is the grouped origin record shown in the Provenance tab:
	// what hopper's database knows about where this sample came from. Empty
	// for samples with no recorded provenance beyond their own identity.
	Provenance []ProvenanceGroup
	// Badges are the findings the header names outright; Summary is the line
	// under the title; ShortProv is the rail's provenance; MaleculeSVG is the
	// compound drawing; CompoundURL finds other samples with this formula.
	Badges []topTrait
	// Findings lists what was found when no evidence region can be drawn,
	// because the sample's findings carry no byte spans.
	Findings       []findingRow
	FindingsHidden int
	Summary        string
	ShortProv      []ProvenanceRow
	MaleculeSVG    template.HTML
	CompoundURL    string
	// Parents lists archives that contain this file (extracted or unpacked
	// members). Populated only on standalone child pages (non-archive views)
	// so the user can navigate up to the archive context the file came from.
	Parents []ParentArchive
	// Referrers lists samples that merely reference this file — its bytes
	// were fetched from a URL/package the sample declares, or looked up as
	// its registry record — and never contained it. Rendered as a separate
	// "Referenced by" panel so prism never claims containment it can't show.
	Referrers []ParentArchive
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
	// LevelConfidence is the level-derived "how confident this is hostile"
	// percentage shown on the litmus badge (from ml.conf, falling back to
	// levelConfidence for cached envelopes).
	LevelConfidence int
	// VerdictTip is the hover text for the level percentage badge: normally a
	// terse "[L250] 80% confident hostile (lower levels are stricter)", but when
	// the LLM interpretation moved the verdict off the raw ML class it instead
	// reads "[L250] ML rated as hostile, LLM downgraded to suspicious".
	VerdictTip  string
	Probability float64
	IsArchive   bool
	// HasTree gates the Structure tab: the containment tree has a root with at
	// least one child (an archive), not a lone file whose tree is one node.
	HasTree       bool
	LimitedInfo   bool
	RescanAllowed bool // last analysis is older than rescanCooldown — the rescan button is hidden when false
}

// storedResult is what we persist in fido/datastore.
type storedResult struct {
	CachedAt        time.Time
	AnalyzedAt      time.Time
	CreatedAt       time.Time
	FirstAnalyzedAt time.Time
	UpdatedAt       time.Time
	RawLitmus       string
	Label           string
	Classification  string
	Formula         string
	FileType        string
	Strings         string
	Traits          string
	Sections        string
	SourceURL       string
	SourceDomain    string
	Ecosystem       string
	Metrics         string
	Source          string
	Feed            string
	Package         string
	Version         string
	// RegistryTitle/RegistryDesc (with RegistryDownloads below, by the other
	// numerics) mirror hopper's provenance registry-record scalars
	// (marketplace listing title, capped short description, install count);
	// zero for samples without a registry sidecar and for results cached
	// before the fields existed.
	RegistryTitle string
	RegistryDesc  string
	// PURLBase is hopper's version-less canonical Package URL (e.g.
	// "pkg:npm/lodash"); empty for uploads and ecosystems without a defined
	// PURL type. The full versioned PURL shown in the hero is this plus
	// "@"+Version.
	PURLBase          string
	Filename          string
	LabelSource       string
	TraitsVersion     string
	CanonicalSHA256   string
	Symbols           string
	SizeBytes         int64
	RegistryDownloads int64
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
	// Package/Version are hopper's registry attribution (e.g. "lodash",
	// "4.17.21"); both empty for uploads and unattributed samples. The
	// template reads them through Headline and SubID.
	Package string
	Version string
	// PURLBase is hopper's version-less canonical Package URL. It is carried
	// through the feed snapshot so machine consumers can recover the full PURL
	// without issuing a detail-page query.
	PURLBase string
	// RegistryTitle is the marketplace display title from the provenance
	// sidecar's registry record (e.g. a Chrome extension's store listing
	// name) and Desc its short description; both empty when the collector
	// recorded none. Users is the pre-formatted install/download count
	// ("412,033", empty when unknown); Downloads, the raw figure behind it,
	// sits below with the other numerics.
	RegistryTitle string
	Desc          string
	Users         string
	// Why is the one-sentence rationale for the row's verdict — the LLM
	// interpretation when that pass ran (litmus `llm.interpretation`), empty
	// otherwise. Conf is the verdict confidence as a 0–100 percentage: the
	// blended LLM confidence when a rationale exists, otherwise the ml-pass
	// confidence (zero for benign verdicts, which hides the chip). TopTraits
	// carries the row's headline trait chips; the ledger shows the top two
	// only when no LLM rationale exists (FallbackTraits), while the Hot
	// Particle shows them all as its evidence row.
	Why string
	// LLMGrade is the LLM interpretation pass's own raw verdict for the
	// sample ("benign"/"suspicious"/"hostile", empty when no pass ran; litmus
	// `llm.grade`). It is the LLM's opinion alone, before the blend that
	// produces Classification — the fallout log gates on it so a catch shows
	// only when the LLM itself agrees the sample looks hostile.
	LLMGrade  string
	TopTraits []feedTrait
	Conf      int
	// Corroborated marks a sample an external threat feed, scanner, blog, or
	// advisory has cited (hopper's sightings ledger, via samples.corroborated) —
	// the per-row "✓" mark. The citing sources stay off the feed page; the
	// detail page names only open databases and blogs (DetectedBy).
	Corroborated bool
	Downloads    int64
	HostileT     float64
	SuspiciousT  float64
	Probability  float64
	// Threshold/Class populated from v=5 envelopes; Threshold > 0 selects
	// the exact-band rendering path in templates.
	Threshold float64
	Class     int
}

// Title is the most recognizable name for the sample: the marketplace display
// title when the collector recorded one, else the package name, else the
// filename — the same preference order as cleave's identity headline. Value
// receiver on purpose: html/template calls it on the non-addressable copies a
// {{range}} yields, which cannot reach a pointer receiver's method set.
//
//nolint:gocritic // see above — a pointer receiver breaks template rendering
func (r feedRow) Title() string {
	return firstNonEmpty(r.RegistryTitle, r.Package, r.Filename)
}

// Headline is the row's bold identity line: Title plus the version when one
// is attributed ("Volume Max 5.2.1", "nomad-pydantic 0.0.0"). Value receiver
// for the same html/template reason as Title.
//
//nolint:gocritic // see above — a pointer receiver breaks template rendering
func (r feedRow) Headline() string {
	return identityHeadline(r.RegistryTitle, r.Package, r.Filename, r.Version)
}

// identityHeadline is the shared identity grammar for feed rows and the
// detail hero: the most recognizable name (marketplace title → package name →
// filename) with the attributed version appended. A filename fallback stays
// bare — filenames usually embed their version already, and the version
// column belongs to the package attribution.
func identityHeadline(registryTitle, pkg, filename, version string) string {
	// A bare sample carries its own hash as its package name. A hash is an
	// identifier, not a name — it already sits in the ids block below — so it
	// yields to any real filename before it becomes the page's title.
	if isHashName(registryTitle) {
		registryTitle = ""
	}
	if isHashName(pkg) {
		pkg = ""
	}
	title := firstNonEmpty(registryTitle, pkg, filename)
	if version == "" || (registryTitle == "" && pkg == "") {
		return title
	}
	return title + " " + version
}

// isHashName reports whether a name is nothing but a hex digest — the md5,
// sha1 or sha256 a bare upload is filed under when no registry named it.
func isHashName(s string) bool {
	switch len(s) {
	case 32, 40, 64:
	default:
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// imageMemberHeadline builds a headline naming the OS image a file came from —
// e.g. "/bin/ls from netbsd 10.1 (amd64)" — for a sample found inside an osimage
// container. It reads the already-loaded found-in parents (no extra query): the
// in-archive path from the containment edge, and the OS/version/edition from the
// parent anchor's columns. Returns false when no osimage parent applies, leaving
// the ordinary filename headline in place.
func imageMemberHeadline(parents []ParentArchive) (string, bool) {
	for i := range parents {
		p := &parents[i]
		if p.Feed != "osimage" {
			continue
		}
		inPath := p.Path
		if i := strings.Index(inPath, "!!"); i >= 0 {
			inPath = inPath[i+2:] // the path within the image, past the "container!!" prefix
		} else {
			inPath = filepath.Base(inPath)
		}
		if inPath != "" && !strings.HasPrefix(inPath, "/") {
			inPath = "/" + inPath
		}
		osName := osDisplayName(firstNonEmpty(p.Ecosystem, p.Package))
		if osName == "" {
			return inPath, inPath != ""
		}
		hl := inPath + " from " + osName
		if p.Version != "" {
			hl += " " + p.Version
		}
		// Package is "os/edition"; surface just the edition (e.g. "amd64").
		if edition := strings.TrimPrefix(p.Package, p.Ecosystem+"/"); edition != "" && edition != p.Package {
			hl += " (" + edition + ")"
		}
		return hl, true
	}
	return "", false
}

// osDisplayNames maps an os-image ecosystem slug to its properly-cased product
// name. Only irregular capitalizations and multi-word names need an entry; a plain
// title-case fallback handles the rest (and any future slug). Keys are the lower-
// case slugs the osimage feed emits.
var osDisplayNames = map[string]string{
	"macos": "macOS", "netbsd": "NetBSD", "freebsd": "FreeBSD", "openbsd": "OpenBSD",
	"ghostbsd": "GhostBSD", "dragonflybsd": "DragonFly BSD", "opensuse": "openSUSE",
	"nixos": "NixOS", "freedos": "FreeDOS", "reactos": "ReactOS", "redox": "Redox", //nolint:misspell // FreeDOS is the OS's real name, not "freedoms"
	"raspios": "Raspberry Pi OS", "androidx86": "Android-x86", "kdeneon": "KDE neon",
	"mxlinux": "MX Linux", "almalinux": "AlmaLinux", "amazonlinux": "Amazon Linux",
	"oraclelinux": "Oracle Linux", "endeavouros": "EndeavourOS", "cachyos": "CachyOS",
	"omnios": "OmniOS", "openindiana": "OpenIndiana", "9front": "9front",
	"talos": "Talos Linux", "photon": "Photon OS", "qubes": "Qubes OS", "arch": "Arch Linux",
	"kali": "Kali Linux", "mint": "Linux Mint", "void": "Void Linux", "rocky": "Rocky Linux",
	"centos": "CentOS", "proxmox": "Proxmox VE", "parrot": "Parrot OS", "kubuntu": "Kubuntu",
	"lubuntu": "Lubuntu", "xubuntu": "Xubuntu", "opensuse-tumbleweed": "openSUSE Tumbleweed",
}

// osDisplayName returns the product name for an os-image ecosystem slug — an
// explicit entry when the casing is irregular ("macos" → "macOS"), otherwise the
// slug with its first letter upper-cased. Empty in, empty out.
func osDisplayName(slug string) string {
	if slug == "" {
		return ""
	}
	if d, ok := osDisplayNames[strings.ToLower(slug)]; ok {
		return d
	}
	return strings.ToUpper(slug[:1]) + slug[1:]
}

// SubID is the machine coordinate shown muted beside the headline, only when
// it says something the headline doesn't: the package id when a marketplace
// title displaced it (a Chrome extension's store name vs its extension id).
// Empty — and omitted — when the headline already is the package name, so the
// identity line never repeats itself. Value receiver for the same
// html/template reason as Title.
//
//nolint:gocritic // see above — a pointer receiver breaks template rendering
func (r feedRow) SubID() string {
	if r.Package == "" || r.Package == r.Title() {
		return ""
	}
	return r.Package
}

// FallbackTraits is the ledger row's rationale line when no LLM
// interpretation ran: the top two headline traits. The interpretation replaces
// the chips rather than stacking with them. Value receiver for the same
// html/template reason as Title.
//
//nolint:gocritic // see above — a pointer receiver breaks template rendering
func (r feedRow) FallbackTraits() []feedTrait {
	if r.Why == "" {
		return r.TopTraits[:min(2, len(r.TopTraits))]
	}
	return r.DependencyTraits()
}

// DependencyTraits are the row's chips that link somewhere — the flagged
// dependencies this sample pulled in, each pointing at that dependency's own
// record.
//
// These survive an LLM rationale where ordinary chips do not, because they are
// not a restatement of it. A prose rationale explains *why* the sample is
// elevated; the chip is the only way to navigate to the dependency that made it
// so. Suppressing them alongside the rest hid that link on precisely the rows
// most likely to have one: a verdict inherited from a hostile dependency is
// exactly what an interpretation pass tends to write about.
//
//nolint:gocritic // value receiver required by html/template, as above
func (r feedRow) DependencyTraits() []feedTrait {
	var deps []feedTrait
	for _, t := range r.TopTraits {
		if t.Href != "" {
			deps = append(deps, t)
		}
	}
	return deps[:min(2, len(deps))]
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
	// SelectedPURL is the canonical full PURL (pkg:type/name@version) behind an
	// active purl: filter, echoed back into the search box; empty when unset.
	SelectedPURL string
	SearchQuery  string
	CSRFToken    string
	SelectedEco  string
	// PrevURL/NextURL are empty when there is no adjacent page.
	PrevURL    string
	NextURL    string
	Domains    []string
	Ecosystems []string
	Rows       []feedRow
	// Stats seeds the masthead's live "files indexed" counter with the latest
	// exact snapshot published by statsPollLoop, projected to request time (nil until
	// the first poll — the client's /_/stats poll fills it in either way). A
	// lock-free pointer read, so it never adds a query to the feed's hot path.
	Stats *indexStats
	// Pages holds the per-page links (empty when a single page covers every
	// row); Page is the 1-indexed current page over the cached snapshot.
	Pages []feedPageLink
	Page  int
	// WeeklyHostile is the count behind the Fallout nav pill's badge: hostile
	// catches in the fallout log's rolling window. Zero hides the badge.
	WeeklyHostile int
	Refresh       bool
	HasHopper     bool
	// ZeroState marks the unfiltered, unsearched first page — the view that
	// gets the "Latest analyses" framing instead of query results.
	ZeroState bool
	// FeedDegraded is set when hopper is connected but the feed query failed
	// (timeout, circuit breaker open, replica blip). The page still renders —
	// the feed section just shows a "temporarily unavailable" notice instead
	// of a 500. HasHopper stays true so the filter bar keeps working.
	FeedDegraded bool
	// UploadEnabled combines the package-level toggle with the shared backend
	// liveness state so the template can pick the real upload form vs. the
	// disabled placeholder without probing either backend per request.
	UploadEnabled bool
	// FeedsOnly restricts the feed to label='bad' samples (threat-intel +
	// curated open-source malware sources) — the rows that carry the
	// "✓ corroborated" mark. Toggled by the filter bar's checkbox (?feeds=1).
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
	// Bytes is the JSON-serialized size of this snapshot (the same encoding
	// the localfs cache persists), captured once at build time so the
	// per-request diagnostics can report payload size without re-marshaling
	// on a cache hit.
	Bytes int
	// Truncated reports that a windowed read stopped at its page cap with
	// window left unread, so a view rendering a period can say how much of it
	// this snapshot actually covers instead of claiming the whole period.
	Truncated bool
}

// feedDropdowns holds the ecosystem and domain filter options rendered on the
// feed. They are a global property of the corpus — identical for every filter
// combination — so a single cached copy (feedDropdownCache) backs every feed
// key instead of two DISTINCT scans on each snapshot rebuild.
type feedDropdowns struct {
	Ecosystems []string
	Domains    []string
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
	// Package/Version are hopper's registry attribution; Headline and SubID
	// derive from them at render time (feedRowsFromSnapshot).
	Package  string
	Version  string
	PURLBase string
	// RegistryTitle/Desc/Downloads mirror the provenance registry record's
	// marketplace title, capped short description, and install count (see
	// feedRow; Downloads sits below with the other numerics).
	RegistryTitle string
	Desc          string
	// Why/Conf are the LLM rationale and verdict confidence percentage
	// (blended when a rationale exists, ml-pass otherwise); TopTraits the
	// display-ready headline trait chips; Corroborated is hopper's
	// samples.corroborated flag (sightings ledger). See feedRow.
	Why string
	// LLMGrade is the LLM pass's own raw verdict; see feedRow.
	LLMGrade     string
	TopTraits    []feedTrait
	Conf         int
	Corroborated bool
	Downloads    int64
	Probability  float64
	SuspiciousT  float64
	HostileT     float64
	Threshold    float64 // v=5 only; zero for v=4 inputs
	Class        int     // v=5 only; mirrored from envelope for rendering
}

// cleaveReport is constructed from JSONL output (multiple lines).
type cleaveReport struct {
	Files []cleaveFile `json:"files"`
}

// cleaveFile represents a file entry in cleave compact output.
// Litmus injects "class" and "prob" into each files[] entry.
type cleaveFile struct {
	KV             map[string]json.RawMessage `json:"k,omitempty"`
	Parent         *int                       `json:"pid,omitempty"`
	Gradient       template.CSS               `json:"-"`
	Path           string                     `json:"path"`
	FileType       string                     `json:"type"`
	SHA256         string                     `json:"sha"`
	Classification string                     `json:"-"`
	Formula        string                     `json:"mol,omitempty"`
	// Rel is how this file relates to its pid: "fetched" (pulled over the
	// network from a reference in the parent), "registry", "unpacked", or empty
	// for an ordinary archive member. Via is the resolved source URL, set only
	// when Rel=="fetched". Role is "sidecar" for a metadata node (a registry or
	// provenance record about its parent), empty for ordinary content.
	Rel         string            `json:"rel,omitempty"`
	Via         string            `json:"via,omitempty"`
	Role        string            `json:"role,omitempty"`
	Facts       cleaveFacts       `json:"fact,omitzero"`
	Imports     []string          `json:"is,omitempty"`
	Exports     []symbolInfo      `json:"exports,omitempty"`
	Strings     []json.RawMessage `json:"ss,omitempty"`
	Findings    []finding         `json:"find,omitempty"`
	Sections    []sectionInfo     `json:"sections,omitempty"`
	Refs        []cleaveRef       `json:"refs,omitempty"`
	Metrics     json.RawMessage   `json:"ms,omitempty"`
	Ctx         []contextWindow   `json:"ctx,omitempty"`
	Probability float64           `json:"-"`
	Threshold   float64           `json:"-"`
	Size        int64             `json:"size"`
	Class       int               `json:"-"`
	ID          int               `json:"id"`
	Depth       int               `json:"dp"`
	Container   bool              `json:"-"`
}

// cleaveRef is one reference a file declares — what it points at and, when
// cleave resolved it to another file in the same report, that file's id. An
// external dependency carries a PURL/URL in To; an internal reference carries a
// relative path. TargetFile is the file→file edge the galaxy draws.
type cleaveRef struct {
	TargetFile *int   `json:"file,omitempty"`
	To         string `json:"to"`
	Kind       string `json:"kind"`
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

func (f *cleaveFacts) isEmpty() bool {
	return len(f.Metrics) == 0 && f.KV == nil && len(f.Strings) == 0 && len(f.Imports) == 0 && len(f.Exports) == 0 && len(f.Functions) == 0 && len(f.Sections) == 0
}

func (f *cleaveFacts) UnmarshalJSON(data []byte) error {
	var raw struct {
		Metrics     json.RawMessage            `json:"metrics,omitempty"` // v8
		OldMetrics  json.RawMessage            `json:"met,omitempty"`     // v7
		V4Metrics   json.RawMessage            `json:"m,omitempty"`       // v4
		KV          map[string]json.RawMessage `json:"val,omitempty"`
		OldKV       map[string]json.RawMessage `json:"v,omitempty"`
		Strings     []json.RawMessage          `json:"str,omitempty"`
		OldStrings  []json.RawMessage          `json:"s,omitempty"`
		Imports     []json.RawMessage          `json:"imp,omitempty"`
		OldImports  []json.RawMessage          `json:"i,omitempty"`
		Exports     []json.RawMessage          `json:"exp,omitempty"`
		OldExports  []json.RawMessage          `json:"x,omitempty"`
		Functions   []json.RawMessage          `json:"funcs,omitempty"` // v8
		OldFuncs    []json.RawMessage          `json:"fn,omitempty"`    // v7
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
	if len(f.Metrics) == 0 {
		f.Metrics = raw.V4Metrics
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
	if len(f.Functions) == 0 {
		f.Functions = raw.OldFuncs
	}
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
		Parent      *int                       `json:"pid"`
		Path        string                     `json:"path"`
		FileType    string                     `json:"type"`
		SHA256      string                     `json:"sha"`
		Formula     string                     `json:"mol,omitempty"`
		OldFormula  string                     `json:"f,omitempty"`
		Rel         string                     `json:"rel,omitempty"`
		Via         string                     `json:"via,omitempty"`
		Role        string                     `json:"role,omitempty"`
		Facts       cleaveFacts                `json:"facts,omitzero"` // v8
		OldFacts    cleaveFacts                `json:"fact,omitzero"`  // v7
		V4Facts     cleaveFacts                `json:"ff,omitzero"`    // v4
		Exports     []symbolInfo               `json:"exports,omitempty"`
		Findings    []finding                  `json:"traits,omitempty"` // v8
		OldFindings []finding                  `json:"find,omitempty"`   // v7
		V4Findings  []finding                  `json:"ts,omitempty"`     // v4
		Ctx         []contextWindow            `json:"ctx,omitempty"`
		Strings     []json.RawMessage          `json:"ss,omitempty"`
		Imports     []string                   `json:"is,omitempty"`
		Sections    []sectionInfo              `json:"sections,omitempty"`
		Metrics     json.RawMessage            `json:"ms,omitempty"`
		Size        int64                      `json:"size"`
		OldSize     int64                      `json:"sz"`
		ID          int                        `json:"id"`
		Depth       int                        `json:"depth"` // v8
		OldDepth    int                        `json:"dp"`    // v7
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	findings := raw.Findings
	if len(findings) == 0 {
		findings = raw.OldFindings
	}
	if len(findings) == 0 {
		findings = raw.V4Findings
	}
	facts := raw.Facts
	if facts.isEmpty() {
		facts = raw.OldFacts
	}
	if facts.isEmpty() {
		facts = raw.V4Facts
	}
	depth := raw.Depth
	if depth == 0 {
		depth = raw.OldDepth
	}
	*f = cleaveFile{
		KV:       raw.KV,
		Parent:   raw.Parent,
		Path:     raw.Path,
		FileType: raw.FileType,
		SHA256:   raw.SHA256,
		Formula:  raw.Formula,
		Rel:      raw.Rel,
		Via:      raw.Via,
		Role:     raw.Role,
		Facts:    facts,
		Exports:  raw.Exports,
		Findings: findings,
		Ctx:      raw.Ctx,
		Strings:  raw.Strings,
		Imports:  raw.Imports,
		Sections: raw.Sections,
		Metrics:  raw.Metrics,
		Size:     raw.Size,
		ID:       raw.ID,
		Depth:    depth,
	}
	if f.Formula == "" {
		f.Formula = raw.OldFormula
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

// contextWindow is one entry in a file's `ctx` array. The format is
// self-describing per-chunk, so prism reads both the current and the legacy
// shape — a store holds a mix of the two for as long as it takes to rescan.
//
// v8 (current): `ln` is always the byte offset of the chunk's first stored byte
// — for both text and binary, never a line number. A textual chunk additionally
// carries `line`/`col`, the 1-based source line and column of that byte, and may
// span several physical lines; binary units carry neither.
//
// v7 (legacy): one entry per source line — `ln` is the 1-based line number and
// `addr` the byte offset of the line's first byte; binary units have neither and
// `ln` is a byte offset. No `line`/`col`.
//
// The presence of `line` unambiguously marks a v8 textual chunk; `addr` without
// `line` marks a v7 source line; neither marks a binary unit. `b` holds the raw
// bytes Z85-encoded. Legacy (v6 and earlier): pre-rendered text in `t`, offset
// in `l`.
type contextWindow struct {
	Line   *int64 `json:"-"` // v8: source line of the first byte
	Col    *int64 `json:"-"` // v8: source column of the first byte
	Addr   *int64 `json:"-"` // v7: byte offset of a source line (ln is the line number)
	Text   string `json:"t"`
	Data   []byte `json:"-"`
	Offset int64  `json:"ln"`
}

func (w *contextWindow) UnmarshalJSON(data []byte) error {
	var raw struct {
		Line    *int64 `json:"line"`
		Col     *int64 `json:"col"`
		Addr    *int64 `json:"addr"`
		OldAddr *int64 `json:"a"`
		Text    string `json:"t"`
		Bytes   string `json:"b"`
		Offset  int64  `json:"ln"`
		OldOff  int64  `json:"l"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	w.Offset = raw.Offset
	if w.Offset == 0 {
		w.Offset = raw.OldOff
	}
	w.Line = raw.Line
	w.Col = raw.Col
	w.Addr = raw.Addr
	if w.Addr == nil {
		w.Addr = raw.OldAddr
	}
	w.Text = raw.Text
	if raw.Bytes != "" {
		decoded, err := z85Decode(raw.Bytes)
		if err != nil {
			return fmt.Errorf("ctx window z85: %w", err)
		}
		w.Data = decoded
	}
	return nil
}

// byteBase returns the absolute byte offset of the chunk's first stored byte,
// resolving the v7/v8 difference: a v8 chunk (or a binary unit) keeps its offset
// in `ln`, while a v7 source line keeps the line number in `ln` and the byte
// offset in `addr`.
func (w *contextWindow) byteBase() int64 {
	if w.Line == nil && w.Addr != nil {
		return *w.Addr
	}
	return w.Offset
}

// isTextChunk reports a v8 byte-addressed textual chunk (carrying line/col),
// which the renderer splits into physical rows.
func (w *contextWindow) isTextChunk() bool { return w.Line != nil }

// isSourceLine reports a v7 single-line source entry (`ln` is a line number).
func (w *contextWindow) isSourceLine() bool { return w.Line == nil && w.Addr != nil }

type finding struct {
	ID string `json:"id"`
	// Desc is the human-readable trait description.
	Desc string `json:"desc,omitempty"`
	// Spans holds byte-span evidence: each entry is [offset, length] in
	// the file's byte space. Intersect against ctx windows to highlight matches.
	Spans [][2]int64 `json:"spans,omitempty"`
	// Uses names the traits a composite rule required, as indices into this
	// file's own Findings slice. Empty for an atomic trait, and for anything
	// scanned before cleave began recording the relation. Indices are checked
	// against the slice before use: a stale or truncated report must draw
	// nothing rather than panic.
	Uses []int `json:"uses,omitempty"`
	// Locations is archive attribution: "archive:<member-path>" or
	// "<file-id>[:<offset>]" strings used by aggregateArchiveCategories to
	// route findings to the right extracted sub-file.
	Locations []string `json:"loc,omitempty"`
	// From lists the files this finding came from. A single entry means it was
	// inherited from that embedded member; multiple entries means a cross-file
	// composite. Empty when native to this file.
	From []compactSource `json:"from,omitempty"`
	Crit int             `json:"crit"`
	Conf float64         `json:"conf,omitempty"`
}

// compactSource is one member a cross-file composite drew from.
type compactSource struct {
	Line   *int64 `json:"line,omitempty"`
	Offset *int64 `json:"off,omitempty"`
	File   int    `json:"file"`
}

func (s *compactSource) UnmarshalJSON(data []byte) error {
	var raw struct {
		Line    *int64 `json:"line"`
		OldLine *int64 `json:"ln"`
		Offset  *int64 `json:"off"`
		OldOff  *int64 `json:"o"`
		File    int    `json:"file"`
		OldFile int    `json:"f"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	s.File = raw.File
	if s.File == 0 {
		s.File = raw.OldFile
	}
	s.Line = raw.Line
	if s.Line == nil {
		s.Line = raw.OldLine
	}
	s.Offset = raw.Offset
	if s.Offset == nil {
		s.Offset = raw.OldOff
	}
	return nil
}

func (f *finding) UnmarshalJSON(data []byte) error {
	var raw struct {
		Src       *int            `json:"src,omitempty"`
		OldDesc   string          `json:"d,omitempty"`
		Desc      string          `json:"desc,omitempty"`
		ID        string          `json:"id"`
		OldID     string          `json:"i"`
		Spans     [][2]int64      `json:"spans,omitempty"`
		Uses      []int           `json:"uses,omitempty"`
		Locations []string        `json:"loc,omitempty"`
		OldLocs   []string        `json:"el,omitempty"`
		From      []compactSource `json:"from,omitempty"`
		Srcs      []compactSource `json:"srcs,omitempty"`
		Crit      int             `json:"crit"`
		OldCrit   int             `json:"l"`
		Conf      float64         `json:"conf,omitempty"`
		OldConf   float64         `json:"c,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	f.From = raw.From
	if len(f.From) == 0 && len(raw.Srcs) > 0 {
		f.From = raw.Srcs
	}
	if len(f.From) == 0 && raw.Src != nil {
		f.From = []compactSource{{File: *raw.Src}}
	}
	f.Uses = raw.Uses
	f.ID = raw.ID
	if f.ID == "" {
		f.ID = raw.OldID
	}
	f.Desc = raw.Desc
	if f.Desc == "" {
		f.Desc = raw.OldDesc
	}
	f.Spans = raw.Spans
	f.Locations = raw.Locations
	if len(f.Locations) == 0 {
		f.Locations = raw.OldLocs
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
	initDependencyMetrics()

	// Parse command-line flags via the stdlib flag package. Single-dash and
	// double-dash forms are both accepted (flag package treats `--foo` as
	// `-foo`), with `-flag=value` and `-flag value` both supported.
	var noCache bool
	var dbDSN string
	var listenAddr string
	var port string
	cli := flag.NewFlagSet("prism", flag.ExitOnError)
	cli.BoolVar(&noCache, "no-cache", false, "disable persistent caching (in-memory only)")
	cli.BoolVar(&publicMode, "public", false, "public-deployment mode: isotope13 labs branding and Secure cookies")
	cli.BoolVar(&uploadEnabled, "uploads", uploadEnabled, "enable browser uploads via POST /upload (also reads PRISM_UPLOADS env, set to 1/true to enable)")
	cli.BoolVar(&noEscalateScan, "no-escalate-scan", noEscalateScan, "when someone waits on an unanalyzed sample, only promote it in hopper's queue instead of also analyzing it on the litmus server (also reads PRISM_NO_ESCALATE_SCAN env, set to 1/true to disable the local scan)")
	cli.StringVar(&dbDSN, "db", "", "hopper postgres DSN (overrides HOPPER_DSN / FALLOUT_DB env)")
	cli.StringVar(&listenAddr, "listen", os.Getenv("LISTEN_ADDR"), "HTTP listen address (overrides LISTEN_ADDR env; empty means all interfaces)")
	cli.StringVar(&port, "port", "", "HTTP listen port (overrides PORT env)")
	cli.StringVar(&hopperAPIAddr, "hopper-api-addr", hopperAPIAddr, "hopper API host:port")
	cli.StringVar(&litmusAddr, "litmus", litmusAddr, "litmus analysis server host:port (also reads LITMUS_ADDR env; empty disables, falling back to hopper-only analysis)")
	var rateLimit int
	var rateWindow time.Duration
	cli.IntVar(&rateLimit, "rate-limit", 20, "max requests per client IP per --rate-window before 429/challenge (0 disables; served freely up to this rate, only the excess is shed)")
	cli.DurationVar(&rateWindow, "rate-window", 5*time.Minute, "window over which --rate-limit applies, as a sustained token-bucket rate with a burst of --rate-limit")
	if err := cli.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	// Env-var fallback so the rc.d script can flip these without shipping a new
	// binary. The CLI flag wins if both are set.
	set := map[string]bool{}
	cli.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if !set["uploads"] {
		uploadEnabled = envBool("PRISM_UPLOADS", uploadEnabled)
	}
	if !set["no-escalate-scan"] {
		noEscalateScan = envBool("PRISM_NO_ESCALATE_SCAN", noEscalateScan)
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
	// Optional controls depend on live HTTP backends, but page renders must not
	// fan out into per-request probes. Check both servers once now, then refresh
	// their process-wide atomic status at most every 15 seconds.
	backendStatus = newBackendAvailabilityMonitor(hopperAPIAddr, litmusAddr, nil)
	backendStatus.refresh(ctx)
	go backendStatus.run(ctx)

	// Initialize fido caches. See doc.go for the cache discipline.
	if noCache {
		logger.Info("cache disabled via --no-cache flag, using null stores")
		cache = openNullCache[storedResult]("result cache")
		feedCache = openNullCache[cachedFeedSnapshot]("feed cache")
		feedDropdownCache = openNullCache[feedDropdowns]("feed dropdowns")
		reportCache = openNullCache[cachedReport]("report cache")
		parentArchiveCache = openNullCache[cachedParents]("parent-archive cache")
		membersCache = openNullCache[cachedMembers]("members cache")
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
		// feedDropdownCache holds the single global ecosystem/domain options
		// set. It's memory-only for the same reason as feedCache, and it needs
		// no persistence: one key, cheap to rebuild after a restart.
		feedDropdownCache = openNullCache[feedDropdowns]("feed dropdowns")
		reportCache = openLocalFSCache[cachedReport]("prism-report", cacheDir, "report cache")
		parentArchiveCache = openLocalFSCache[cachedParents]("prism-parents", cacheDir, "parent-archive cache")
		// Keyed by real sha256s, so the localfs tier's growth is bounded by the
		// sample set — persisting these survives restarts and keeps warmed
		// archive pages instant.
		membersCache = openLocalFSCache[cachedMembers]("prism-members", cacheDir, "members cache")
	}
	// feedStaleCache is always memory-only (like feedCache) — even under
	// --no-cache, the in-memory tier is what backs the degraded-mode fallback,
	// and it holds only last-known-good feed snapshots that are cheap to rebuild.
	feedStaleCache = openNullCache[cachedFeedSnapshot]("feed stale cache")

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
		"ecoColor":     ecosystemColor,
		"chromaCSS":    func() template.CSS { return chromaStylesheet },
		"commaInt":     commaInt,
		"formulaTiers": formulaTiers,
		"tierName":     tierName,
	}
	var tmplErr error
	uploadTemplate, tmplErr = template.New("upload.html").Funcs(funcs).ParseFS(templatesFS, "templates/base.html", "templates/upload.html")
	if tmplErr != nil {
		logger.Error("template loading failed", "error", tmplErr)
		os.Exit(1)
	}
	falloutTemplate, tmplErr = template.New("fallout.html").Funcs(funcs).ParseFS(templatesFS, "templates/base.html", "templates/fallout.html")
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
		db, err := hopper.Open(context.Background(), dbDSN, "prism")
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

	// Publish the live exact index-size snapshot for the masthead counter. Runs for
	// the life of ctx independent of the hopper connection — it retries on its
	// exact/rate schedules and starts succeeding once hopper connects — so it needs
	// no hookup to the connect/reconnect callbacks. This background poll is the
	// counter's entire database cost; the endpoint only ever reads its result.
	go statsPollLoop(ctx)

	mux := newMux()

	// Shed per-client request floods (aggressive crawlers, runaway scrapers)
	// before they reach the handlers or hopper-db. Traffic is served freely up
	// to the configured rate; only the excess gets 429 + Retry-After, which
	// well-behaved clients honor. nil when disabled (--rate-limit 0) — limit()
	// is then a pass-through. Keyed on the real client IP via clientIP.
	rl := newRateLimiter(rateLimit, rateWindow)
	if rl != nil {
		go rl.sweepIdle(ctx)
		logger.Info("rate limiting enabled", "limit", rateLimit, "window", rateWindow.String())
	}

	server := &http.Server{
		Addr:              net.JoinHostPort(listenAddr, port),
		Handler:           obs.Middleware(requestLogger(rl.limit(securityHeaders(mux)))),
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
		if feedStaleCache != nil {
			if err := feedStaleCache.Close(); err != nil {
				logger.Error("failed to close fido feed stale cache", "error", err)
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
		if membersCache != nil {
			if err := membersCache.Close(); err != nil {
				logger.Error("failed to close fido members cache", "error", err)
			}
		}

		// Flush OTel exporters last so the shutdown logs/spans go out.
		if err := obsShutdown(shutdownCtx); err != nil {
			logger.Warn("obs shutdown", "error", err)
		}

		close(done)
	}()

	logger.Info("server starting",
		"listen_addr", listenAddr,
		"port", port,
		"hopper_api_addr", hopperAPIAddr,
		"hopper_token", hopper.APIToken() != "",
	)
	// hopper authenticates every API route but its probes, so a missing
	// credential leaves /healthz green while uploads, downloads, escalations,
	// and result publishes all 401 — a failure that reads as "hopper is fine,
	// prism is broken" unless it is called out here.
	if hopper.APIToken() == "" {
		logger.Warn("no hopper API credential found; uploads, downloads, and escalations will be rejected",
			"looked_in", "$HOPPER_TOKEN, ~/.tok/hopper")
	}

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
	mux.HandleFunc("GET /favicon.ico", handleFavicon)
	mux.HandleFunc("GET /{$}", handleFallout)
	mux.HandleFunc("GET /stream", handleIndex)
	// /index was the stream's name until it got one that says what it is.
	// Bookmarks and external links keep working.
	mux.HandleFunc("GET /index", func(w http.ResponseWriter, r *http.Request) {
		// Rebuilt from a fixed path plus a re-encoded query, so nothing a
		// caller supplies can reach the path or the host.
		target := url.URL{Path: "/stream", RawQuery: r.URL.Query().Encode()}
		http.Redirect(w, r, target.String(), http.StatusMovedPermanently)
	})
	mux.HandleFunc("GET /fallout", handleFallout)
	mux.HandleFunc("GET /fallout.json", handleFalloutJSON)
	mux.HandleFunc("GET /api/fallout", handleFalloutJSON)
	mux.HandleFunc("GET /feed.atom", handleAtomFeed)
	mux.HandleFunc("POST /upload", handleUpload)
	mux.HandleFunc("GET /file/{sha256}", handleFile)
	mux.HandleFunc("GET /file/{sha256}/wait", handleFileWait)
	mux.HandleFunc("GET /file/{sha256}/status", handleFileStatus)
	mux.HandleFunc("POST /file/{sha256}/rescan", handleRescan)
	mux.HandleFunc("POST /file/{sha256}/rum", handleFileRUM)
	mux.HandleFunc("GET /file/{sha256}/members", handleFileMembers)
	mux.HandleFunc("GET /formats", handleFormats)
	mux.HandleFunc("GET /powered-by", handlePoweredBy)
	mux.HandleFunc("GET /help/query", handleHelpQuery)
	mux.HandleFunc("GET /_/challenge", handleChallenge)
	mux.HandleFunc("POST /_/challenge", handleChallenge)
	mux.HandleFunc("GET /_/health", handleHealth)
	mux.HandleFunc("GET /_/stats", handleStats)
	mux.Handle("GET /_/metrik", obs.MetricsHandler())
	registerPprof(mux)
	mux.HandleFunc("GET /{ecosystem}", handleEcosystemRedirect)
	mux.HandleFunc("GET /{ecosystem}/", handleEcosystem)
	return mux
}

// registerPprof mounts the runtime profiler under /_/pprof, gated to
// loopback and private-network clients. The endpoints expose full
// goroutine dumps and a CPU profiler that can pin a core, so they must
// never be reachable from the public internet through the tunnel — only
// from the host or LAN (e.g. an SSH-forwarded curl during an incident).
// The canonical hang diagnosis is `curl .../_/pprof/goroutine?debug=2`.
func registerPprof(mux *http.ServeMux) {
	mux.HandleFunc("GET /_/pprof/", localOnly(pprof.Index))
	mux.HandleFunc("GET /_/pprof/cmdline", localOnly(pprof.Cmdline))
	mux.HandleFunc("GET /_/pprof/profile", localOnly(pprof.Profile))
	mux.HandleFunc("GET /_/pprof/symbol", localOnly(pprof.Symbol))
	mux.HandleFunc("GET /_/pprof/trace", localOnly(pprof.Trace))
	// Named runtime profiles (goroutine, heap, allocs, block, mutex, …). A
	// more specific pattern above wins for the fixed endpoints; this wildcard
	// serves the rest. pprof.Index hard-codes the /debug/pprof/ prefix, so it
	// can't serve named profiles when mounted elsewhere — dispatch by name.
	mux.HandleFunc("GET /_/pprof/{name}", localOnly(func(w http.ResponseWriter, r *http.Request) {
		pprof.Handler(r.PathValue("name")).ServeHTTP(w, r)
	}))
}

// localOnly wraps h so it serves only requests from a loopback or private
// address, returning 404 (not 403) to anyone else so the endpoint's
// existence isn't advertised to the public internet.
func localOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := net.ParseIP(clientIP(r))
		if ip == nil || !ip.IsLoopback() && !ip.IsPrivate() {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}
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
		Timeout:   5 * time.Minute,
		Transport: backendTransport(),
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
		Timeout:   uploadIngestTimeout + time.Minute,
		Transport: backendTransport(),
	}

	csrfKey = loadCSRFKey()

	logger.Debug("configuration loaded",
		"HOPPER_API_ADDR", hopperAPIAddr,
		"LITMUS_ADDR", litmusAddr,
		"PORT", os.Getenv("PORT"),
	)
}

// backendTransport builds an HTTP transport tuned for prism's backends. Both
// the hopper and litmus clients talk to a single host each, so the default
// transport's MaxIdleConnsPerHost of 2 would force connection churn (a fresh
// TCP+TLS handshake and teardown) once more than two calls to a backend are in
// flight — exactly the case under a download burst or concurrent uploads.
// Cloning DefaultTransport preserves its proxy, dialer, and TLS defaults; we
// only widen the idle-connection pool so keep-alives are actually reused.
func backendTransport() *http.Transport {
	t := &http.Transport{}
	// DefaultTransport is always *http.Transport; clone it to keep its proxy,
	// dialer, and TLS settings when the assertion holds, else start from zero.
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		t = base.Clone()
	}
	t.MaxIdleConns = 100
	t.MaxIdleConnsPerHost = 64
	t.IdleConnTimeout = 90 * time.Second
	return t
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

// feedWindowPageSize / feedWindowPages bound a windowed read (see
// feedSamplesInWindow). The page size is hopper's own per-query ceiling, so a
// period costs as few round trips as it can; the page count puts a ceiling on
// the whole read — at the 2026 hostile rate a week is around eight pages, so
// sixteen leaves room for a doubling before a view has to admit it is showing
// less than the period it names.
const (
	feedWindowPageSize = 1000
	feedWindowPages    = 16
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
	// since / until bound the query to a half-open created_at window,
	// [since, until). The fallout log's calendar weeks are the only caller:
	// its page is a period rather than a page of rows, so it pages the whole
	// window in (see loadFeedRowsFromHopper) instead of letting feedLimit
	// decide how far back the page reaches. Zero means unbounded, which every
	// other view is.
	since time.Time
	until time.Time

	ecosystem   string
	domain      string
	criticality string
	formula     string
	// search is the free-text filter behind ?q=: case-insensitive filename
	// substring OR exact sha256 OR exact package name, applied as a hopper SQL
	// predicate (not an in-memory pass) so it spans the whole index rather than
	// the cached page. The exact package-name disjunct means a bare name typed
	// into the box (e.g. "xz-utils") resolves to the package even when the
	// filename embeds no such substring. (A full sha pasted into the box is
	// caught earlier and redirected to the file page; this equality is the
	// no-JS / belt-and-suspenders path.)
	search string
	// purlBase / purlVersion filter the feed to one package identity: an exact
	// match on the indexed purl_base column (version-less canonical PURL),
	// optionally pinned to one release. Both are pre-canonicalized by
	// normalizePURL so the same coordinate via ?purl=, the search box, or a
	// pasted URL resolves to one cache key and one indexed query.
	purlBase    string
	purlVersion string
	// claimName / claimSigner filter by identity claim through hopper's
	// asset_claims view: any claim — a registry's, or the analyzer's read of
	// the file's own version resource / signature — asserting this exact
	// name / signer. Claim hits are typically archive members (an exe inside
	// each installer that ships it), so these disable TopLevelOnly.
	claimName   string
	claimSigner string
	// feedsOnly toggles the "malware feeds" view: only label='bad'
	// samples (curated threat-intel / open-source malware sources) are
	// returned, and the table picks up a Feed column.
	feedsOnly bool
}

// feedCacheKey produces a deterministic cache key from the feed-query
// dimensions. Stable across reorderings (so swapping field order can't
// silently fragment the cache) and never empty. Version-prefixed so the
// next schema change can invalidate the whole on-disk set.
func feedCacheKey(a *feedQueryArgs) string {
	feeds := "0"
	if a.feedsOnly {
		feeds = "1"
	}
	return "feed-v12:eco=" + a.ecosystem + ":dom=" + a.domain +
		":crit=" + a.criticality + ":formula=" + a.formula + ":feeds=" + feeds +
		":q=" + a.search + ":purl=" + a.purlBase + ":pv=" + a.purlVersion +
		":cn=" + a.claimName + ":cs=" + a.claimSigner +
		":from=" + timeKey(a.since) + ":to=" + timeKey(a.until)
}

// timeKey renders a window bound for a cache key: a fixed RFC3339 instant in
// UTC, and the empty string for an unset bound so an unwindowed key keeps the
// shape it always had.
func timeKey(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// feedCacheTTLFor is how long a snapshot of this query stays cached. A closed
// window — a period that ended before now — can never gain a row, so re-asking
// hopper for it on the working TTL is pure waste; it is held for
// feedArchiveTTL instead. Everything else, the period still in progress
// included, keeps the working TTL.
func feedCacheTTLFor(a *feedQueryArgs) time.Duration {
	if !a.until.IsZero() && a.until.Before(time.Now()) {
		return feedArchiveTTL
	}
	return feedCacheTTL
}

// loadFeedSnapshot fetches a feed page, caching every query for feedCacheTTL.
// All concurrent requests for the same filter set share one hopper round-
// trip via fido's built-in singleflight. Pre-cached variants (default +
// criticality) stay hot via feedPrecacheLoop so high-traffic views never
// hit a cold loader on the request path. The returned queryDiag reports
// whether the data came from cache, how long the fetch took, the snapshot's
// age, and its row/byte counts.
func loadFeedSnapshot(ctx context.Context, a *feedQueryArgs, reqLogger *slog.Logger, bypass bool) (cachedFeedSnapshot, queryDiag, error) {
	feedPopular.record(a) // learn which views to keep hot
	start := time.Now()
	diag := queryDiag{Name: "index", Source: "postgres", Params: feedDiagParams(a)}
	var snapshot cachedFeedSnapshot
	var err error
	if feedCache == nil {
		snapshot, err = buildFeedSnapshot(ctx, a)
	} else {
		// A hard refresh drops the cached entry first so FetchTTL rebuilds it
		// live and repopulates the cache for the next visitor.
		if bypass {
			if delErr := feedCache.Delete(ctx, feedCacheKey(a)); delErr != nil {
				reqLogger.Debug("hard refresh: feed cache invalidation failed", "error", delErr)
			}
		}
		fromCache := true
		snapshot, err = feedCache.FetchTTL(ctx, feedCacheKey(a), feedCacheTTLFor(a), func(lctx context.Context) (cachedFeedSnapshot, error) {
			fromCache = false
			// Detach the shared rebuild from the caller's request context.
			// FetchTTL coalesces concurrent callers onto one loader, and lctx
			// is the *first* caller's request context — if that client
			// disconnects, cancelling lctx would abort the rebuild for every
			// waiter, the feed can never repopulate under load, and the cache
			// stays cold (the 2026-06-18 outage). WithoutCancel keeps trace
			// context and values but drops cancellation; a fresh deadline
			// still bounds a genuinely stuck rebuild.
			bctx, cancel := context.WithTimeout(context.WithoutCancel(lctx), feedRebuildTimeout)
			defer cancel()
			return buildFeedSnapshot(bctx, a)
		})
		if fromCache {
			diag.Source = "cache"
		}
	}
	if err != nil {
		// Live query failed (hopper-db timeout, circuit breaker open, replica
		// blip). Fall back to the last-known-good snapshot so the feed degrades
		// to slightly-stale rows instead of a 500. diag.Source="stale" tells the
		// caller to flag the view as degraded in the UI.
		if feedStaleCache != nil {
			if stale, found, gerr := feedStaleCache.Get(ctx, feedCacheKey(a)); gerr == nil && found {
				diag.Source = "stale"
				diag.Duration = time.Since(start).Round(time.Microsecond).String()
				diag.Age = time.Since(stale.GeneratedAt).Round(time.Second).String()
				diag.Rows = len(stale.Rows)
				diag.Bytes = stale.Bytes
				reqLogger.Warn("serving stale feed snapshot after live query failure",
					"error", err, "age", diag.Age, "rows", diag.Rows)
				return stale, diag, nil
			}
		}
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
func feedDiagParams(a *feedQueryArgs) string {
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
	if a.purlBase != "" {
		parts = append(parts, "purl="+diagSafe(a.purlBase))
		if a.purlVersion != "" {
			parts = append(parts, "purlver="+diagSafe(a.purlVersion))
		}
	}
	if a.claimName != "" {
		parts = append(parts, "name="+diagSafe(a.claimName))
	}
	if a.claimSigner != "" {
		parts = append(parts, "signer="+diagSafe(a.claimSigner))
	}
	if a.feedsOnly {
		parts = append(parts, "feeds=1")
	}
	if !a.since.IsZero() || !a.until.IsZero() {
		parts = append(parts, "window="+timeKey(a.since)+".."+timeKey(a.until))
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
func buildFeedSnapshot(ctx context.Context, a *feedQueryArgs) (cachedFeedSnapshot, error) {
	fetch, err := loadFeedRowsFromHopper(ctx, a)
	if err != nil {
		return cachedFeedSnapshot{}, err
	}
	snap := cachedFeedSnapshot{
		GeneratedAt: time.Now(),
		Rows:        cachedFeedSamplesFromRows(fetch.rows),
		Ecosystems:  fetch.ecosystems,
		Domains:     fetch.domains,
		Truncated:   fetch.truncated,
	}
	if encoded, err := json.Marshal(snap); err == nil {
		snap.Bytes = len(encoded)
	}
	// Remember every fresh snapshot as last-known-good so loadFeedSnapshot can
	// fall back to it when a later live query fails. Written under a detached
	// context — recording the fallback must not be cancelled with the request
	// that happened to trigger the build.
	if feedStaleCache != nil {
		if err := feedStaleCache.SetTTL(context.WithoutCancel(ctx), feedCacheKey(a), snap, feedStaleTTL); err != nil {
			logger.Debug("feed stale-cache store failed", "key", feedCacheKey(a), "error", err)
		}
	}
	return snap, nil
}

// feedDropdownOptions returns the ecosystem and domain filter options, cached
// globally across every feed key. The options don't depend on the query
// filters, so one cached copy backs every feed render; without this each
// uncached rebuild — one per distinct ?m=/?q= a crawler mints — would re-run
// two DISTINCT-over-the-corpus scans for an identical result. fido
// singleflights the loader, so a stampede of cold feed requests triggers a
// single refresh, and the loader runs on a detached context (as in
// loadFeedSnapshot) so one client disconnecting can't abort the shared rebuild.
func feedDropdownOptions(ctx context.Context) (feedDropdowns, error) {
	return feedDropdownCache.FetchTTL(ctx, "options", feedDropdownTTL, func(lctx context.Context) (feedDropdowns, error) {
		db := hopperDB.Load()
		if db == nil {
			return feedDropdowns{}, errors.New("hopper not connected")
		}
		qctx, cancel := context.WithTimeout(context.WithoutCancel(lctx), hopperQueryTimeout)
		defer cancel()
		ecosystems, err := db.FeedEcosystems(qctx, "", "", time.Now().Add(-feedEcosystemWindow))
		if err != nil {
			return feedDropdowns{}, err
		}
		domains, err := db.FeedDomains(qctx, "", "")
		if err != nil {
			return feedDropdowns{}, err
		}
		return feedDropdowns{Ecosystems: ecosystems, Domains: domains}, nil
	})
}

// feedFetch is one hopper feed read: the rows it produced, the filter options
// rendered beside them, and whether a windowed read gave up at its page cap
// before reaching the window's far edge — the one thing a caller cannot infer
// from the rows, and the difference between "a quiet Monday" and "more than
// this page can hold".
type feedFetch struct {
	rows       []feedRow
	ecosystems []string
	domains    []string
	truncated  bool
}

func loadFeedRowsFromHopper(ctx context.Context, args *feedQueryArgs) (feedFetch, error) {
	db := hopperDB.Load()
	if db == nil {
		return feedFetch{}, errors.New("hopper not connected")
	}
	// Gate the feed behind the shared hopper-db breaker so a degraded
	// hopper sheds these queries fast instead of every request queueing a
	// full rebuild (the 2026-06-18 outage). This is the same breaker that
	// guards the per-sample lookups in fetchFromHopper.
	if berr := dbBreaker.allow(); berr != nil {
		recordDep(ctx, "hopper-db", "feed", "rejected", time.Time{})
		return feedFetch{}, fmt.Errorf("hopper-db feed: %w", berr)
	}
	// Bound the DB-query phase independently of the caller: a slow hopper
	// round-trip must not pin a request goroutine (or precache tick), and a
	// timeout becomes a breaker failure that trips it for later callers.
	ctx, cancel := context.WithTimeout(ctx, hopperQueryTimeout)
	defer cancel()
	feedStart := time.Now()
	// fail records a feed-query fault on both the breaker and the metric.
	fail := func() {
		dbBreaker.failure()
		recordDep(ctx, "hopper-db", "feed", "error", feedStart)
	}
	// The ecosystem/domain filter options don't depend on the query filters,
	// so they come from the global cache and are reused across every feed key
	// rather than re-scanned on each rebuild.
	dropdowns, err := feedDropdownOptions(ctx)
	if err != nil {
		fail()
		return feedFetch{}, err
	}

	// Source="" spans every Source value (legacy "harvest" rows from before
	// the rename, new "forager" rows, manual "upload"s) so the result set
	// works across the transition.
	q := hopper.FeedQuery{
		OrderBy:     "created_at",
		Formula:     args.formula,
		Search:      args.search,
		PURLBase:    args.purlBase,
		PURLVersion: args.purlVersion,
		ClaimName:   args.claimName,
		ClaimSigner: args.claimSigner,
		// A claim filter searches the whole containment tree: the exe that
		// carries a signer's claim lives inside its installers, never at the
		// top level. Every other view keeps the top-level restriction.
		TopLevelOnly:  args.claimName == "" && args.claimSigner == "",
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
		// Corroborated is hopper's denormalized flag: at least one external
		// threat feed, scanner, blog, or advisory cited this sample's sha256 or
		// purl_base (the sightings ledger). It supersedes the old label='bad'
		// proxy — a strictly richer signal (ClamAV, Socket, Aikido, blogs, not
		// just forager's own feeds) and still a single-column predicate that
		// composes with hopper's tuned feed indexes.
		q.Corroborated = true
	}

	q.Since, q.Until = args.since, args.until
	samples, truncated, err := feedSamplesInWindow(ctx, db, &q)
	if err != nil {
		fail()
		return feedFetch{}, err
	}
	dbBreaker.success()
	recordDep(ctx, "hopper-db", "feed", "ok", feedStart)

	out := feedFetch{
		rows:       make([]feedRow, 0, len(samples)),
		ecosystems: dropdowns.Ecosystems,
		domains:    dropdowns.Domains,
		truncated:  truncated,
	}
	now := time.Now()
	for _, sample := range samples {
		// Build the row straight from the sample hopper already returned.
		// Every field the feed shows is derivable from it, so there is no need
		// to consult (and churn) the shared per-SHA result cache: doing so
		// added a disk round-trip per row and evicted genuinely-hot detail-page
		// entries from the shared in-memory tier under crawler load.
		res := storedResultFromHopperSample(sample)
		classification := res.Classification
		if classification == "" {
			continue
		}
		// Registry sidecars are the `*.registry.json` provenance snapshots
		// (cleave types them "registry") forager writes beside each package —
		// metadata *about* an artifact, not an artifact. hopper's feed query
		// excludes them (file_type <> 'registry'), so this is a fallback that
		// keeps the index clean when served by an older hopper predating that
		// filter, mirroring the criticality recheck below.
		if firstNonEmpty(res.FileType, sample.FileType) == "registry" {
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
		suspiciousT, hostileT, mlConf := sampleMLVerdict(sample)
		why, llmGrade, conf := llmWhy(sample.LLMResult)
		// Keep interpreted and uninterpreted rows consistent: a row without
		// an LLM rationale still shows a verdict-confidence chip, sourced
		// from the ml pass instead of the blend.
		if why == "" {
			conf = mlConf
		}
		out.rows = append(out.rows, feedRow{
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
			Package:        sample.Package,
			Version:        sample.Version,
			PURLBase:       res.PURLBase,
			RegistryTitle:  sample.RegistryTitle,
			Desc:           truncDesc(sample.RegistryDescription),
			Users:          formatCount(sample.RegistryDownloads),
			Downloads:      sample.RegistryDownloads,
			Why:            why,
			Conf:           conf,
			TopTraits:      parseTopTraits(sample.TopTraits),
			LLMGrade:       llmGrade,
			Corroborated:   sample.Corroborated,
			AnalyzedAt:     addedAt,
			AnalyzedDate:   feedDate(addedAt, now),
			TimeAgo:        timeAgo(now.Sub(addedAt)),
		})
	}

	return out, nil
}

// feedSamplesInWindow reads a feed query, paging when it carries a created_at
// window. An unwindowed query is one page: the row cap is the whole point of
// the index feed, which shows the newest rows and pages in memory. A windowed
// one is a period the caller means to see all of, so it walks the window down
// — each page asking for what is left below the oldest row it has seen —
// until the window empties, the page cap is reached, or a page adds nothing
// new. Ties on the boundary instant are why the next bound is inclusive of the
// last row (created_at has microsecond resolution) and why rows are deduped by
// sha256: re-reading one row beats losing the ones beside it.
func feedSamplesInWindow(ctx context.Context, db *hopper.DB, q *hopper.FeedQuery) ([]*hopper.Sample, bool, error) {
	if q.Since.IsZero() && q.Until.IsZero() {
		samples, err := db.FeedSamples(ctx, q)
		return samples, false, err
	}
	q.Limit = feedWindowPageSize
	var out []*hopper.Sample
	seen := make(map[string]bool, feedWindowPageSize)
	for range feedWindowPages {
		page, err := db.FeedSamples(ctx, q)
		if err != nil {
			return nil, false, err
		}
		added := 0
		for _, sample := range page {
			if seen[sample.SHA256] {
				continue
			}
			seen[sample.SHA256] = true
			out = append(out, sample)
			added++
		}
		if len(page) < q.Limit || added == 0 {
			return out, false, nil
		}
		q.Until = page[len(page)-1].CreatedAt.Add(time.Microsecond)
	}
	return out, true, nil
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
			Package:        sample.Package,
			Version:        sample.Version,
			PURLBase:       sample.PURLBase,
			RegistryTitle:  sample.RegistryTitle,
			Desc:           sample.Desc,
			Users:          formatCount(sample.Downloads),
			Downloads:      sample.Downloads,
			Why:            sample.Why,
			Conf:           sample.Conf,
			TopTraits:      sample.TopTraits,
			LLMGrade:       sample.LLMGrade,
			Corroborated:   sample.Corroborated,
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

// feedPrecacheVariants enumerates the baseline feed views the static tier
// sweeps: the unfiltered "any" view (the frontpage default), the criticality
// views (hostile is the Hot Particle's candidate pool), the feeds-only views,
// and each static ecosystem's default (hostile) view. The hot tier adds
// whatever pivots real traffic favors; everything else is cached on demand.
var feedPrecacheVariants = func() []feedQueryArgs {
	v := []feedQueryArgs{
		{criticality: "hostile"},
		{},
		{criticality: "suspicious"},
		{criticality: ">=1"},
		{criticality: "benign"},
		{feedsOnly: true, criticality: "hostile"},
		{feedsOnly: true},
	}
	for _, eco := range feedStaticPrecacheEcosystems {
		v = append(v, feedQueryArgs{ecosystem: eco, criticality: "hostile"})
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
		for i := range feedPrecacheVariants {
			v := &feedPrecacheVariants[i]
			if err := refreshFeedCacheEntry(ctx, v, feedStaticPrecacheInterval); err != nil {
				logger.Warn("feed static pre-cache refresh failed", "key", feedCacheKey(v), "error", err)
			}
		}
		// The fallout log's current week. It cannot live in the static list:
		// the week it names moves every Monday. Warming it here is what lets
		// the index page's badge read the count out of cache instead of
		// building a week of rows on the request path — and what keeps the
		// first visitor to the log off a cold loader.
		now := time.Now().UTC()
		current := falloutWeekOf(now, now).snapshotArgs()
		if err := refreshFeedCacheEntry(ctx, &current, feedStaticPrecacheInterval); err != nil {
			logger.Warn("fallout week pre-cache refresh failed", "key", feedCacheKey(&current), "error", err)
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
			hot := feedPopular.top(feedHotPrecacheCount)
			for i := range hot {
				v := &hot[i]
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
func refreshFeedCacheEntry(ctx context.Context, a *feedQueryArgs, maxAge time.Duration) error {
	key := feedCacheKey(a)
	if snapshot, found, err := feedCache.Get(ctx, key); err == nil && found {
		if time.Since(snapshot.GeneratedAt) <= maxAge {
			return nil
		}
	}
	snapshot, err := buildFeedSnapshot(ctx, a)
	if err != nil {
		return err
	}
	if err := feedCache.SetTTL(ctx, key, snapshot, feedCacheTTLFor(a)); err != nil {
		return err
	}
	logger.Debug("feed pre-cache refreshed", "key", key, "rows", len(snapshot.Rows))
	return nil
}

// feedPopularity tracks how often each structured feed pivot is requested, so
// the hot pre-cache tier can keep genuinely-popular ecosystem and severity views
// warm. Free-text searches and formula filters are excluded — their key space is
// unbounded and one-off, not worth pre-warming — as is the domain dimension, so
// a /npm/ visit with any domain filter still counts toward the plain /npm/ view.
type feedPopularity struct {
	counts map[feedQueryArgs]uint64
	mu     sync.Mutex
}

// feedPopularityCap bounds the tracked key set so cycling through distinct
// pivots can't grow it without bound; past the cap only already-seen keys keep
// counting. The real structured key space (ecosystems × criticalities × feeds)
// is well under this.
const feedPopularityCap = 512

var feedPopular = &feedPopularity{counts: make(map[feedQueryArgs]uint64)}

// record bumps the visit count for the structured form of a, ignoring free-text
// and domain dimensions. A no-op for search/formula queries.
func (p *feedPopularity) record(a *feedQueryArgs) {
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
		return feedCacheKey(&entries[i].args) < feedCacheKey(&entries[j].args)
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	out := make([]feedQueryArgs, len(entries))
	for i := range entries {
		out[i] = entries[i].args
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
			Ecosystem:      row.Ecosystem,
			Package:        row.Package,
			Version:        row.Version,
			PURLBase:       row.PURLBase,
			RegistryTitle:  row.RegistryTitle,
			Desc:           row.Desc,
			Downloads:      row.Downloads,
			Why:            row.Why,
			Conf:           row.Conf,
			TopTraits:      row.TopTraits,
			LLMGrade:       row.LLMGrade,
			Corroborated:   row.Corroborated,
			CreatedAt:      row.AnalyzedAt,
		})
	}
	return samples
}

// truncDesc caps a registry short description to one feed-row line, cutting
// on a rune boundary with an ellipsis. Applied before the snapshot is cached
// so oversized listings never inflate the stored rows.
func truncDesc(s string) string {
	const maxRunes = 140
	s = strings.TrimSpace(s)
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return strings.TrimSpace(string(runes[:maxRunes-1])) + "…"
}

// formatCount renders a positive count with thousands separators for the
// install-count chip ("412,033"); zero and negative values render as "" so
// the template omits the chip when the marketplace figure is unknown.
func formatCount(n int64) string {
	if n <= 0 {
		return ""
	}
	s := strconv.FormatInt(n, 10)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
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

// requestRescan re-queues a sample for analysis by asking hopper's HTTP API to
// clear its cached analysis fields, so the next worker poll picks it up as Tier
// 1 (unanalyzed) work. The write is routed through hopper-api rather than
// prism's own pool: prism reads from a replica, and funneling every write
// through hopper keeps the master authoritative — the same reason uploads and
// result publishes go over the API. hopper limits the action to top-level
// non-skipped samples and enforces the re-queue cooldown server-side.
//
// On success prism's per-sha caches are invalidated so a subsequent
// GET /file/<sha> rebuilds from the re-queued state instead of the stale view.
func requestRescan(ctx context.Context, sha string) error {
	if err := postRescanToHopper(ctx, sha); err != nil {
		return err
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
		del  func(context.Context, string) error
		name string
	}{
		{name: "result", del: cache.Delete},
		{name: "report", del: reportCache.Delete},
		{name: "parents", del: parentArchiveCache.Delete},
		{name: "members", del: membersCache.Delete},
	} {
		if err := c.del(ctx, sha); err != nil {
			logger.Debug("sample cache invalidation failed", "sha256", sha, "cache", c.name, "reason", reason, "error", err)
		}
	}
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

// classLabel is the inverse of classificationClass: the lowercase verdict name
// for a 0/1/2 severity class. Unknown classes render as "unknown".
func classLabel(class int) string {
	switch class {
	case 0:
		return "benign"
	case 1:
		return "suspicious"
	case 2:
		return "hostile"
	default:
		return "unknown"
	}
}

// verdictTip builds the hover text for the level percentage badge. The badge
// renders only for a non-benign level (non-nil, != -1), so an empty string is
// returned otherwise. When an LLM interpretation pass ran and moved the verdict
// off the raw ML class, the tip names the disagreement — e.g. "[L250] ML rated
// as hostile, LLM downgraded to suspicious". Otherwise it states the level:
// "[L250] 80% confident hostile (lower levels are stricter)".
func verdictTip(level *int, pct int, finalClass string, rawClass *int, llm llmInterpretation) string {
	if level == nil || *level == -1 {
		return ""
	}
	if llm.Grade != "" && rawClass != nil {
		if outClass, ok := classificationClass(llm.Outcome); ok && outClass != *rawClass {
			dir := "escalated"
			if outClass < *rawClass {
				dir = "downgraded"
			}
			return fmt.Sprintf("[L%d] ML rated as %s, LLM %s to %s",
				*level, classLabel(*rawClass), dir, llm.Outcome)
		}
	}
	label := finalClass
	if label == "" {
		label = classLabel(envelopeClass(level))
	}
	return fmt.Sprintf("[L%d] %d%% confident %s (lower levels are stricter)", *level, pct, label)
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

// sampleMLVerdict extracts the feed's render inputs from a sample's ml
// envelope: the suspicious/hostile band edges (standard defaults when the
// envelope is absent or predates per-envelope thresholds) and the ml verdict
// confidence percentage — the same "NN% confident" figure the detail page's
// litmus badge shows; zero for benign verdicts and unparseable envelopes.
func sampleMLVerdict(sample *hopper.Sample) (suspiciousT, hostileT float64, conf int) {
	suspiciousT, hostileT = 0.65, 0.887
	if sample == nil || len(sample.LitmusResult) == 0 {
		return suspiciousT, hostileT, 0
	}
	var mlResp litmusMlResponse
	if json.Unmarshal(sample.LitmusResult, &mlResp) != nil {
		return suspiciousT, hostileT, 0
	}
	if s, h := mlResp.suspiciousT(), mlResp.hostileT(); s > 0 && h > 0 {
		suspiciousT, hostileT = s, h
	}
	return suspiciousT, hostileT, mlResp.Confidence
}

// llmWhy extracts the one-sentence verdict rationale and the blended
// confidence (as a 0–100 percentage) from a sample's llm_result column — the
// bare `llm` envelope object. Both zero when no interpretation pass ran, when
// the pass failed (carries only `error`), or when the JSON doesn't parse; the
// feed row then renders without a rationale line, exactly as before.
func llmWhy(raw []byte) (why, grade string, conf int) {
	if len(raw) == 0 {
		return "", "", 0
	}
	var llm llmInterpretation
	if err := json.Unmarshal(raw, &llm); err != nil || llm.Interpretation == "" {
		return "", "", 0
	}
	return llm.Interpretation, llm.Grade, int(llm.Conf*100 + 0.5)
}

// feedTrait is one of a row's headline traits, ready for the chip the feed
// renders: the display text (last directory + leaf of the cleave trait path,
// "exfil.dns-tunnel" — or, for a dependency verdict, the phrase naming what
// the verdict is inherited from), the full detail for the tooltip, and the
// criticality class for the colored dot. Href, when set, links the chip to
// the dependency's own record.
type feedTrait struct {
	ID   string
	Full string
	Crit string
	Href string
}

// parseTopTraits decodes hopper's top_traits column (JSON []hopper.TopTrait)
// into display-ready chips, deduped by chip ID — named traits from the same
// rule file share a truncated label, and one chip per label is enough, while
// dependency chips naming different packages all survive. The column is
// crit-sorted, so the survivor is the highest-criticality entry. Empty or
// malformed input yields nil — the row simply renders without a traits line.
func parseTopTraits(raw string) []feedTrait {
	if raw == "" {
		return nil
	}
	var top []hopper.TopTrait
	if err := json.Unmarshal([]byte(raw), &top); err != nil {
		return nil
	}
	chips := make([]feedTrait, 0, len(top))
	for _, t := range top {
		if t.ID == "" {
			continue
		}
		chip := feedTrait{ID: traitChipID(t.ID), Full: t.ID, Crit: critIntToString(t.Crit)}
		if dep, ok := parseDepIdentity(t.Dep); ok {
			chip = dependencyChip(t.ID, dep, chip)
		}
		if slices.ContainsFunc(chips, func(c feedTrait) bool { return c.ID == chip.ID }) {
			continue
		}
		chips = append(chips, chip)
	}
	return chips
}

// depIdentity is the machine-readable identity scan pins on its synthetic
// fetch/dependency-verdict trait and hopper forwards opaquely: the reference
// locator (PURL or URL) the dependency was declared at, the fetched payload's
// sha256, and its sniffed file type.
type depIdentity struct {
	Locator string `json:"locator"`
	SHA     string `json:"sha"`
	Type    string `json:"type"`
}

// parseDepIdentity decodes a top trait's dep field. ok is false when it is
// absent (every ordinary trait, and dependency verdicts scanned before scan
// emitted the field) or malformed — the caller keeps the generic id chip.
func parseDepIdentity(raw json.RawMessage) (depIdentity, bool) {
	var dep depIdentity
	if len(raw) == 0 || json.Unmarshal(raw, &dep) != nil || dep.Locator == "" {
		return depIdentity{}, false
	}
	return dep, true
}

// dependencyChip specializes a fetch/dependency-verdict chip with the
// dependency's identity: the text names the inherited verdict and where it
// comes from ("depends on hostile npm: zaboodle v1.49", "references hostile
// pe: x.y.z/x.exe"), the tooltip carries the full locator, and the chip links
// to the dependency's own record.
func dependencyChip(traitID string, dep depIdentity, base feedTrait) feedTrait {
	if eco, name, version, ok := purlCoords(dep.Locator); ok {
		base.ID = "depends on " + base.Crit + " " + eco + ": " + name
		if version != "" {
			base.ID += " v" + version
		}
	} else {
		kind := dep.Type
		if kind == "" || kind == "unknown" {
			kind = "dependency"
		}
		base.ID = "references " + base.Crit + " " + kind + ": " + urlCoords(dep.Locator)
	}
	// Locators are attacker-authored manifest strings; the cap keeps a
	// pathological one from blowing up the chip row or the atom summary.
	// The tooltip and the linked record carry the whole thing.
	base.ID = truncateRunes(base.ID, 80)
	base.Full = traitID + " — " + dep.Locator
	if validSHA256(dep.SHA) {
		base.Href = "/file/" + dep.SHA
	}
	return base
}

// purlCoords splits a PURL locator into the display coordinates for a
// dependency chip: the ecosystem (purl type), the package name (namespace
// kept — "@types/node", "debian/curl" — since it is part of the identity),
// and the version, percent-decoded for display. ok is false for a locator
// that isn't a PURL (a raw URL reference).
func purlCoords(locator string) (eco, name, version string, ok bool) {
	rest, found := strings.CutPrefix(locator, "pkg:")
	if !found {
		return "", "", "", false
	}
	eco, path, found := strings.Cut(rest, "/")
	if !found || eco == "" {
		return "", "", "", false
	}
	path, _, _ = strings.Cut(path, "?") // qualifiers never display
	path = strings.Trim(path, "/")
	// The version separator is an @ after the last /; an npm scope's leading
	// @ sits before one, so it can't be mistaken for a version.
	if i := strings.LastIndexByte(path, '@'); i > strings.LastIndexByte(path, '/') && i > 0 {
		version = path[i+1:]
		path = path[:i]
	}
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}
	if decoded, err := url.PathUnescape(version); err == nil {
		version = decoded
	}
	if path == "" {
		return "", "", "", false
	}
	return eco, path, version, true
}

// urlCoords compacts a URL locator for chip display: host plus the final path
// segment ("x.y.z/x.exe"), or just the host when the path names nothing. A
// locator that doesn't parse as a URL displays raw.
func urlCoords(locator string) string {
	u, err := url.Parse(locator)
	if err != nil || u.Host == "" {
		return locator
	}
	if file := u.Path[strings.LastIndexByte(u.Path, '/')+1:]; file != "" {
		return u.Host + "/" + file
	}
	return u.Host
}

// truncateRunes caps s at n runes, marking the cut with an ellipsis.
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	return string(runes[:n-1]) + "…"
}

// traitChipID compacts a cleave trait path for a feed chip: the last two
// path segments ("objectives/exfil/dns-tunnel" → "exfil.dns-tunnel") —
// recognizable without the taxonomy root. A "::name" suffix (a named trait
// inside a multi-trait rule file) is dropped; the full ID stays in the chip's
// tooltip. (Distinct from traitDisplayID, which keeps every segment for the
// Traits tab.)
func traitChipID(id string) string {
	id, _, _ = strings.Cut(id, "::")
	parts := strings.Split(id, "/")
	if len(parts) < 2 {
		return id
	}
	return parts[len(parts)-2] + "/" + parts[len(parts)-1]
}

func storedResultFromHopperSample(sample *hopper.Sample) storedResult {
	// hopper owns the column↔envelope mapping ({ml,llm,raw}); use it so the
	// shape stays in lockstep with the splitter/joiner.
	rawLitmus := hopper.Envelope(sample)

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
		Filename:          firstNonEmpty(sample.Filename, filepath.Base(sample.Path)),
		RawLitmus:         string(rawLitmus),
		Classification:    classification,
		Formula:           sample.Formula,
		FileType:          sample.FileType,
		CachedAt:          cachedAt,
		CreatedAt:         sample.CreatedAt,
		AnalyzedAt:        analyzedAt,
		SourceURL:         sample.URL,
		SourceDomain:      sample.Domain,
		Ecosystem:         sample.Ecosystem,
		SizeBytes:         sample.SizeBytes,
		Source:            sample.Source,
		Feed:              sample.Feed,
		Package:           sample.Package,
		Version:           sample.Version,
		RegistryTitle:     sample.RegistryTitle,
		RegistryDesc:      sample.RegistryDescription,
		RegistryDownloads: sample.RegistryDownloads,
		PURLBase:          sample.PURLBase,
		Label:             sample.Label,
		LabelSource:       sample.LabelSource,
		TraitsVersion:     sample.TraitsVersion,
		CanonicalSHA256:   sample.CanonicalSHA256,
		UpdatedAt:         sample.UpdatedAt,
		FirstAnalyzedAt:   firstAnalyzedAt,
	}
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

// purlDisplayString converts an internal canonical PURL to the form shown in
// the UI. Hopper stores npm scope sigils escaped as %40 so they cannot be
// confused with the version separator; people should see the familiar
//
//	@scope	spelling instead. Keep this transformation limited to the npm path,
//
// so an encoded @ in a qualifier or another ecosystem is not rewritten.
func purlDisplayString(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return purl
	}
	typ, path, ok := strings.Cut(rest, "/")
	if !ok || !strings.EqualFold(typ, "npm") || len(path) < 3 || !strings.EqualFold(path[:3], "%40") {
		return purl
	}
	return "pkg:" + typ + "/@" + path[3:]
}

// purlDisplay renders the full versioned Package URL for the result page:
// hopper's version-less PURLBase with "@"+Version appended when a version is
// known, converted to the UI spelling by purlDisplayString. Empty when the
// sample has no PURLBase (uploads, ecosystems without a defined PURL type), so
// callers can hide the row.
func purlDisplay(res *storedResult) string {
	if res.PURLBase == "" || res.Version == "" {
		return purlDisplayString(res.PURLBase)
	}
	return purlDisplayString(res.PURLBase) + "@" + res.Version
}

// purlIndexURL is the version-index link behind the hero's Package row: the
// version-less canonical base as a rooted path (pkg:npm/lodash →
// /npm/lodash), the package hierarchy servePURL serves. A base carrying an
// identity qualifier (Open VSX's repository_url survives VersionlessPURL)
// keeps the ?purl= filter form instead — its "?" would otherwise start the
// path URL's query string and drop the qualifier on the round-trip. Empty
// in, empty out.
func purlIndexURL(base string) string {
	rest, ok := strings.CutPrefix(base, "pkg:")
	if !ok {
		return ""
	}
	if strings.ContainsAny(rest, "?#") {
		return "/?purl=" + url.QueryEscape(base)
	}
	return "/" + strings.TrimPrefix(purlDisplayString(base), "pkg:")
}

// Citation is one external source that has cited this sample, shown as a chip
// in the detail page's "also detected by" row. Source is the public display
// name ("osv", "bleepingcomputer"); URL links to the advisory/report when the
// source gave one; Note is the source's own tag.
type Citation struct {
	Source string
	URL    string
	Note   string
}

// citationDisplayName maps a sightings-ledger source to the name we show
// publicly, or "" for sources we only count. Open databases (osv,
// opensourcemalware) and blogs (cyclotron:<blog>, shown as the bare blog
// name) are named; commercial vendors and scanners (socket, aikido, clamav,
// ...) are not name-dropped.
func citationDisplayName(source string) string {
	if blog, ok := strings.CutPrefix(source, "cyclotron:"); ok {
		return blog
	}
	switch source {
	case "osv", "osm", "opensourcemalware":
		return source
	}
	return ""
}

// detectedBy reads hopper's sightings ledger for this sample and returns one
// chip per distinct nameable source that cited it (by sha256 or version-less
// purl_base), plus a count chip covering the sources we leave unnamed.
// Best-effort: a nil DB or a query error yields no chips (the row hides) rather
// than failing the page. One small indexed read per detail render, so a citation
// that arrived since the last analysis shows without waiting for a rescan.
func detectedBy(ctx context.Context, sha, purlBase string) (named []Citation, more string) {
	db := hopperDB.Load()
	if db == nil {
		return nil, ""
	}
	subjects := []string{sha}
	if purlBase != "" {
		subjects = append(subjects, purlBase)
	}
	m, err := db.SightingsFor(ctx, subjects)
	if err != nil {
		logger.Warn("sightings lookup failed", "sha256", sha, "error", err)
		return nil, ""
	}
	seen := make(map[string]bool)
	unnamed := 0
	for _, subj := range subjects {
		sightings := m[subj]
		for i := range sightings {
			s := &sightings[i]
			if seen[s.Source] {
				continue
			}
			seen[s.Source] = true
			name := citationDisplayName(s.Source)
			if name == "" {
				unnamed++
				continue
			}
			named = append(named, Citation{Source: name, URL: s.URL, Note: s.Note})
		}
	}
	sort.Slice(named, func(i, j int) bool { return named[i].Source < named[j].Source })
	switch {
	case unnamed == 0:
	case len(named) > 0:
		more = fmt.Sprintf("+%d more", unnamed)
	case unnamed == 1:
		more = "1 source"
	default:
		more = fmt.Sprintf("%d sources", unnamed)
	}
	return named, more
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
			{Label: "PURL", Value: purlDisplay(res), Mono: true},
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
func composeSearchQuery(crit, purl, eco, domain, formula, q string) string {
	var parts []string
	if crit != "" {
		parts = append(parts, "crit:"+crit)
	}
	if purl != "" {
		parts = append(parts, "purl:"+purl)
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

// purlFromSearchQuery extracts a package coordinate from a search-box value that
// is purely a PURL — either the explicit `purl:<coord>` token or a bare
// `pkg:<type>/...` string. It is the no-JS / pasted-link mirror of upload.js's
// tokenizer: with JS the coordinate already arrives as the discrete ?purl=
// param. Bare detection is anchored on the pkg: scheme so a filename never gets
// mistaken for a PURL, and a value carrying whitespace is more than one token
// (not a bare PURL), so it is left to the free-text path. The returned string is
// not yet canonical — normalizePURL does that.
// claimTokenFromSearchQuery sniffs a leading `name:<n>` or `signer:<s>` token
// from the free-text box — the no-JS twin of upload.js's tokenizer, mirroring
// purlFromSearchQuery. Unlike a PURL, names and signers legitimately contain
// spaces ("Igor Pavlov"), so the token consumes the rest of the query.
func claimTokenFromSearchQuery(q string) (key, value string, ok bool) {
	q = strings.TrimSpace(q)
	for _, k := range []string{"name", "signer"} {
		if len(q) > len(k)+1 && strings.EqualFold(q[:len(k)+1], k+":") {
			if rest := strings.TrimSpace(q[len(k)+1:]); rest != "" {
				return k, rest, true
			}
		}
	}
	return "", "", false
}

func purlFromSearchQuery(q string) (string, bool) {
	q = strings.TrimSpace(q)
	if q == "" || strings.ContainsAny(q, " \t\r\n") {
		return "", false
	}
	// Explicit token: `purl:<coord>`, with or without the pkg: scheme (which
	// normalizePURL prepends). Case-insensitive key, matching upload.js.
	if len(q) >= 5 && strings.EqualFold(q[:5], "purl:") {
		if rest := strings.TrimSpace(q[5:]); rest != "" {
			return rest, true
		}
		return "", false
	}
	// Bare PURL: the pkg: scheme is the unambiguous marker.
	if len(q) >= 4 && strings.EqualFold(q[:4], "pkg:") {
		return q, true
	}
	return "", false
}

// normalizePURL canonicalizes a user-entered package coordinate into the exact
// values the hopper feed filter matches: the version-less canonical PURL (the
// indexed samples.purl_base) and, when the coordinate carries one, the release
// version (samples.version). A missing `pkg:` scheme is prepended so both
// "npm/lodash@1.2.3" (from the purl: token) and "pkg:npm/lodash@1.2.3" (a bare
// paste) fold to one identity, and pkgparse.CanonicalizePURL applies the same
// type/case folding forager used when it wrote purl_base — so old and new
// spellings compare equal. canonical is the full round-trip form for the search
// box; a coordinate that isn't a real PURL yields all-empty (no filter), the
// same drop-to-nothing normalizeDomain uses so a dead filter can't fragment the
// cache.
func normalizePURL(raw string) (canonical, base, version string) {
	s := sanitizeFilter(raw)
	if s == "" {
		return "", "", ""
	}
	if len(s) < 4 || !strings.EqualFold(s[:4], "pkg:") {
		s = "pkg:" + s
	}
	canonical = pkgparse.CanonicalizePURL(s)
	base = pkgparse.VersionlessPURL(canonical)
	// A well-formed PURL is pkg:<type>/<...>/<name>; reject anything that
	// canonicalization couldn't shape into that (it returns degenerate input
	// unchanged) rather than filtering on a value that can never match.
	rest, ok := strings.CutPrefix(base, "pkg:")
	if !ok {
		return "", "", ""
	}
	typ, path, ok := strings.Cut(rest, "/")
	if !ok || typ == "" {
		return "", "", ""
	}
	if name, _, _ := strings.Cut(path, "?"); name == "" {
		return "", "", ""
	}
	// The version is the @-tail before any qualifiers (mirrors VersionlessPURL's
	// split); npm-scoped '@' in names is percent-encoded in canonical form, so a
	// literal '@' here is always the version separator.
	body, _, _ := strings.Cut(canonical, "?")
	if i := strings.LastIndexByte(body, '@'); i > 0 {
		version = body[i+1:]
	}
	return canonical, base, version
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
//
// Terms shorter than three characters are dropped to "". The hopper Search
// predicate's filename disjunct is `filename ILIKE '%term%'`, served by
// pg_trgm's GIN index whose operator class only indexes trigrams — a one- or
// two-character substring can't use it and forces a full scan of the feed
// working set, while every distinct short term is also its own cache-miss key.
// A 1–2 char term is too coarse to filter usefully, so it falls back to the
// unfiltered feed. (The exact package-name and sha256 disjuncts are indexed
// equalities that could serve a short term, but no real package name or hash is
// that short.) A pasted SHA is handled earlier by shaFromSearchQuery, so no
// exact lookup is lost.
func normalizeSearch(s string) string {
	q := strings.ToLower(strings.Join(strings.Fields(sanitizeFilter(s)), " "))
	if utf8.RuneCountInString(q) < 3 {
		return ""
	}
	return q
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
	renderFeed(w, r, "", "")
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
	// A path that continues past the ecosystem is a package coordinate, not a
	// feed: /npm/lodash@4.17.21 reads as pkg:npm/lodash@4.17.21 and is the
	// record's URL, extending the hierarchy /npm/ (feed) → /npm/lodash (every
	// release) → /npm/lodash@4.17.21 (one release).
	if coordinate := strings.Trim(r.URL.Path, "/"); strings.Contains(coordinate, "/") {
		servePURL(w, r, coordinate)
		return
	}
	renderFeed(w, r, eco, "")
}

// servePURL resolves a package coordinate from the URL path. A versioned
// coordinate that pins exactly one sample lands directly on its /file page;
// everything else — a version-less package, several matches, an unknown
// package, hopper down — renders the feed filtered to that identity in
// place, so /npm/lodash is the package's version index the way /npm/ is the
// ecosystem's. A version-less coordinate always gets the index (never the
// sole-sample shortcut): its URL promises every release, even when only one
// exists yet. The redirect targets are a constant and a DB-sourced hex sha,
// so no user-controlled byte ever starts the Location header (the
// open-redirect trick validEcosystem defeats).
func servePURL(w http.ResponseWriter, r *http.Request, coordinate string) {
	canonical, base, version := normalizePURL(coordinate)
	if base == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if version != "" {
		if sha := soleSampleByPURL(r.Context(), base, version); sha != "" {
			//nolint:gosec // G710: sha is a DB-sourced hex digest behind a literal "/file/" prefix, so the target stays same-origin.
			http.Redirect(w, r, "/file/"+sha, http.StatusFound)
			return
		}
	}
	renderFeed(w, r, "", canonical)
}

// soleSampleByPURL returns the sha256 of the one sample matching the
// canonical purl base (and version, when set), or "" when the coordinate
// matches zero or several samples — ambiguity the purl-filtered feed
// resolves better than a guess. The query is an indexed exact match
// (samples.purl_base), gated by the shared hopper-db breaker like every
// other per-request lookup. No litmus requirement: a still-unanalyzed
// sample should resolve to its record page, which shows analysis progress.
func soleSampleByPURL(ctx context.Context, base, version string) string {
	db := hopperDB.Load()
	if db == nil {
		return ""
	}
	if err := dbBreaker.allow(); err != nil {
		recordDep(ctx, "hopper-db", "purl", "rejected", time.Time{})
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, hopperQueryTimeout)
	defer cancel()
	start := time.Now()
	samples, err := db.FeedSamples(ctx, &hopper.FeedQuery{
		PURLBase:      base,
		PURLVersion:   version,
		OrderBy:       "created_at",
		TopLevelOnly:  true,
		Limit:         2,
		CriticalLevel: CriticalLevel,
	})
	if err != nil {
		dbBreaker.failure()
		recordDep(ctx, "hopper-db", "purl", "error", start)
		logger.Warn("purl lookup failed", "purl", base, "version", version, "error", err)
		return ""
	}
	dbBreaker.success()
	recordDep(ctx, "hopper-db", "purl", "ok", start)
	if len(samples) == 1 {
		return samples[0].SHA256
	}
	return ""
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
	//nolint:gosec // G710: validEcosystem rejects slash, backslash and control bytes, so "/"+eco+"/" cannot become "//host".
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
// change between pages — no extra hopper query.
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

func renderFeed(w http.ResponseWriter, r *http.Request, ecosystem, purl string) {
	// Server-side fallback for ?q=sha256:<hex> / ?q=<64-hex> deep links —
	// JS already short-circuits these before sending, but a pasted URL or
	// a no-JS client still gets the redirect. Run it on the raw value;
	// shaFromSearchQuery trims and lowercases internally.
	if sha, ok := shaFromSearchQuery(r.URL.Query().Get("q")); ok {
		//nolint:gosec // G710: shaFromSearchQuery returns only validSHA256 hex, behind a literal "/file/" prefix.
		http.Redirect(w, r, "/file/"+sha, http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Link", fontPreloadLink)
	// The feed's default view is unfiltered ("Any" — every analyzed verdict).
	// With no explicit ?criticality= key crit is "", which loadFeedRowsFromHopper
	// treats as "require litmus, no class filter". The dropdown's Any option
	// submits criticality=any, which normalizes to "" too, so the default and the
	// explicit Any view render identically. The search box mirrors only explicit
	// choices (critToken), so the default view keeps an empty box and round-trips
	// back to itself.
	crit, critToken := "", ""
	if r.URL.Query().Has("criticality") {
		crit = normalizeCriticality(r.URL.Query().Get("criticality"))
		critToken = firstNonEmpty(crit, "any")
	}
	// PURL filter: a package path (/npm/lodash) passes the coordinate in
	// directly and wins. Otherwise JS sends it as ?purl=; a no-JS client or
	// pasted link carries it in the free-text box, so fall back to sniffing
	// ?q= for a bare pkg: / purl: token. A coordinate consumed from ?q= must
	// not also run as a filename search, so its raw value is dropped before
	// normalizeSearch.
	rawPURL, searchRaw := firstNonEmpty(purl, r.URL.Query().Get("purl")), r.URL.Query().Get("q")
	if rawPURL == "" {
		if p, ok := purlFromSearchQuery(searchRaw); ok {
			rawPURL, searchRaw = p, ""
		}
	}
	purlCanonical, purlBase, purlVersion := normalizePURL(rawPURL)
	// Identity-claim filter: JS sends ?name= / ?signer=; a no-JS client types
	// `name:` / `signer:` into the box. Like the purl sniff above, a consumed
	// token must not also run as a filename search.
	claimName := sanitizeFilter(r.URL.Query().Get("name"))
	claimSigner := sanitizeFilter(r.URL.Query().Get("signer"))
	if claimName == "" && claimSigner == "" {
		if key, value, ok := claimTokenFromSearchQuery(searchRaw); ok {
			if key == "name" {
				claimName = value
			} else {
				claimSigner = value
			}
			searchRaw = ""
		}
	}
	data := feedPageData{
		CSRFToken:       csrfToken(r, "upload"),
		WeeklyHostile:   weeklyHostileCount(r.Context(), viewerLocation(r)),
		UploadEnabled:   uploadEnabled && uploadBackendsAvailable(),
		FeedsOnly:       parseBoolQuery(r.URL.Query().Get("feeds")),
		Nonce:           nonceFor(r),
		StyleNonce:      styleNonceFor(r),
		BuildCommit:     buildCommit,
		Refresh:         r.URL.Query().Get("refresh") == "1",
		SelectedEco:     ecosystem,
		SelectedDomain:  normalizeDomain(r.URL.Query().Get("domain")),
		SelectedCrit:    crit,
		SelectedFormula: formulaFromQuery(r.URL.Query()),
		SelectedQ:       normalizeSearch(searchRaw),
		SelectedPURL:    purlCanonical,
		Title:           "Stream",
		HasHopper:       hopperDB.Load() != nil,
	}
	data.SearchQuery = composeSearchQuery(
		critToken, purlDisplayString(data.SelectedPURL), data.SelectedEco, data.SelectedDomain,
		data.SelectedFormula, data.SelectedQ,
	)
	if ecosystem != "" {
		data.Title = ecosystem + " · Stream"
	}
	// A package path (/npm/lodash) titles its tab by the coordinate; the
	// ?purl= query form stays a plain search, matching the box it came from.
	if purl != "" && purlCanonical != "" {
		data.Title = purlDisplayString(purlCanonical)
	}

	var diags []queryDiag
	if hopperDB.Load() != nil {
		snapshot, diag, err := loadFeedSnapshot(
			r.Context(),
			&feedQueryArgs{
				ecosystem:   data.SelectedEco,
				domain:      data.SelectedDomain,
				criticality: data.SelectedCrit,
				formula:     data.SelectedFormula,
				search:      data.SelectedQ,
				purlBase:    purlBase,
				purlVersion: purlVersion,
				claimName:   claimName,
				claimSigner: claimSigner,
				feedsOnly:   data.FeedsOnly,
			},
			logger,
			isHardRefresh(r),
		)
		if err != nil {
			// The live query failed and no last-known-good snapshot was
			// available to fall back on. This must not take down the whole
			// index page — the upload form, filters, and footer still work
			// without rows. Degrade gracefully: flag the feed section and fall
			// through to render the page instead of serving a 500.
			logger.Warn("failed to load feed rows", "error", err, "ecosystem", ecosystem)
			data.FeedDegraded = true
		} else {
			diags = append(diags, diag)
			// loadFeedSnapshot serves a stale last-known-good snapshot when the
			// live query fails; diag.Source=="stale" marks that so the template
			// can flag the rows as slightly out of date.
			data.FeedDegraded = diag.Source == "stale"
			data.Rows = feedRowsFromSnapshot(snapshot)
			data.Domains = snapshot.Domains
			data.Ecosystems = snapshot.Ecosystems
			data.ZeroState = data.SelectedEco == "" && data.SelectedDomain == "" &&
				data.SelectedFormula == "" && data.SelectedQ == "" &&
				data.SelectedPURL == "" && data.SelectedCrit == "" &&
				!data.FeedsOnly && r.URL.Query().Get("page") == ""
			paginateFeed(&data, r)
		}
	}
	// Seed the live counter with the latest exact published snapshot, projected to
	// this request's clock — a lock-free pointer read, no query on the feed
	// path. When cold (before the first poll), the template omits the initial
	// value and the client's /_/stats poll populates it.
	if s, ok := cachedIndexStats(); ok {
		live := projectIndexStats(s, time.Now().UTC())
		data.Stats = &live
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
		if _, err := fmt.Fprintf(w, "\n<!-- %s source:%s duration:%s age:%s params:%s rows=%d bytes=%d -->",
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

	ctx := r.Context()
	lookupStart := time.Now()
	lctx, lookupSpan := obs.Span(ctx, "prism.detail.lookup")
	cacheHit, res, err := lookupResult(lctx, sha, reqLogger)
	lookupSpan.End()
	lookupDur := time.Since(lookupStart)
	if err != nil {
		if pend, ok := errors.AsType[*pendingAnalysisError](err); ok {
			reqLogger.Info("rendering pending state", "filename", pend.Filename)
			renderPending(w, r, sha, pend.Filename)
			return
		}
		// Ingestion ran and gave up. Say so plainly: a 404 here would tell the
		// user to re-upload, which cannot help until the backends recover.
		if failed, ok := errors.AsType[*uploadFailedError](err); ok {
			reqLogger.Warn("rendering upload-failure state", "filename", failed.Filename)
			renderError(w, r, http.StatusServiceUnavailable, errorData{
				Icon:    "⚠",
				Title:   "Analysis unavailable",
				Message: "We received this file but couldn't analyze it — the analysis backends were unreachable. This is a problem on our side; re-uploading won't help until it's resolved.",
			})
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
	prepStart := time.Now()
	data := prepareResultData(res.Filename, sha, &res)
	data.DetectedBy, data.MoreSources = detectedBy(ctx, sha, res.PURLBase)
	prepDur := time.Since(prepStart)
	data.Nonce = nonceFor(r)
	data.StyleNonce = styleNonceFor(r)
	data.BuildCommit = buildCommit
	data.CSRFToken = csrfToken(r, "rescan")
	data.DownloadToken = csrfToken(r, "download")
	data.DownloadEnabled = hopperAPIAvailable()
	// A compacted-archive envelope carries member stubs but no member bodies;
	// the browser hydrates the Content + galaxy from /file/{sha}/members after
	// first paint.
	data.DeferredMembers = membersDeferred(res.RawLitmus)
	if data.DeferredMembers {
		// Warming means this is usually already built by the time anyone asks.
		// When it is, inline it: a second round trip the browser cannot even
		// start until the HTML has parsed costs more than the bytes do.
		if cached, ok, cerr := membersCache.Get(ctx, sha); cerr == nil && ok && cached.HasContent {
			data.MembersHTML = template.HTML(cached.ContentHTML)  //nolint:gosec // rendered by our own templates
			data.MembersTraits = template.HTML(cached.TraitsHTML) //nolint:gosec // rendered by our own templates
			data.DeferredMembers = false
		} else {
			warmMembers(ctx, sha, &res)
		}
	}
	var reportDur, parentsDur time.Duration
	if hopperDB.Load() != nil {
		reportStart := time.Now()
		if cached, ok := latestReport(ctx, sha, reqLogger); ok {
			data.ReportContent = cached.Content
			data.ReportProvider = cached.Provider
			if !cached.CreatedAt.IsZero() {
				data.ReportCreated = cached.CreatedAt.Format("2 Jan 2006 15:04 UTC")
			}
		}
		reportDur = time.Since(reportStart)
		// Parent archives: only meaningful on a standalone child view, not
		// when the user is already looking at the archive itself. Contained
		// members and mere references render as separate panels.
		if !data.IsArchive {
			parentsStart := time.Now()
			backlinks := lookupParentArchives(ctx, sha, reqLogger)
			for i := range backlinks {
				if backlinks[i].containsChild() {
					data.Parents = append(data.Parents, backlinks[i])
				} else {
					data.Referrers = append(data.Referrers, backlinks[i])
				}
			}
			parentsDur = time.Since(parentsStart)
		}
	}
	// For a file extracted from an OS image, name the source image in the headline
	// — "/bin/ls from netbsd 10.1 (amd64)" — so a thousand "ls" binaries don't all
	// read the same. Sourced from the already-fetched found-in parent, so no query.
	if hl, ok := imageMemberHeadline(data.Parents); ok {
		data.Headline = hl
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
	w.Header().Set("Link", fontPreloadLink)
	// template_ms below includes the streamed write to the client, so a slow
	// client (not a slow server) inflates it — read it alongside the client
	// RUM beacon (handleFileRUM), which times the browser side directly.
	tmplStart := time.Now()
	if err := resultTemplate.Execute(w, data); err != nil {
		reqLogger.Error("template execution failed",
			"template", "result",
			"error", err,
		)
	}
	tmplDur := time.Since(tmplStart)

	// Always-on phase breakdown of the whole detail render. Emitted for every
	// request (not just sampled traces) so a slow page is never invisible, and
	// escalated to WARN past the slow threshold. molecule_bytes is the payload
	// the browser must parse and lay out — the server-side proxy for client
	// render cost.
	totalDur := time.Since(requestStart)
	level := slog.LevelInfo
	if totalDur >= slowDetailThreshold {
		level = slog.LevelWarn
	}
	reqLogger.Log(ctx, level, "detail render timing",
		"cache_hit", cacheHit,
		"is_archive", data.IsArchive,
		"lookup_ms", lookupDur.Milliseconds(),
		"prepare_ms", prepDur.Milliseconds(),
		"report_ms", reportDur.Milliseconds(),
		"parents_ms", parentsDur.Milliseconds(),
		"template_ms", tmplDur.Milliseconds(),
		"total_ms", totalDur.Milliseconds(),
	)
}

// clientTiming is the render-timing beacon molecule.js posts after the detail
// page's first paint. Values are milliseconds since navigation start except
// MoleculeBuildMs (the Three.js scene-graph construction); Atoms is the
// molecule's node count, the dominant driver of browser render cost. Every
// field is clamped on ingest so a malformed or hostile beacon cannot skew the
// histogram.
type clientTiming struct {
	TTFBMs          float64 `json:"ttfb_ms"`
	DOMContentMs    float64 `json:"dom_content_ms"`
	MoleculeBuildMs float64 `json:"molecule_build_ms"`
	FirstRenderMs   float64 `json:"first_render_ms"`
	Atoms           int     `json:"atoms"`
}

// handleFileRUM ingests the browser render-timing beacon for a detail page,
// recording the client-render histogram plus a structured log correlated by
// sha. It performs no privileged action and mutates no state — it only clamps
// and records bounded telemetry — so it needs no CSRF token; the browser posts
// it fire-and-forget via navigator.sendBeacon and ignores the 204.
func handleFileRUM(w http.ResponseWriter, r *http.Request) {
	sha := strings.ToLower(r.PathValue("sha256"))
	if !validSHA256(sha) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// A timing beacon is a few hundred bytes; cap the body hard.
	var t clientTiming
	if err := json.NewDecoder(io.LimitReader(r.Body, 512)).Decode(&t); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	size := moleculeSizeBucket(t.Atoms)
	ttfb := clampMillis(t.TTFBMs)
	domContent := clampMillis(t.DOMContentMs)
	build := clampMillis(t.MoleculeBuildMs)
	firstRender := clampMillis(t.FirstRenderMs)
	// The histogram is in seconds; the log carries the raw milliseconds.
	recordClientRender(ctx, "ttfb", size, ttfb/1000)
	recordClientRender(ctx, "dom_content", size, domContent/1000)
	recordClientRender(ctx, "molecule_build", size, build/1000)
	recordClientRender(ctx, "first_render", size, firstRender/1000)
	logger.Info("client render timing",
		"sha256", sha,
		"atoms", t.Atoms,
		"size", size,
		"ttfb_ms", int64(ttfb),
		"dom_content_ms", int64(domContent),
		"molecule_build_ms", int64(build),
		"first_render_ms", int64(firstRender),
	)
	w.WriteHeader(http.StatusNoContent)
}

// clampMillis bounds a client-reported millisecond value to [0, 10min]. JSON
// numbers cannot carry NaN/Inf, so a plain range clamp keeps a bogus beacon
// from injecting absurd samples.
func clampMillis(ms float64) float64 {
	switch {
	case ms < 0:
		return 0
	case ms > 600000:
		return 600000
	default:
		return ms
	}
}

// moleculeSizeBucket maps a molecule's atom count to a bounded label so
// client-render latency stays correlatable with molecule complexity without an
// unbounded-cardinality metric label.
func moleculeSizeBucket(atoms int) string {
	switch {
	case atoms <= 0:
		return "unknown"
	case atoms < 50:
		return "small"
	case atoms < 250:
		return "medium"
	case atoms < 1000:
		return "large"
	default:
		return "huge"
	}
}

// handleFavicon serves the embedded SVG icon at /favicon.ico. It is
// content-typed as SVG (browsers honor the type, not the .ico extension) and
// cached hard since the asset ships with the binary.
func handleFavicon(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	if _, err := w.Write(faviconSVG); err != nil {
		logger.Debug("favicon write failed", "error", err)
	}
}

// membersDeferred reports whether res is a compacted-archive envelope whose
// member bodies are lazy-loaded by the browser. The raw (cleave) section keeps
// hopper's "truncated" marker until the members are spliced back in, so this is
// the signal that the page should render member-content placeholders and the
// client should fetch /file/{sha}/members.
func membersDeferred(rawLitmus string) bool {
	if rawLitmus == "" {
		return false
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rawLitmus), &env); err != nil {
		return false
	}
	return hopperWasCompacted(env["raw"])
}

// handleFileMembers serves the lazily-loaded archive-member payload for the
// detail page: the reassembled Content-tab HTML, the archive Traits HTML, and
// the galaxy molecule JSON, for the same top-maxFilesShown members the page
// caps to. Only JS-running clients reach it (a crawler renders the parent-only
// page and never fetches), so the member DB work happens for real viewers only.
func handleFileMembers(w http.ResponseWriter, r *http.Request) {
	sha := strings.ToLower(r.PathValue("sha256"))
	if !validSHA256(sha) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// The response is deterministic per sha, so build it once and serve the
	// finished bytes thereafter. FetchTTL singleflights concurrent first-viewers
	// onto one build, so a burst on a freshly-crawled archive costs one member
	// fetch, not one per tab. renderMembersResponse holds the DB + reassembly +
	// render cost; on a hit none of that runs.
	cached, err := membersCache.FetchTTL(r.Context(), sha, auxCacheTTL, func(lctx context.Context) (cachedMembers, error) {
		return renderMembersResponse(lctx, sha)
	})
	if err != nil {
		// Best-effort enhancement: the page keeps its parent-only view either
		// way, but distinguish a genuine 404 from a transient hopper fault so
		// the client (and dashboards) can tell "no such sample" from "retry".
		logger.Debug("members enrich failed", "sha256", sha, "error", err)
		if errors.Is(err, hopper.ErrNotFound) {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		return
	}
	// Derived entirely from an immutable analysis and carrying no session-bound
	// token, so unlike the page HTML this is safe for shared caches. A rescan
	// changes it, which is what bounds max-age rather than "immutable".
	body, err := json.Marshal(cached)
	if err != nil {
		logger.Debug("members json encode failed", "sha256", sha, "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=300, stale-while-revalidate=86400")
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if _, err := w.Write(body); err != nil {
		logger.Debug("members json write failed", "sha256", sha, "error", err)
	}
}

// renderMembersResponse builds the GET /file/{sha}/members payload: it hydrates
// the archive members, renders the Content and Traits partials, and marshals the
// JSON the client injects. It is the uncached body behind membersCache; a
// returned error is propagated (not cached) so a transient hopper fault or a
// 404 is retried on the next request rather than pinned.
func renderMembersResponse(ctx context.Context, sha string) (cachedMembers, error) {
	start := time.Now()
	res, err := enrichedResult(ctx, sha)
	if err != nil {
		return cachedMembers{}, err
	}
	return renderMembers(ctx, sha, &res, start, time.Since(start).Milliseconds())
}

// renderMembersFromResult is renderMembersResponse for a caller that already
// holds the parent's storedResult — the detail handler, warming its own page.
// It skips the parent re-read; everything downstream is identical.
func renderMembersFromResult(ctx context.Context, sha string, parent *storedResult) (cachedMembers, error) {
	start := time.Now()
	res := *parent // local copy: RawLitmus is replaced with the enriched envelope
	if sample, ok := parentSampleFromEnvelope(res.RawLitmus); ok && hopperWasCompacted(sample.CleaveResult) {
		enriched, err := enrichMembers(ctx, sha, sample)
		if err != nil {
			logger.Debug("member enrichment failed; serving parent-only", "sha", sha, "error", err)
		} else if enriched != nil {
			res.RawLitmus = string(enriched)
		}
	}
	return renderMembers(ctx, sha, &res, start, time.Since(start).Milliseconds())
}

// renderMembers turns an enriched result into the cached payload: the shared
// tail of both paths above.
func renderMembers(ctx context.Context, sha string, res *storedResult, start time.Time, enrichMS int64) (cachedMembers, error) {
	prepareStart := time.Now()
	data := prepareResultData(res.Filename, sha, res)
	prepareMS := time.Since(prepareStart).Milliseconds()
	renderStart := time.Now()

	var content, traits bytes.Buffer
	if err := resultTemplate.ExecuteTemplate(&content, "contentBody", data); err != nil {
		// A template failure is a server bug, not a transient fault — surface it
		// at Error so it isn't buried at the handler's Debug level.
		logger.Error("members render failed", "template", "contentBody", "sha256", sha, "error", err)
		return cachedMembers{}, fmt.Errorf("members render contentBody %s: %w", sha, err)
	}
	if err := resultTemplate.ExecuteTemplate(&traits, "findingsbody", data); err != nil {
		logger.Error("members render failed", "template", "findingsbody", "sha256", sha, "error", err)
		return cachedMembers{}, fmt.Errorf("members render findingsbody %s: %w", sha, err)
	}

	// The client sits on "Loading the archive's members…" for exactly this long,
	// so the phases are logged separately: a slow DB and a slow render call for
	// different fixes, and the total alone can't tell them apart.
	level := slog.LevelDebug
	if time.Since(start) >= slowDetailThreshold {
		level = slog.LevelWarn
	}
	logger.Log(ctx, level, "members render timing",
		"sha256", sha,
		"enrich_ms", enrichMS,
		"prepare_ms", prepareMS,
		"template_ms", time.Since(renderStart).Milliseconds(),
		"cleave_bytes", len(res.RawLitmus),
		"files", len(data.FileViews),
		"total_ms", time.Since(start).Milliseconds(),
	)
	return cachedMembers{
		ContentHTML: content.String(),
		TraitsHTML:  traits.String(),
		HasContent:  len(data.FileViews) > 0,
	}, nil
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
	refs, err := db.ParentArchivesForChild(ctx, childSHA, maxParentArchives)
	if err != nil {
		log.Debug("parent archive lookup failed", "error", err)
		return nil
	}
	out := make([]ParentArchive, 0, len(refs))
	for i := range refs {
		ref := &refs[i]
		entry := ParentArchive{
			SHA256:      ref.SHA256,
			SHA256Short: shortSHA(ref.SHA256),
			Filename:    firstNonEmpty(ref.Filename, filepath.Base(ref.SamplePath)),
			ChildSHA:    childSHA,
			Path:        ref.Path,
			Rel:         ref.Rel,
			Feed:        ref.Feed,
			Ecosystem:   ref.Ecosystem,
			Version:     ref.Version,
			Package:     ref.Package,
		}
		if len(ref.LitmusResult) > 0 {
			var ml litmusMlResponse
			if json.Unmarshal(ref.LitmusResult, &ml) == nil {
				entry.Classification = classificationName(ml.verdictClass())
			}
		}
		if ref.AnalyzedAt != nil {
			entry.AnalyzedAt = ref.AnalyzedAt.Format("2 Jan 2006 15:04 UTC")
			entry.AnalyzedAgo = timeAgo(time.Since(*ref.AnalyzedAt))
		}
		out = append(out, entry)
	}
	return out
}

// parentLookupTimeout bounds the single ParentArchivesForChild lookup so a slow
// hopper-db degrades the backlinks, not the page.
const parentLookupTimeout = 2 * time.Second

// memberEnrichTimeout bounds the archive-member hydration behind GET
// /file/{sha}/members. The parent-only page has already painted, so member
// splicing is a best-effort enhancement: a distressed hopper-db must shed it
// fast rather than let unbounded member queries pile on (observed stretching a
// ~6-row primary-key fetch to 37s when the DB was contended).
const memberEnrichTimeout = 5 * time.Second

// membersWarmTimeout bounds the background build kicked off by warmMembers.
// Generous next to memberEnrichTimeout because nothing is waiting on it: the
// only cost of a slow warm is that the browser's own fetch does the work
// instead, which is exactly today's behaviour.
const membersWarmTimeout = 30 * time.Second

// fontPreloadLink starts the two Latin webfaces before the HTML is parsed —
// browsers honour rel=preload in the header, and Cloudflare promotes it to a
// 103 Early Hint, so the fonts are in flight while the origin is still
// rendering. Only the Latin subsets: the -ext files carry accents most pages
// never reference, and preloading an unused font is worse than not preloading.
const fontPreloadLink = `</static/fonts/inter-latin.woff2>; rel=preload; as=font; type="font/woff2"; crossorigin, ` +
	`</static/fonts/oxanium-latin.woff2>; rel=preload; as=font; type="font/woff2"; crossorigin`

// warmMembers builds the archive-member payload in the background while the
// page HTML is still being written, so the browser's fetch a few milliseconds
// later is a cache hit rather than the thing it waits on. FetchTTL
// singleflights, so a real request arriving mid-warm joins this build instead
// of starting a second one, and a warm that loses the race costs nothing.
//
// The request context is detached (values kept, cancellation dropped): this
// outlives the response it was started from by design.
func warmMembers(ctx context.Context, sha string, res *storedResult) {
	if membersCache == nil {
		return
	}
	// The goroutine outlives the request that started it, so it works from its
	// own copy rather than the handler's.
	parent := *res
	go func() {
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), membersWarmTimeout)
		defer cancel()
		_, err := membersCache.FetchTTL(wctx, sha, auxCacheTTL, func(lctx context.Context) (cachedMembers, error) {
			// The page render already holds this sample's envelope, so the warm
			// path splices members into that copy rather than re-reading a
			// multi-megabyte row hopper just handed us.
			return renderMembersFromResult(lctx, sha, &parent)
		})
		if err != nil {
			logger.Debug("members warm failed", "sha256", sha, "error", err)
		}
	}()
}

// parentSampleFromEnvelope rebuilds the three analysis columns Reassemble reads
// from an envelope prism already has in memory. The top-level unmarshal keeps
// each section as a raw slice, so this is one scan rather than a full parse.
func parentSampleFromEnvelope(envelope string) (*hopper.Sample, bool) {
	var top map[string]json.RawMessage
	if json.Unmarshal([]byte(envelope), &top) != nil {
		return nil, false
	}
	sample := &hopper.Sample{
		LitmusResult: top["ml"],
		LLMResult:    top["llm"],
		CleaveResult: top["raw"],
	}
	return sample, len(sample.CleaveResult) > 0
}

// hopperCacheTTL is how long a cached result is served without consulting
// hopper. Older entries are still served immediately; the refresh happens
// in a background goroutine so the request path never waits on the database.
const hopperCacheTTL = time.Hour

// slowDetailThreshold is the total uncached hopper-fetch time past which
// fetchFromHopper and handleFile log their phase breakdowns at WARN instead of
// Debug/Info, so pathological detail-page loads surface in logs regardless of
// trace sampling.
const slowDetailThreshold = time.Second

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
		// result, and an explicit failure page once it has given up.
		if v, ok := uploadsInFlight.Load(sha); ok {
			if st, isState := v.(uploadState); isState {
				switch {
				case st.FailedAt.IsZero():
					if _, ok := errors.AsType[*pendingAnalysisError](err); !ok {
						return false, storedResult{}, &pendingAnalysisError{SHA: sha, Filename: st.Filename}
					}
				case time.Since(st.FailedAt) <= uploadFailureTTL:
					return false, storedResult{}, &uploadFailedError{SHA: sha, Filename: st.Filename}
				default:
					uploadsInFlight.Delete(sha)
				}
			}
		}
		return false, storedResult{}, err
	}
	// Refresh a stale cache hit in the background so the request path never
	// blocks on hopper. The cached value is a parent-only envelope now (members
	// load lazily via /file/{sha}/members), so there's no compaction re-enrich
	// to do here — only TTL freshness. The refreshInFlight guard keeps a sha to
	// one concurrent background refresh.
	if cacheHit && time.Since(res.CachedAt) > hopperCacheTTL && hopperDB.Load() != nil {
		if _, loaded := refreshInFlight.LoadOrStore(sha, struct{}{}); !loaded {
			go refreshFromHopper(context.WithoutCancel(ctx), sha, reqLogger)
		}
	}
	return cacheHit, res, nil
}

// pendingAnalysisError signals that a sample exists in hopper but has not
// been analyzed yet (cleave_result is NULL). Handlers should render the
// "Analyzing…" page and not cache the partial result.
type pendingAnalysisError struct {
	SHA      string
	Filename string
}

func (e *pendingAnalysisError) Error() string { return "analysis pending for " + e.SHA }

// loadParentSample reads a sample's parent row from hopper under the shared
// circuit breaker and query timeout, mapping hopper's not-found and not-yet-
// analyzed states to the errors the HTTP handlers expect (a "not found" message
// for a 404, *pendingAnalysisError while a worker is still running). It is the
// common preamble for the cached parent-only path (fetchFromHopper) and the
// member-complete path (enrichedResult); callers layer their own span, logging,
// and member reassembly on top.
func loadParentSample(ctx context.Context, sha string) (*hopper.Sample, error) {
	db := hopperDB.Load()
	if db == nil {
		return nil, fmt.Errorf("hopper db not connected (host=%s)", hopperDSNHost(hopperDBDSN))
	}
	if err := dbBreaker.allow(); err != nil {
		recordDep(ctx, "hopper-db", "lookup", "rejected", time.Time{})
		return nil, fmt.Errorf("hopper-db lookup: %w", err)
	}
	// Bound the read so a slow hopper-db can't pin the caller; a timeout trips
	// the breaker.
	ctx, cancel := context.WithTimeout(ctx, hopperQueryTimeout)
	defer cancel()
	start := time.Now()
	sample, err := db.SampleBySHA256(ctx, sha)
	if err != nil {
		if errors.Is(err, hopper.ErrNotFound) {
			// The DB answered; "not found" is a healthy response, not a fault.
			dbBreaker.success()
			recordDep(ctx, "hopper-db", "lookup", "ok", start)
			return nil, fmt.Errorf("sample not found in hopper: %w", err)
		}
		dbBreaker.failure()
		recordDep(ctx, "hopper-db", "lookup", "error", start)
		return nil, fmt.Errorf("hopper lookup (host=%s): %w", hopperDSNHost(hopperDBDSN), err)
	}
	dbBreaker.success()
	recordDep(ctx, "hopper-db", "lookup", "ok", start)
	if len(sample.CleaveResult) == 0 {
		return nil, &pendingAnalysisError{SHA: sha, Filename: firstNonEmpty(sample.Filename, filepath.Base(sample.Path))}
	}
	return sample, nil
}

// fetchFromHopper maps a sample to the parent-only storedResult the detail page
// renders on first paint. Archive member bodies are hydrated lazily (GET
// /file/{sha}/members), so this hot path — reached by every visitor, crawlers
// included, via lookupResult's cache — is a single SampleBySHA256 that never
// touches the member queries.
func fetchFromHopper(ctx context.Context, sha string) (storedResult, error) {
	start := time.Now()
	sctx, span := obs.Span(ctx, "prism.detail.sample_lookup")
	sample, err := loadParentSample(sctx, sha)
	span.End()
	if err != nil {
		return storedResult{}, err
	}
	res := storedResultFromHopperSample(sample)
	dur := time.Since(start)
	level := slog.LevelDebug
	if dur >= slowDetailThreshold {
		level = slog.LevelWarn
	}
	logger.Log(ctx, level, "hopper detail fetch",
		"sha256", sha,
		"compacted", hopperWasCompacted(sample.CleaveResult),
		"cleave_bytes", len(sample.CleaveResult),
		"sample_ms", dur.Milliseconds(),
	)
	return res, nil
}

// enrichMembers hydrates the archive members prism will display — the top
// maxFilesShown by per-file criticality (from the compacted envelope's risk-
// sorted stubs) plus any composite-linked members — and splices them back into
// the parent envelope via hopper.Reassemble. Returns the enriched envelope JSON
// (nil when nothing needed splicing). One deterministic SamplesBySHAs primary-
// key fetch, called off the render hot path so only real JS-running clients pay
// for it.
func enrichMembers(ctx context.Context, sha string, sample *hopper.Sample) ([]byte, error) {
	db := hopperDB.Load()
	if db == nil {
		return nil, errors.New("hopper not connected")
	}
	pickStart := time.Now()
	// Risk-ranked members first, then the members a cross-file composite drew
	// from so its trail links resolve. Both lists are deduped and the total is
	// capped: the page renders at most maxFilesShown files and
	// maxEvidenceBlocks regions, so anything past maxMemberFetch is fetched,
	// parsed and thrown away. One archive asked for 143 members — 3 MB of child
	// rows inflating a 9 MB envelope — to render three files.
	wanted := make([]string, 0, maxMemberFetch)
	seen := make(map[string]bool, maxMemberFetch)
	add := func(shas []string) {
		for _, s := range shas {
			if len(wanted) >= maxMemberFetch {
				return
			}
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			wanted = append(wanted, s)
		}
	}
	// Risk first, and only the top maxFilesShown of it, because that is all the
	// content view will ever render. compositeLinkedSHAs is unranked — it names
	// every member a cross-file composite touched, which is how one archive
	// asked for 143 — so it only fills what is left, and a member it wanted but
	// did not get simply loses its trail link (traitSources already drops links
	// to files that did not render).
	risky := envelopeChildSHAs(sample.CleaveResult, sha)
	if len(risky) > maxFilesShown {
		risky = risky[:maxFilesShown]
	}
	add(risky)
	add(compositeLinkedSHAs(sample.CleaveResult, sha))
	pickMS := time.Since(pickStart).Milliseconds()
	if len(wanted) == 0 {
		return nil, nil
	}
	// Gate on the same breaker as the parent lookup and bound the read tightly:
	// the page is already usable parent-only, so a slow/contended hopper-db must
	// fail this fast instead of hanging the /members request (see
	// memberEnrichTimeout). Member timeouts feed the breaker so sustained
	// distress sheds this load entirely.
	if err := dbBreaker.allow(); err != nil {
		recordDep(ctx, "hopper-db", "members", "rejected", time.Time{})
		return nil, fmt.Errorf("hopper-db members: %w", err)
	}
	mctx, cancel := context.WithTimeout(ctx, memberEnrichTimeout)
	defer cancel()
	membersStart := time.Now()
	sctx, memSpan := obs.Span(mctx, "prism.detail.members")
	children, err := db.SamplesBySHAs(sctx, wanted)
	memSpan.End()
	if err != nil {
		dbBreaker.failure()
		recordDep(ctx, "hopper-db", "members", "error", membersStart)
		return nil, err
	}
	dbBreaker.success()
	recordDep(ctx, "hopper-db", "members", "ok", membersStart)
	if len(children) == 0 {
		return nil, nil
	}
	fetchMS := time.Since(membersStart).Milliseconds()
	reStart := time.Now()
	_, reSpan := obs.Span(ctx, "prism.detail.reassemble")
	enriched, err := hopper.Reassemble(sample, children)
	reSpan.End()
	if err != nil {
		return nil, err
	}
	childBytes := 0
	for _, c := range children {
		childBytes += len(c.CleaveResult)
	}
	logger.Debug("member enrich timing",
		"sha256", sha,
		"wanted", len(wanted),
		"got", len(children),
		"pick_ms", pickMS,
		"fetch_ms", fetchMS,
		"reassemble_ms", time.Since(reStart).Milliseconds(),
		"child_bytes", childBytes,
		"enriched_bytes", len(enriched),
	)
	return enriched, nil
}

// enrichedResult loads a sample and returns its storedResult with the archive
// members spliced in — the member-complete view the lazy /members endpoint and
// the JSON export need (the cached fetchFromHopper result is parent-only). It
// re-reads the parent row because Reassemble needs the raw *hopper.Sample; that
// lookup is cheap and only JS-running clients / API callers reach it.
func enrichedResult(ctx context.Context, sha string) (storedResult, error) {
	sample, err := loadParentSample(ctx, sha)
	if err != nil {
		return storedResult{}, err
	}
	res := storedResultFromHopperSample(sample)
	if hopperWasCompacted(sample.CleaveResult) {
		if enriched, eerr := enrichMembers(ctx, sha, sample); eerr != nil {
			logger.Debug("member enrichment failed; serving parent-only", "sha", sha, "error", eerr)
		} else if len(enriched) > 0 {
			res.RawLitmus = string(enriched)
		}
	}
	return res, nil
}

// compositeLinkedSHAs returns the content SHAs of members that a notable+
// finding on the container draws from, ranked by the strongest such finding
// (then SHA for determinism). These are the files the archive's verdict hangs
// on, regardless of their own standalone score.
func compositeLinkedSHAs(cleaveResult []byte, parentSHA string) []string {
	if len(cleaveResult) == 0 {
		return nil
	}
	var env struct {
		Files []json.RawMessage `json:"files"`
		FS    []json.RawMessage `json:"fs"`
	}
	if json.Unmarshal(cleaveResult, &env) != nil {
		return nil
	}
	entries := env.Files
	if len(entries) == 0 {
		entries = env.FS
	}
	idToSHA := make(map[int]string, len(entries))
	var containerFindings []json.RawMessage
	for _, raw := range entries {
		var f struct {
			SHA      string            `json:"sha"`
			Traits   []json.RawMessage `json:"traits"`
			Find     []json.RawMessage `json:"find"`
			TS       []json.RawMessage `json:"ts"`
			ID       int               `json:"id"`
			Depth    int               `json:"depth"`
			OldDepth int               `json:"dp"`
		}
		if json.Unmarshal(raw, &f) != nil {
			continue
		}
		if f.SHA != "" {
			idToSHA[f.ID] = f.SHA
		}
		depth := f.Depth
		if depth == 0 {
			depth = f.OldDepth
		}
		if depth == 0 {
			containerFindings = f.Traits
			if len(containerFindings) == 0 {
				containerFindings = f.Find
			}
			if len(containerFindings) == 0 {
				containerFindings = f.TS
			}
		}
	}

	type leg struct {
		File    int `json:"file"`
		OldFile int `json:"f"`
	}
	maxCrit := make(map[string]int)
	for _, raw := range containerFindings {
		var fd struct {
			From    []leg `json:"from"`
			Srcs    []leg `json:"srcs"`
			Crit    int   `json:"crit"`
			OldCrit int   `json:"l"`
		}
		if json.Unmarshal(raw, &fd) != nil {
			continue
		}
		crit := fd.Crit
		if crit == 0 {
			crit = fd.OldCrit
		}
		if crit < minFileCrit {
			continue // notable+ only
		}
		legs := fd.From
		if len(legs) == 0 {
			legs = fd.Srcs
		}
		for _, lg := range legs {
			id := lg.File
			if id == 0 {
				id = lg.OldFile
			}
			memberSHA, ok := idToSHA[id]
			if !ok || memberSHA == parentSHA {
				continue
			}
			if crit > maxCrit[memberSHA] {
				maxCrit[memberSHA] = crit
			}
		}
	}
	if len(maxCrit) == 0 {
		return nil
	}
	out := make([]string, 0, len(maxCrit))
	for memberSHA := range maxCrit {
		out = append(out, memberSHA)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if maxCrit[out[i]] != maxCrit[out[j]] {
			return maxCrit[out[i]] > maxCrit[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

// envelopeChildSHAs returns the member SHAs of a compacted archive envelope: the
// files[] entries other than the container, which compaction keeps as
// lightweight stubs. Returns nil for an envelope that carries no member stubs
// (an older stored archive) — callers then have only sample_locations.
func envelopeChildSHAs(cleaveResult []byte, parentSHA string) []string {
	if len(cleaveResult) == 0 {
		return nil
	}
	var env struct {
		Files []json.RawMessage `json:"files"`
		FS    []json.RawMessage `json:"fs"`
	}
	if json.Unmarshal(cleaveResult, &env) != nil {
		return nil
	}
	entries := env.Files
	if len(entries) == 0 {
		entries = env.FS
	}
	// Rank by the per-file risk the stub carries so a capped fetch pulls the
	// most significant members first — the same criticality order the Content
	// tab and galaxy display, so the fetched set and the displayed set agree.
	// Compaction retains a stub per member up to maxArchiveMembers (100k), so
	// this sees the whole member set, not a truncated prefix.
	type member struct {
		sha  string
		risk int
	}
	members := make([]member, 0, len(entries))
	for _, raw := range entries {
		var f struct {
			SHA  string `json:"sha"`
			Risk int    `json:"risk"`
		}
		if json.Unmarshal(raw, &f) != nil || f.SHA == "" || f.SHA == parentSHA {
			continue
		}
		members = append(members, member{sha: f.SHA, risk: f.Risk})
	}
	sort.SliceStable(members, func(i, j int) bool { return members[i].risk > members[j].risk })
	out := make([]string, len(members))
	for i, m := range members {
		out[i] = m.sha
	}
	return out
}

// hopperWasCompacted reports whether the cleave result was stripped of child
// entries by hopper's compactCleaveResultForStorage, which always sets the
// "truncated" marker when it does so. Callers should query hopper for samples
// whose parent matches and splice them back in.
//
// It keys off "truncated" alone, not omitted_files: a result prism has already
// reassembled keeps omitted_files for the members beyond its fetch cap but
// clears "truncated", so it is correctly seen as enriched — without it, the
// read path would re-enrich a partially-merged archive on every cache hit.
func hopperWasCompacted(cleaveResult []byte) bool {
	if len(cleaveResult) == 0 {
		return false
	}
	var env struct {
		Truncated bool `json:"truncated"`
	}
	if err := json.Unmarshal(cleaveResult, &env); err != nil {
		return false
	}
	return env.Truncated
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

// Download-from-hopper retry tuning. hopper's retryable answers (a 503 while
// warming up, extraction slots momentarily full, or a transient I/O blip) carry
// a Retry-After and usually clear within a beat, but a cold or busy hopper can
// take longer, so we wait patiently rather than failing the user's click.
const (
	// downloadAttemptTimeout bounds the wait for hopper to *start* responding to
	// one attempt. It does not cap the stream itself: once a 200 arrives the body
	// flows under the client's longer timeout, so a large file isn't truncated.
	downloadAttemptTimeout = 60 * time.Second
	// downloadMaxRetryWait clamps a Retry-After hint so a misbehaving or
	// pathological value can't strand the waiting user for minutes.
	downloadMaxRetryWait = 60 * time.Second
)

// downloadBackoff is the default wait before each download retry: 15s, then
// 30s — three attempts in all. A 503's Retry-After overrides the matching entry
// when hopper sends one (clamped to downloadMaxRetryWait).
var downloadBackoff = []time.Duration{15 * time.Second, 30 * time.Second}

// parseRetryAfter reads a delta-seconds Retry-After header (RFC 9110 §10.2.3).
// hopper emits integer seconds; a missing, negative, or HTTP-date value falls
// back to def.
func parseRetryAfter(v string, def time.Duration) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n < 0 {
		return def
	}
	return time.Duration(n) * time.Second
}

// sleepCtx waits for d or until ctx is cancelled, reporting whether the full
// wait elapsed. A false return (client went away mid-backoff) tells the caller
// to abandon the retry rather than issue a request nobody is waiting for.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// drainClose reads and discards a small tail of body then closes it, so an
// idle keep-alive connection can be reused instead of dropped after a non-2xx
// response we don't otherwise read.
func drainClose(body io.ReadCloser, log *slog.Logger) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 4096)) //nolint:errcheck // diagnostics-free drain for connection reuse
	if err := body.Close(); err != nil {
		log.Debug("hopper download body close failed", "error", err)
	}
}

// retryAfterSeconds renders a backoff duration as the integer delta-seconds a
// Retry-After header carries, never less than 1.
func retryAfterSeconds(d time.Duration) int {
	if s := int(d / time.Second); s >= 1 {
		return s
	}
	return 1
}

// fetchHopperFile performs GET /api/file/{sha} with a patient, Retry-After
// aware retry loop. On success it returns the live response and a cancel func
// the caller MUST defer — it keeps the streaming context alive, so cancelling
// early would truncate the body. On failure it writes the appropriate status to
// w and returns (nil, nil); the caller simply returns.
func fetchHopperFile(w http.ResponseWriter, r *http.Request, sha string, dlStart time.Time, reqLogger *slog.Logger) (*http.Response, context.CancelFunc) {
	for attempt := 1; ; attempt++ {
		// Bound the wait for hopper to *start* responding without capping the
		// stream: the AfterFunc cancels this attempt only if no response has
		// arrived in time. On a kept response we stop the timer and let the body
		// flow under the client's longer timeout, so a multi-GB file isn't
		// truncated at downloadAttemptTimeout.
		attemptCtx, cancel := context.WithCancel(r.Context())
		timer := time.AfterFunc(downloadAttemptTimeout, cancel)
		req, err := http.NewRequestWithContext(attemptCtx, http.MethodGet, hopperFileURL(sha), http.NoBody)
		if err != nil {
			timer.Stop()
			cancel()
			http.Error(w, "failed to prepare download", http.StatusInternalServerError)
			return nil, nil
		}
		hopper.Authorize(req)
		resp, err := hopperClient.Do(req)
		if err != nil {
			timer.Stop()
			cancel()
			// A fired attempt timer (or a parent cancel) surfaces here as a context
			// error; either way the attempt failed, so trip the breaker and retry.
			apiBreaker.failure()
			recordDep(r.Context(), "hopper-api", "download", "error", dlStart)
			if attempt <= len(downloadBackoff) && sleepCtx(r.Context(), downloadBackoff[attempt-1]) {
				reqLogger.Warn("hopper download attempt failed; retrying",
					"attempt", attempt, "error", err, "backoff", downloadBackoff[attempt-1])
				continue
			}
			status, msg := http.StatusBadGateway, "download unavailable"
			if errors.Is(err, context.DeadlineExceeded) && r.Context().Err() == nil {
				status, msg = http.StatusGatewayTimeout, "download timed out; please try again"
			}
			reqLogger.Warn("hopper download request failed", "error", err, "hopper_api_addr", hopperAPIAddr)
			http.Error(w, msg, status)
			return nil, nil
		}
		// 503 is hopper backpressure (warming up, extraction slots momentarily
		// full, or a transient I/O blip), not a fault — it carries a Retry-After
		// and must not trip the breaker. Honor the hint (clamped), retry within
		// budget, and on the last attempt hand the Retry-After back so the client
		// backs off by the amount hopper asked for.
		if resp.StatusCode == http.StatusServiceUnavailable {
			timer.Stop()
			idx := min(attempt-1, len(downloadBackoff)-1)
			wait := min(parseRetryAfter(resp.Header.Get("Retry-After"), downloadBackoff[idx]), downloadMaxRetryWait)
			drainClose(resp.Body, reqLogger)
			cancel()
			recordDep(r.Context(), "hopper-api", "download", "rejected", dlStart)
			if attempt <= len(downloadBackoff) && sleepCtx(r.Context(), wait) {
				reqLogger.Warn("hopper download unavailable; retrying", "attempt", attempt, "retry_after", wait)
				continue
			}
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(wait)))
			http.Error(w, "download temporarily unavailable; please try again shortly", http.StatusServiceUnavailable)
			return nil, nil
		}
		// A response we'll act on (200 or a terminal status). Stop the response
		// timer; if the caller streams the body it's bounded by the client timeout.
		timer.Stop()
		return resp, cancel
	}
}

func serveFileDownload(w http.ResponseWriter, r *http.Request, sha, ip string) {
	if !validSHA256(sha) {
		http.Error(w, "invalid sha256", http.StatusBadRequest)
		return
	}

	reqLogger := logger.With("sha256", sha, "client_ip", ip)

	if !hopperAPIAvailable() {
		reqLogger.Info("download rejected: hopper-api unavailable")
		w.Header().Set("Retry-After", "15")
		http.Error(w, "download temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

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
		recordDep(r.Context(), "hopper-api", "download", "rejected", time.Time{})
		reqLogger.Warn("hopper download skipped", "error", err)
		w.Header().Set("Retry-After", "10")
		http.Error(w, "download temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	dlStart := time.Now()
	resp, streamCancel := fetchHopperFile(w, r, sha, dlStart, reqLogger)
	if resp == nil {
		return // fetchHopperFile already wrote the error response.
	}
	defer streamCancel()
	defer func() {
		if err := resp.Body.Close(); err != nil {
			reqLogger.Debug("hopper download body close failed", "error", err)
		}
	}()

	if resp.StatusCode >= http.StatusInternalServerError {
		apiBreaker.failure()
		recordDep(r.Context(), "hopper-api", "download", "error", dlStart)
	} else {
		apiBreaker.success()
		recordDep(r.Context(), "hopper-api", "download", "ok", dlStart)
	}

	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusNotFound:
			http.Error(w, "not found", http.StatusNotFound)
		case http.StatusGone:
			// hopper has the DB row but the bytes were deleted from disk — permanent.
			http.Error(w, "this file is no longer available", http.StatusGone)
		case http.StatusBadRequest:
			http.Error(w, "invalid sha256", http.StatusBadRequest)
		case http.StatusRequestEntityTooLarge:
			http.Error(w, "file is too large to download from the browser; use the litmus CLI", http.StatusRequestEntityTooLarge)
		case http.StatusUnsupportedMediaType:
			http.Error(w, "this archive type can't be served for download", http.StatusUnsupportedMediaType)
		case http.StatusUnprocessableEntity:
			// Encrypted, corrupt, or otherwise unextractable archive member — permanent.
			http.Error(w, "this file could not be extracted for download", http.StatusUnprocessableEntity)
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
// gated at prism by a valid CSRF token (so the request demonstrably came from a
// recently-rendered page) and a global rate limit, then forwarded to hopper's
// /api/rescan endpoint. hopper enforces the per-sample re-queue cooldown
// atomically in its UPDATE; prism mirrors that cooldown (rescanCooldown, 15
// minutes) only to decide when to offer the button. On success the sample's
// analysis fields are cleared on the master so the next worker poll picks it
// up, and prism's local result cache for that SHA is invalidated.
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
			db, err := hopper.Open(ctx, hopperDBDSN, "prism")
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

	// The JSON export is the full envelope, so it hydrates archive members
	// (the interactive page defers them, but an API caller wants everything).
	res, err := enrichedResult(r.Context(), sha)
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

	// name is hopper's filename for a still-pending sample, which escalation
	// hands the scan server as a format hint. Empty in every other state.
	check := func() (state, payload, name string) {
		if after.IsZero() {
			st, filename := uploadViewState(ctx, sha)
			switch st {
			case "ready":
				return "ready", readyPayload(sha), ""
			case "missing":
				return "missing", `{"reason":"not found"}`, ""
			}
			return "pending", "", filename
		}
		// Fresh-analysis mode: pull the full row so we can compare the
		// timestamp. This is a heavier query than SampleAnalyzed but
		// only fires once per poll, well within hopper's budget.
		sample, err := db.SampleBySHA256(ctx, sha)
		if err != nil || sample == nil {
			return "missing", `{"reason":"not found"}`, ""
		}
		if sample.AnalyzedAt != nil && sample.AnalyzedAt.After(after) {
			return "ready", readyPayload(sha), ""
		}
		return "pending", "", ""
	}

	// Initial probe before the first tick — covers the worker-finishes-
	// before-SSE-open race so the browser doesn't wait an extra 50 ms
	// for a result that already exists.
	state, payload, name := check()
	if state == "missing" || state == "ready" {
		emit(state, payload)
		return
	}

	// Somebody is waiting on a sample no worker has reached. This is the one
	// place in prism that knows that, so spend it: escalate once, on the first
	// probe of this connection, and let the loop below just watch. Detached from
	// the request context because the browser drops this stream the instant the
	// result lands — which is exactly when the escalation is finishing its work.
	//
	// Not done in ?after= mode: that is the post-rescan stream, where the sample
	// is already sitting in the tier escalation would promote it to. And not
	// done in handleFileStatus, the no-SSE fallback — it re-polls every two
	// seconds, and a trigger that fires on a timer is not the attention signal
	// this is meant to capture.
	if after.IsZero() {
		go escalate(context.WithoutCancel(ctx), sha, name, logger.With("sha256", sha, "client_ip", ip))
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
			state, payload, _ := check()
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
//
// The second result is hopper's filename for a pending sample, which escalation
// passes to the scan server as a format hint. It is empty in every other state.
func uploadViewState(ctx context.Context, sha string) (state, filename string) {
	_, _, err := lookupResult(ctx, sha, logger)
	if err == nil {
		return "ready", ""
	}
	if pend, ok := errors.AsType[*pendingAnalysisError](err); ok {
		return "pending", pend.Filename
	}
	return "missing", ""
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
		state, _ := uploadViewState(ctx, sha)
		switch state {
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

// noEscalateScan keeps the scan server for uploads only, leaving escalated
// samples to hopper's workers. Set via --no-escalate-scan or
// PRISM_NO_ESCALATE_SCAN (1/true/yes/on).
//
// The flag is negative because pointing --litmus at a scan server is already
// the opt-in; see escalate.go for why that is the right default.
var noEscalateScan = false

// envBool reads a 1/true/yes/on or 0/false/no/off environment variable,
// returning cur when it is unset or unrecognized.
func envBool(name string, cur bool) bool {
	switch strings.ToLower(os.Getenv(name)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return cur
}

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
	if !uploadBackendsAvailable() {
		reqLogger.Info("upload rejected: analysis backends unavailable")
		renderError(w, r, http.StatusServiceUnavailable, errorData{
			Icon:    "⏸",
			Title:   "Upload temporarily unavailable",
			Message: "Uploads will return automatically when the analysis services reconnect.",
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
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
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
		if _, ok := errors.AsType[*http.MaxBytesError](rerr); ok {
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
	uploadsInFlight.Store(sha, uploadState{Filename: filename})
	go ingestUpload(context.WithoutCancel(ctx), buf, sha, filename)

	http.Redirect(w, r, "/file/"+sha, http.StatusSeeOther)
}

// buildUploadEnvelope encodes the multipart body hopper's /api/upload expects:
// a "provenance" part (the required sidecar) followed by the "file" part. A
// browser submission has no package origin, so the provenance is minimal —
// collector "prism", category "submitted", and the artifact identity. hopper
// treats these as claims and never derives a sample's label from them. The
// whole envelope is buffered so postOnce can replay it on retry.
func buildUploadEnvelope(buf []byte, sha, filename string) (payload []byte, contentType string, err error) {
	prov := hopper.Sidecar{
		SchemaVersion: hopper.SidecarSchemaVersion,
		Artifact:      hopper.Artifact{Filename: filename, SHA256: sha, SizeBytes: int64(len(buf))},
		Fetch:         hopper.Fetch{Collector: "prism", Category: "submitted", At: time.Now().UTC()},
	}
	provJSON, err := json.Marshal(&prov)
	if err != nil {
		return nil, "", fmt.Errorf("marshal provenance: %w", err)
	}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	pf, err := mw.CreateFormField("provenance")
	if err != nil {
		return nil, "", fmt.Errorf("provenance part: %w", err)
	}
	if _, err := pf.Write(provJSON); err != nil {
		return nil, "", fmt.Errorf("write provenance: %w", err)
	}
	ff, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return nil, "", fmt.Errorf("file part: %w", err)
	}
	if _, err := ff.Write(buf); err != nil {
		return nil, "", fmt.Errorf("write file: %w", err)
	}
	if err := mw.Close(); err != nil {
		return nil, "", fmt.Errorf("close multipart: %w", err)
	}
	return body.Bytes(), mw.FormDataContentType(), nil
}

// uploadToHopper POSTs the provenance+file envelope to hopper /api/upload,
// bearing the fleet-wide credential [hopper.Authorize] resolves ($HOPPER_TOKEN,
// else the first line of ~/.tok/hopper). The envelope is buffered so the request
// can be safely retried with backoff.
//
// A 401 is reported to the caller rather than retried: the credential is read
// once per process, so a rejected token is rejected until the file is fixed and
// prism restarts. Replaying the upload would only repeat the rejection.
func uploadToHopper(ctx context.Context, buf []byte, sha, filename string, log *slog.Logger) (*hopperUploadResponse, error) {
	target := hopperUploadURL(filename)

	body, contentType, err := buildUploadEnvelope(buf, sha, filename)
	if err != nil {
		return nil, err
	}

	resp, err := postUploadWithRetry(ctx, target, body, contentType, log) //nolint:bodyclose // closed by readUploadResponse below
	if err != nil {
		return nil, err
	}
	return readUploadResponse(resp, log)
}

// postUploadWithRetry POSTs to hopper /api/upload with exponential backoff
// and jitter. Only transport errors and 5xx responses trigger a retry —
// 4xx (including 401, a credential no retry can fix) is returned to the caller
// as-is. The retry budget is bounded by ctx.
func postUploadWithRetry(ctx context.Context, target string, body []byte, contentType string, log *slog.Logger) (*http.Response, error) {
	var resp *http.Response
	err := retry.Do(
		func() error {
			r, err := postOnce(ctx, target, body, contentType)
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

// postOnce performs a single authenticated POST /api/upload. The body (the
// multipart provenance+file envelope) is fully buffered so retries can resend it.
func postOnce(ctx context.Context, target string, body []byte, contentType string) (*http.Response, error) {
	if err := apiBreaker.allow(); err != nil {
		recordDep(ctx, "hopper-api", "upload", "rejected", time.Time{})
		return nil, fmt.Errorf("hopper-api upload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		// Local build error: hopper was never contacted; don't move the breaker.
		return nil, fmt.Errorf("build hopper request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	hopper.Authorize(req)
	start := time.Now()
	resp, err := hopperClient.Do(req)
	if err != nil {
		apiBreaker.failure()
		recordDep(ctx, "hopper-api", "upload", "error", start)
		return nil, fmt.Errorf("hopper request: %w", err)
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		apiBreaker.failure()
		recordDep(ctx, "hopper-api", "upload", "error", start)
	} else {
		apiBreaker.success()
		recordDep(ctx, "hopper-api", "upload", "ok", start)
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
// (sha -> uploadState). lookupResult renders a pending "analyzing" page for
// these instead of a 404 during the window before hopper has the sample row or
// litmus has cached a verdict, and an explicit failure page once ingestion has
// given up.
var uploadsInFlight sync.Map

// uploadState is what uploadsInFlight holds for one sha. FailedAt is zero while
// ingestion is in flight and set when both paths gave up — the entry outlives
// the ingestion in that case so /file/<sha> can explain what happened instead of
// 404ing a hash the user handed us seconds ago.
type uploadState struct {
	FailedAt time.Time
	Filename string
}

// uploadFailureTTL bounds how long a failed ingestion stays visible on the
// detail page. Long enough to cover the redirect plus a few manual reloads,
// short enough that a later successful re-upload of the same sha isn't
// shadowed by the stale failure.
const uploadFailureTTL = 15 * time.Minute

// markUploadFailed records a terminal ingestion failure and sweeps expired
// entries. The sweep is O(entries) but runs only on failure, and the map holds
// at most one entry per in-flight or recently-failed upload.
func markUploadFailed(sha, filename string, now time.Time) {
	uploadsInFlight.Store(sha, uploadState{Filename: filename, FailedAt: now})
	uploadsInFlight.Range(func(k, v any) bool {
		if st, ok := v.(uploadState); ok && !st.FailedAt.IsZero() && now.Sub(st.FailedAt) > uploadFailureTTL {
			uploadsInFlight.Delete(k)
		}
		return true
	})
}

// uploadFailedError signals that a sample's background ingestion finished with
// neither path accepting it. Handlers render a "couldn't analyze" page rather
// than a 404, which would wrongly invite the user to retry an upload that just
// failed deterministically.
type uploadFailedError struct {
	SHA      string
	Filename string
}

func (e *uploadFailedError) Error() string { return "upload ingestion failed for " + e.SHA }

// litmusEnvelope is the subset of litmus /analyze's {"ml":…,"raw":…} response
// that prism forwards to hopper. Error is set when litmus reports a structured
// failure.
type litmusEnvelope struct {
	Error string          `json:"error"`
	ML    json.RawMessage `json:"ml"`
	LLM   json.RawMessage `json:"llm"`
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
	log := logger.With("sha256", sha, "filename", filename)

	var (
		wg                 sync.WaitGroup
		litmusOK, hopperOK bool
		env                *litmusEnvelope
		analyzeMs          int64
	)

	wg.Go(func() {
		if _, err := uploadToHopper(ctx, buf, sha, filename, log); err != nil {
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
		// Keep the sha marked so /file/<sha> can say the analysis failed. A bare
		// delete here leaves the detail page unable to tell a just-failed upload
		// from an unknown hash, which is what produced a "Result not found" 404
		// telling the user to re-upload a file that had just deterministically
		// failed to ingest.
		log.Error("UPLOAD INGESTION FAILED: neither litmus nor hopper accepted the sample; it is not viewable")
		markUploadFailed(sha, filename, time.Now())
		return
	}
	uploadsInFlight.Delete(sha)
}

// cacheLitmusResult stores a litmus verdict in prism's result cache so
// /file/<sha> renders without waiting on (or needing) hopper. The litmus
// /analyze envelope is already the {ml,llm,raw} shape prism stores as RawLitmus.
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
	if json.Valid(env.LLM) {
		envelope["llm"] = env.LLM
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
// (one part named "file") and returns the ml/llm/raw sections of the response
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
	start := time.Now()
	resp, err := litmusClient.Do(req)
	if err != nil {
		recordDep(ctx, "litmus", "analyze", "error", start)
		return nil, fmt.Errorf("litmus request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort
	rd := io.LimitReader(resp.Body, maxLitmusResponseBytes)
	if resp.StatusCode != http.StatusOK {
		recordDep(ctx, "litmus", "analyze", "error", start)
		snippet, _ := io.ReadAll(io.LimitReader(rd, 1024)) //nolint:errcheck // diagnostics only
		return nil, fmt.Errorf("litmus status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	recordDep(ctx, "litmus", "analyze", "ok", start)
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
	LLM        json.RawMessage `json:"llm,omitempty"`
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
		recordDep(ctx, "hopper-api", "result", "rejected", time.Time{})
		return fmt.Errorf("hopper-api result: %w", err)
	}
	body, err := json.Marshal(hopperResultRequest{
		SHA256:     sha,
		Worker:     litmusWorkerName,
		ML:         env.ML,
		LLM:        env.LLM,
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
	hopper.Authorize(req)
	start := time.Now()
	resp, err := hopperClient.Do(req)
	if err != nil {
		apiBreaker.failure()
		recordDep(ctx, "hopper-api", "result", "error", start)
		return fmt.Errorf("hopper request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort
	if resp.StatusCode >= http.StatusInternalServerError {
		apiBreaker.failure()
		recordDep(ctx, "hopper-api", "result", "error", start)
	} else {
		apiBreaker.success()
		recordDep(ctx, "hopper-api", "result", "ok", start)
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // diagnostics only
		return fmt.Errorf("hopper /api/result status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

// hopperRescanURL builds the absolute URL of hopper's POST /api/rescan/{sha256}
// endpoint from the admin-configured hopper-api host. Mirrors hopperFileURL.
func hopperRescanURL(sha string) string {
	base := strings.TrimSpace(hopperAPIAddr)
	if base == "" {
		base = defaultHopperAPIAddr
	}
	if !strings.Contains(base, "://") {
		base = "http://" + base
	}
	u, err := url.Parse(base)
	if err != nil {
		return "http://" + defaultHopperAPIAddr + "/api/rescan/" + sha
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/api/rescan/" + sha
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// postRescanToHopper POSTs to hopper's /api/rescan/{sha256} so the sample is
// re-queued on the master. The same per-dependency breaker that guards other
// hopper-api calls applies. hopper's 409 (sample not eligible, or within its
// re-queue cooldown) maps to errSampleNotEligible so the handler surfaces the
// familiar user-facing message; any other non-200 is a generic error. A single
// attempt is enough — the breaker sheds load when hopper-api is down and the
// user can simply click again.
func postRescanToHopper(ctx context.Context, sha string) error {
	if err := apiBreaker.allow(); err != nil {
		recordDep(ctx, "hopper-api", "rescan", "rejected", time.Time{})
		return fmt.Errorf("hopper-api rescan: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hopperRescanURL(sha), http.NoBody)
	if err != nil {
		// Local build error: hopper was never contacted; don't move the breaker.
		return fmt.Errorf("build request: %w", err)
	}
	hopper.Authorize(req)
	start := time.Now()
	resp, err := hopperClient.Do(req)
	if err != nil {
		apiBreaker.failure()
		recordDep(ctx, "hopper-api", "rescan", "error", start)
		return fmt.Errorf("hopper request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() //nolint:errcheck // best-effort
	if resp.StatusCode >= http.StatusInternalServerError {
		apiBreaker.failure()
		recordDep(ctx, "hopper-api", "rescan", "error", start)
	} else {
		apiBreaker.success()
		recordDep(ctx, "hopper-api", "rescan", "ok", start)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusConflict:
		return errSampleNotEligible
	default:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024)) //nolint:errcheck // diagnostics only
		return fmt.Errorf("hopper /api/rescan status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
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
	data.PURL = purlDisplay(res)
	data.PURLIndexURL = purlIndexURL(res.PURLBase)
	// The raw filename feeds the headline (data.Filename is pre-escaped and
	// the template escapes again on output).
	data.Headline = identityHeadline(res.RegistryTitle, res.Package, filename, res.Version)
	data.RegistryDesc = truncDesc(res.RegistryDesc)
	data.Users = formatCount(res.RegistryDownloads)
	if !res.CreatedAt.IsZero() {
		data.FirstSeenAt = res.CreatedAt.Format("2 Jan 2006 15:04 UTC")
		data.FirstSeenAgo = timeAgo(time.Since(res.CreatedAt))
	}
	// Provenance draws only on the stored sample fields above, so it is
	// built here — before the litmus parse — and survives the parse-failure
	// early return below. filename is passed raw; the template escapes it.
	data.Provenance = provenanceGroups(sha256Hex, filename, res)

	// Parse raw litmus response envelope: {"ml": {...}, "llm": {...}, "raw": {...}}.
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

	// Surface the optional LLM interpretation in the hero when one ran (only a
	// subset of samples get it). The `llm` section is a top-level envelope
	// sibling of `ml`, not nested inside it. Gate on a non-empty rationale so a
	// pass that failed (carries only `error`) doesn't render an empty line.
	var llm llmInterpretation
	if len(fullResp.LLM) > 0 {
		if err := json.Unmarshal(fullResp.LLM, &llm); err != nil {
			logger.Debug("failed to parse llm section", "sha256", sha256Hex, "error", err)
		} else if llm.Interpretation != "" {
			data.LLMInterpretation = llm.Interpretation
			data.LLMConfidence = int(llm.Conf*100 + 0.5)
			data.MetaDesc = llm.Interpretation
		}
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

	// Flag archive/compressed containers so the content view never windows a
	// trait against their packed bytes (it belongs to a member inside).
	markContainers(report.Files)

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

	totalFindings := 0
	for i := range report.Files {
		totalFindings += len(report.Files[i].Findings)
	}

	data.FindingCount = strconv.Itoa(totalFindings)

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

	// LevelConfidence is the level-derived hostile-confidence percentage shown on
	// the litmus badge for v4/v5 envelopes (v6/v7 carry it directly).
	if mlResp.V != "6" && mlResp.V != "7" {
		data.LevelConfidence = levelConfidence(data.Level)
	}

	// VerdictTip is the hover text for the level percentage badge. The badge only
	// renders for a non-benign level (Level set and != -1), so build the tip for
	// that case. When the LLM interpretation moved the verdict off the raw ML
	// class, the tip names the disagreement; otherwise it states the level.
	data.VerdictTip = verdictTip(data.Level, data.LevelConfidence, res.Classification, mlResp.RawClass, llm)

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

	// Sort archive files by trait criticality first, then ML probability as a
	// tiebreak, so every tab leads with the most dangerous member files — not the
	// ones that merely scored high on the ML model while carrying only
	// baseline/component traits. (Criticality and probability are distinct
	// signals; sorting on probability alone buried notable/suspicious members
	// below low-criticality spam and could even truncate them away.) Depth-0 (the
	// archive container itself) stays first regardless. maxCritInFile re-scans the
	// file's findings; the archive's file count is bounded, so this stays cheap.
	sort.SliceStable(report.Files, func(i, j int) bool {
		if report.Files[i].Depth == 0 {
			return true
		}
		if report.Files[j].Depth == 0 {
			return false
		}
		ci, cj := maxCritInFile(&report.Files[i]), maxCritInFile(&report.Files[j])
		if ci != cj {
			return ci > cj
		}
		return report.Files[i].Probability > report.Files[j].Probability
	})

	// For large archives, truncate to the top 100 files — now genuinely the most
	// critical, since the sort above leads with criticality. The depth-0
	// container is always first (guaranteed by the sort above).
	const maxArchiveFiles = 100
	if len(report.Files) > maxArchiveFiles {
		report.Files = report.Files[:maxArchiveFiles]
	}

	// Build structured data for the Traits tab.
	data.FileFindings = buildStructuredFindings(report.Files)
	data.ArchiveCategories, data.ArchiveTraitTotal, data.ArchiveTraitShown = aggregateArchiveCategories(report.Files)

	// The File tab renders cleave's per-file context view and, when present,
	// becomes the default tab. It is populated only for reports carrying
	// current-format context, so legacy samples keep Traits as the default.
	var omitted contentOmitted
	data.FileViews, data.TopTraits, omitted = buildFileViews(report.Files)
	if omitted.Files > 0 {
		data.FilesOmitted = omitted.Files
		data.ResultsOmitted = omitted.Results
		data.FilesShownLimit = maxFilesShown
	}
	// Social-preview fallback: with no LLM rationale, the strongest trait's
	// description is the next-best one-line answer to "why is this here".
	if data.MetaDesc == "" && len(data.TopTraits) > 0 {
		data.MetaDesc = data.TopTraits[0].Desc
	}
	if srcCh, hexCh := contentLocCh(data.FileViews); srcCh > 0 || hexCh > 0 {
		//nolint:gosec // G203: both widths are ints computed from rendered context, never user input
		data.ContentLocStyle = template.HTMLAttr(fmt.Sprintf(`style="--ctx-loc-src-ch:%d;--ctx-loc-hex-ch:%d"`, srcCh, hexCh))
	}

	// IsArchive reflects the underlying file set, not the findings count: an
	// archive whose children are all clean still has multiple files and
	// should render the aggregated archive Traits tab.
	data.IsArchive = len(report.Files) > 1

	// Containment/provenance hierarchy from the members' pid edges — the
	// archive → member → fetched-dependency structure. The Structure tab renders
	// only when the root has children; buildFileTree folds large and fetched
	// subtrees shut so a 10k-member dependency never floods the initial render.
	// Older payloads predate pid and would yield a flat forest the tab hides
	// anyway, so the build (and its sort) is skipped entirely for them.
	if reportHasPid(report.Files) {
		data.Tree = buildFileTree(report.Files)
		data.HasTree = len(data.Tree) > 0 && len(data.Tree[0].Children) > 0
	}

	// Flagged fetched dependencies: external content the sample references
	// whose own scan classified suspicious or hostile — the panel answers "why
	// is this sample elevated" at a glance. Benign dependencies stay out of it
	// (they remain visible in the Structure tab's fetched chips).
	data.FlaggedDeps, data.FlaggedDepsHidden = flaggedDeps(report.Files)

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
	data.CompoundURL = "/stream?m=" + url.QueryEscape(data.FormulaQuery)
	data.Badges = resultBadges(data.TopTraits, report.Files)
	data.Findings, data.FindingsHidden = fallbackFindings(data.FileViews, report.Files)
	data.ShortProv = shortProvenance(data.Provenance)
	// The drawing is the top-level file's own behaviours: an archive's members
	// each have their own, and stacking them would draw a graph no single file
	// has. Rendered at rail size here; the feed renders the same graph small.
	for i := range report.Files {
		if report.Files[i].Depth == 0 || i == len(report.Files)-1 {
			g := buildMaleculeGraph(&report.Files[i])
			data.MaleculeSVG = template.HTML(maleculeSVG(g, 196, 168)) //nolint:gosec // every dynamic value is escaped or from a fixed palette
			break
		}
	}
	data.Summary = data.LLMInterpretation
	if data.Summary == "" {
		counted := report.Files[0].Findings
		for i := range report.Files {
			if report.Files[i].Depth == 0 {
				counted = report.Files[i].Findings
				break
			}
		}
		members := 0
		for i := range report.Files {
			if report.Files[i].Depth > 0 {
				members++
			}
		}
		data.Summary = summaryLine(countFindings(counted), members, data.RiskLabel, data.LevelConfidence)
	}

	// The 3D molecule and the galaxy were retired in favour of the server-drawn
	// malecule above; nothing renders them any more. Building them cost a full
	// pass over every finding and string in the archive, marshalled ~90 KB per
	// page, and on a compacted archive ran a second time behind the members
	// fetch — all of it discarded. BuildGalaxy/BuildMalecule and their tests are
	// now unreferenced by the server and can go.

	return data
}

// buildStructuredFindings converts cleave findings into structured display data grouped by category.
// Findings are aggregated by directory path, keeping only the highest criticality/confidence per directory.

// maxCritInFile returns the highest criticality ordinal from a file's traits.
func maxCritInFile(f *cleaveFile) int {
	best := 0
	for i := range f.Findings {
		if f.Findings[i].Crit > best {
			best = f.Findings[i].Crit
		}
	}
	return best
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
	for i := range scored {
		byCat[scored[i].topLevel] = append(byCat[scored[i].topLevel], scored[i])
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
		for i := range items {
			fds[i] = items[i].display
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
// lexerCache memoizes chroma's filename-to-lexer lookup, which is far more
// expensive than it looks: lexers.Match globs the whole registry — hundreds of
// lexers, several filename patterns each — through path/filepath.Match. Called
// once per rendered line, as it was, it accounted for 90% of a five-second
// archive render. The answer depends only on the filename, and a page renders
// at most a handful of distinct ones.
var lexerCache sync.Map // filename -> cachedLexer

// cachedLexer wraps the result so a filename chroma has no lexer for caches as
// a hit holding nil, rather than repeating the registry scan every time.
type cachedLexer struct{ lexer chroma.Lexer }

// matchLexer returns the coalesced lexer for a filename, or nil when chroma has
// none. Coalescing happens once here too: it wraps the lexer, so doing it per
// call allocated a new wrapper for every line.
func matchLexer(filename string) chroma.Lexer {
	if v, ok := lexerCache.Load(filename); ok {
		if cached, isCached := v.(cachedLexer); isCached {
			return cached.lexer
		}
	}
	var lexer chroma.Lexer
	if matched := lexers.Match(filename); matched != nil {
		lexer = chroma.Coalesce(matched)
	}
	lexerCache.Store(filename, cachedLexer{lexer: lexer})
	return lexer
}

func highlightEvidence(evidence, filename string) []EvidenceToken {
	if evidence == "" || filename == "" {
		return nil
	}
	lexer := matchLexer(filename)
	if lexer == nil {
		return nil
	}
	iter, err := lexer.Tokenise(nil, evidence)
	if err != nil {
		return nil
	}
	var out []EvidenceToken
	for tok := iter(); tok != chroma.EOF; tok = iter() {
		// Evidence is a fragment, not a whole document, so a lexer's state
		// machine often loses context (e.g. JSON snippets that start mid-object
		// mark every ':' ',' '}' as chroma.Error). Those aren't real errors, so
		// render them as plain text rather than the style's red error span.
		class := chroma.StandardTypes[tok.Type]
		if tok.Type == chroma.Error {
			class = ""
		}
		out = append(out, EvidenceToken{Class: class, Text: tok.Value})
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

// contextIndex maps each full trait ID to the evidence rows derived from the
// file's findings by intersecting their Spans with ctx windows. The snippet is
// rendered the same way the Content tab shows it — the source line for text
// files, a compact hex+ascii dump for binary — so a trait's "evidence" column
// matches its context block. Returns nil when no ctx window carries decoded
// bytes (legacy files), so callers fall back to the inline-evidence path.
func contextIndex(file *cleaveFile) map[string][]evidenceRow {
	if !hasRichContext(file) {
		return nil
	}
	isHex := isBinaryType(file.FileType)
	idx := make(map[string][]evidenceRow)
	for i := range file.Findings {
		f := &file.Findings[i]
		if len(f.From) > 0 {
			// Inherited rollup: its spans are member-relative, so they don't
			// index against this file's own ctx. Attributed to its member by
			// aggregateArchiveCategories instead.
			continue
		}
		for _, sp := range f.Spans {
			text, ok := evidenceFromCtx(file.Ctx, sp[0], isHex)
			if !ok {
				continue // span lands in no decoded window
			}
			idx[f.ID] = append(idx[f.ID], evidenceRow{
				text:   text,
				offset: formatOffset(sp[0], isHex),
				hex:    isHex,
			})
		}
	}
	return idx
}

// evidenceFromCtx returns the matched snippet for a span: the source line for
// text files, a hex+ascii dump for binary — the same content the Content tab's
// context block renders. It reports false when no decoded window covers off.
func evidenceFromCtx(windows []contextWindow, off int64, isHex bool) (string, bool) {
	for i := range windows {
		win := &windows[i]
		if win.Data == nil {
			continue
		}
		base := win.byteBase()
		if off < base || off >= base+int64(len(win.Data)) {
			continue
		}
		if isHex {
			return hexDump(win.Data), true
		}
		return string(win.Data), true
	}
	return "", false
}

// hexDump renders bytes as the Content tab's hex view does in one line: the
// space-separated hex pairs, then the printable-ascii gutter (dots for
// non-printables).
func hexDump(b []byte) string {
	var hexCol, ascii strings.Builder
	for i, c := range b {
		if i > 0 {
			hexCol.WriteByte(' ')
		}
		fmt.Fprintf(&hexCol, "%02x", c)
		ascii.WriteString(printableByte(c))
	}
	return hexCol.String() + "  " + ascii.String()
}

// evidenceRows returns the match rows for a finding from the ctx index. Falls
// back to span offsets (paired with any legacy `loc` for back-attribution) when
// the ctx index has no entry — older envelopes whose findings carry spans/loc
// but no decoded ctx windows.
func evidenceRows(f finding, idx map[string][]evidenceRow) []evidenceRow {
	if rows := idx[f.ID]; len(rows) > 0 {
		return rows
	}
	rows := make([]evidenceRow, len(f.Spans))
	for i, sp := range f.Spans {
		rows[i] = evidenceRow{text: fmt.Sprintf("0x%x", sp[0])}
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

// archiveAgg accumulates one category bucket while aggregating an archive's
// findings: dedup'd match rows in insertion order, plus the strongest crit/conf
// and description seen for the bucket.
type archiveAgg struct {
	matches  map[string]*FindingMatch
	dirPath  string
	topLevel string
	desc     string
	order    []string
	crit     int
	conf     float64
}

// addMatch inserts a match (or bumps its count) under key mk, preserving first-
// seen order. build constructs the FindingMatch only on first insert.
func (a *archiveAgg) addMatch(mk string, build func() *FindingMatch) {
	if m, ok := a.matches[mk]; ok {
		m.Count++
		return
	}
	a.matches[mk] = build()
	a.order = append(a.order, mk)
}

// addRollupMatches attributes a v8 rollup finding to each embedded member it was
// inherited from (From): one match per member, carrying filename + location only
// (member bytes are omitted from the envelope, so there is no snippet). Container
// self-references are skipped.
func (a *archiveAgg) addRollupMatches(from []compactSource, idToFile map[int]*cleaveFile, containerSHAs map[string]bool) {
	for _, src := range from {
		member := idToFile[src.File]
		if member == nil || containerSHAs[member.SHA256] {
			continue
		}
		path := displayPath(member.Path)
		loc := sourceLoc(src)
		a.addMatch("\x00"+path+"\x00"+loc, func() *FindingMatch {
			return &FindingMatch{Path: path, Filename: extractBasename(path), Location: loc, Count: 1}
		})
	}
}

// addEvidenceMatches resolves a finding's evidence rows into (filename, location,
// evidence) matches. A row's legacy loc back-attributes a container rollup to the
// inner file that produced it; otherwise a finding on an inner file (depth>0) is
// attributed to that file. The archive container is never kept as a source — it's
// a rollup, not a real file — though its evidence text is retained.
func (a *archiveAgg) addEvidenceMatches(f finding, ctxIdx map[string][]evidenceRow, file *cleaveFile, pathToFile map[string]*cleaveFile, idToFile map[int]*cleaveFile, containerSHAs map[string]bool) {
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
			path = displayPath(file.Path)
			sha = file.SHA256
		}
		if containerSHAs[sha] {
			path, loc = "", ""
		}
		base := extractBasename(path)
		a.addMatch(ev+"\x00"+path+"\x00"+loc, func() *FindingMatch {
			return &FindingMatch{
				Evidence: ev, Path: path, Filename: base, Location: loc,
				Tokens: matchTokens(ev, base, row.hex), Count: 1,
			}
		})
	}
}

// aggregateArchiveCategories merges every file's findings into one category
// list, deduped by trait-ID directory prefix. Used by the archive Traits tab.
// Unlike per-file aggregation, this version attributes every aggregated trait
// back to the files that contributed, so the UI can expand a trait into
// "filename — location — evidence" rows.
func aggregateArchiveCategories(files []cleaveFile) (groups []CategoryGroup, total, shown int) {
	categoryNames := map[string]string{
		"objectives":      "Objectives",
		"micro-behaviors": "Micro-behaviors",
		"metadata":        "Metadata",
		"well-known":      "Well-known",
		"third_party":     "Third-party",
	}

	bucket := make(map[string]*archiveAgg)
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
		for fi := range file.Findings {
			f := &file.Findings[fi]
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
				agg = &archiveAgg{
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
			// A v8 rollup is attributed to the members it was inherited from;
			// otherwise resolve the finding's own evidence rows.
			if len(f.From) > 0 {
				agg.addRollupMatches(f.From, idToFile, containerSHAs)
				continue
			}
			agg.addEvidenceMatches(*f, ctxIdx, file, pathToFile, idToFile, containerSHAs)
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

		for fi := range file.Findings {
			f := &file.Findings[fi]
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
			for _, row := range evidenceRows(*f, ctxIdx) {
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
	LLM json.RawMessage `json:"llm"`
	Raw json.RawMessage `json:"raw"`
}

// llmInterpretation is the optional `llm` object a litmus envelope carries when
// the LLM interpretation pass ran. The pass is gated (on ML probability), so it
// is present only for a subset of samples — typically suspicious/hostile.
// Interpretation is the human-readable rationale shown in the hero; Grade and
// Outcome carry the LLM's raw verdict and the final blended verdict; the rest
// mirror scan's interpret::Interpretation. All fields are absent (zero) when no
// pass ran.
type llmInterpretation struct {
	Grade          string  `json:"grade"`   // LLM's raw verdict; "" when the call failed
	Outcome        string  `json:"outcome"` // final blended verdict
	Interpretation string  `json:"interpretation"`
	Model          string  `json:"model"`
	Error          string  `json:"error"` // failure reason; "" on success
	Conf           float64 `json:"conf"`  // blended confidence [0,1]
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
	// RawClass is the model's *pre-interpretation* verdict — the most severe
	// class across the per-route detection modules (`ml.mods[].cls`), before any
	// LLM blend overwrote the top-level level. nil when the envelope carries no
	// `mods` (v<7, or cached rows). Used to surface an ML/LLM disagreement.
	RawClass *int `json:"-"`
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
		// Mods is the per-route detection output (v7). Each `cls` is that route's
		// raw class; the sample's raw ML verdict is the most severe across them.
		Mods []struct {
			Cls int `json:"cls"`
		} `json:"mods"`
		Prob float64 `json:"prob"` // raw model score used for the top-level decision
	}
	if err := json.Unmarshal(data, &current); err != nil {
		return err
	}
	if len(current.Mods) > 0 {
		raw := current.Mods[0].Cls
		for _, m := range current.Mods[1:] {
			if m.Cls > raw {
				raw = m.Cls
			}
		}
		r.RawClass = &raw
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

// CriticalLevel is prism's single consumer-side cutoff between hostile and
// suspicious on the per-100M-benigns scale. A v6/v7 envelope's level is the
// strictest grid level at which the file fires; level <= CriticalLevel means it
// fires at or below our critical line (hostile), higher levels mean it only
// fires in the noisier tail (suspicious, up to SuspiciousCeiling), and `-1`
// means it never fires (benign). Both derivations (envelopeClass and
// classFromLevel) use this one constant — there is no second cutoff.
//
// Set to L25, matching scan's DEFAULT_SEVERITY_LEVEL operating point (the level
// the model is currently deployed and calibrated at; tightened from L50 in
// 2026-07 to the knee of the hostile curve, just below the sharp L30->L40 FP
// cliff). See collimator/src/collimator/thresholds/__init__.py for the cross-repo group.
const CriticalLevel = 25

// SuspiciousCeiling is the loosest fired-level (FP per 100M benigns) that still
// reads as suspicious. Above it a firing is benign informational noise rather
// than a suspicious verdict. Set to L3000 — an EXPERIMENTAL widening (2026-07),
// the loosest robustly-stable point on the calibrate curve (recall peaks at L4000
// then collapses ~8pp at L5000). Overrides the prior L100 precision elbow from
// hopper's fired-level analysis (L250 and looser add more false positives than
// true positives); re-measure and tighten back if the suspicious bucket floods.
// Mirrors scan's SUSPICIOUS_LEVEL_CEILING and hopper/promoter's SuspiciousCeiling;
// keep the cross-repo group in sync.
const SuspiciousCeiling = 3000

// envelopeClass derives the legacy 0/1/2 classification from a v6/v7 envelope's
// level field. -1 → benign (0); 0..=CriticalLevel → hostile (2); CriticalLevel <
// l <= SuspiciousCeiling → suspicious (1); looser → benign (0, past the elbow);
// nil/null (manual mode, no level info) → hostile (2), fail-safe.
func envelopeClass(l *int) int {
	if l == nil {
		return 2
	}
	switch {
	case *l < 0:
		return 0
	case *l <= CriticalLevel:
		return 2
	case *l <= SuspiciousCeiling:
		return 1
	default:
		return 0
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
// 0..=CriticalLevel are hostile; CriticalLevel < l <= SuspiciousCeiling are
// suspicious; looser levels are benign (past the L100 precision elbow). Lower
// levels fire at stricter false-positive cutoffs, so they carry higher
// confidence. Uses the same CriticalLevel constant as envelopeClass — one
// cutoff, no divergence.
func classFromLevel(l *int) int {
	if l == nil {
		return 2 // hostile under manual thresholds
	}
	switch v := *l; {
	case v == -1:
		return 0 // benign sentinel
	case v <= CriticalLevel:
		return 2 // hostile
	case v <= SuspiciousCeiling:
		return 1 // suspicious
	default:
		return 0 // benign: looser than the ceiling
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
