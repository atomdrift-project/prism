package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The challenge is a human bypass for the rate limiter: a visitor who trips the
// 429 (see rateLimiter) can solve a small arithmetic problem to earn a pass
// cookie and keep browsing, while automated floods that ignore the page stay
// shed. It is deliberately NOT a strong CAPTCHA — a determined scraper can solve
// arithmetic — only a courtesy exit for real people who browse faster than the
// configured rate.
//
// Everything is stateless and signed with the existing csrfKey: the presented
// problem carries an HMAC over its own answer, and a solved pass carries an HMAC
// over its expiry. Both are bound to the client IP so a pass can't be farmed by
// one solver and replayed across a bot fleet on other IPs.
const (
	passCookieName  = "prism_pass"
	passMaxAge      = time.Hour        // unthrottled browsing earned by one solve
	challengeMaxAge = 10 * time.Minute // how long a presented problem stays solvable
)

// passMAC binds the client IP and expiry into the pass-cookie signature.
func passMAC(ip string, exp int64) string {
	mac := hmac.New(sha256.New, csrfKey[:])
	mac.Write([]byte(ip))
	mac.Write([]byte{0})
	mac.Write([]byte(strconv.FormatInt(exp, 10)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// issuePass sets a signed, IP-bound, time-limited cookie that hasValidPass
// accepts. SameSite=Lax so it rides the top-level navigation back to the page
// the visitor was trying to reach.
func issuePass(w http.ResponseWriter, r *http.Request) {
	exp := time.Now().Add(passMaxAge).Unix()
	http.SetCookie(w, &http.Cookie{
		Name:     passCookieName,
		Value:    strconv.FormatInt(exp, 10) + "." + passMAC(clientIP(r), exp),
		Path:     "/",
		HttpOnly: true,
		Secure:   publicMode || requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(passMaxAge / time.Second),
	})
}

// hasValidPass reports whether the request carries an unexpired, IP-matched
// pass, letting it skip rate limiting.
func hasValidPass(r *http.Request) bool {
	c, err := r.Cookie(passCookieName)
	if err != nil {
		return false
	}
	exp, mac, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	expUnix, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || time.Now().Unix() > expUnix {
		return false
	}
	return hmac.Equal([]byte(mac), []byte(passMAC(clientIP(r), expUnix)))
}

// challengeMAC signs the expected answer and expiry (IP-bound) so a submission
// can be verified without any server-side record of the problem issued.
func challengeMAC(ip string, answer, exp int64) string {
	mac := hmac.New(sha256.New, csrfKey[:])
	mac.Write([]byte(ip))
	mac.Write([]byte{0})
	mac.Write([]byte(strconv.FormatInt(answer, 10)))
	mac.Write([]byte{0})
	mac.Write([]byte(strconv.FormatInt(exp, 10)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// wantsChallenge reports whether an over-limit request should get the solvable
// challenge page rather than a bare 429: only browser navigations (a GET asking
// for HTML). Scripts and file-download bots get the plain 429.
func wantsChallenge(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
}

// randOperand returns a small positive integer for the arithmetic problem.
// crypto/rand keeps successive problems unpredictable; on the vanishingly rare
// read error it degrades to a trivial operand rather than failing the request.
func randOperand() int64 {
	n, err := rand.Int(rand.Reader, big.NewInt(9))
	if err != nil {
		return 1
	}
	return n.Int64() + 1 // 1..9
}

// serveChallenge renders the interstitial with status 429. The page is
// CSP-clean: no inline script or style, same-origin image and form only, so it
// renders under prism's strict Content-Security-Policy. retryAfter feeds the
// Retry-After header for the non-browser clients that read it.
func serveChallenge(w http.ResponseWriter, r *http.Request, retryAfter time.Duration) {
	a, b := randOperand(), randOperand()
	exp := time.Now().Add(challengeMaxAge).Unix()
	token := strconv.FormatInt(exp, 10) + "." + challengeMAC(clientIP(r), a+b, exp)
	next := sanitizeNext(r.URL.RequestURI())
	logger.Info("challenge shown", "client_ip", clientIP(r), "next", next)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())+1))
	w.WriteHeader(http.StatusTooManyRequests)
	_ = challengeTmpl.Execute(w, challengeData{ //nolint:errcheck // response already committed
		A: a, B: b, Token: token, Next: next,
	})
}

// handleChallenge serves a fresh problem on GET and verifies an answer on POST.
// A correct, unexpired, IP-matched answer issues a pass and redirects back to
// the originally requested page; anything else re-presents a new problem. This
// route is exempt from rate limiting (see rateLimitExempt) so a throttled human
// can always reach it to solve.
func handleChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		serveChallenge(w, r, 0)
		return
	}
	if challengeSolved(r, r.PostFormValue("token"), r.PostFormValue("answer")) {
		issuePass(w, r)
		logger.Info("challenge solved", "client_ip", clientIP(r))
		http.Redirect(w, r, sanitizeNext(r.PostFormValue("next")), http.StatusSeeOther)
		return
	}
	logger.Debug("challenge failed", "client_ip", clientIP(r))
	serveChallenge(w, r, 0)
}

// challengeSolved verifies a submitted answer against its signed token: correct
// shape, unexpired, and an IP-bound HMAC that matches the answer the visitor
// typed. No server-side problem store is consulted.
func challengeSolved(r *http.Request, token, answerStr string) bool {
	exp, mac, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	expUnix, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || time.Now().Unix() > expUnix {
		return false
	}
	answer, err := strconv.ParseInt(strings.TrimSpace(answerStr), 10, 64)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(mac), []byte(challengeMAC(clientIP(r), answer, expUnix)))
}

// sanitizeNext keeps only local, single-slash paths so the post-solve redirect
// cannot be turned into an open redirect to another origin.
func sanitizeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}

type challengeData struct {
	Token string
	Next  string
	A, B  int64
}

// challengeTmpl is the interstitial page. html/template escapes every field;
// the page uses only a same-origin image and a same-origin POST form so it
// satisfies the strict CSP without needing a nonce.
var challengeTmpl = template.Must(template.New("challenge").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Are you a robot?</title>
<link rel="stylesheet" href="/static/challenge.css">
</head>
<body>
<main>
<img src="/static/robot.jpg" alt="A dizzy little robot, spinning">
<h1>Whoa there, speed&nbsp;demon</h1>
<p>You're loading pages faster than our little robot can carry them, and now
it's gotten dizzy. Prove there's a human at the wheel and we'll wave you through.</p>
<form method="POST" action="/_/challenge">
<input type="hidden" name="token" value="{{.Token}}">
<input type="hidden" name="next" value="{{.Next}}">
<label>Quick, while the robot recovers — what is {{.A}} + {{.B}}?
<input type="text" name="answer" inputmode="numeric" autocomplete="off" autofocus></label>
<button type="submit">I'm (probably) human</button>
</form>
</main>
</body>
</html>
`))
