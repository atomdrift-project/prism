package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func reqWithIP(method, target, ip string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Header.Set("Cf-Connecting-Ip", ip)
	return r
}

func TestSanitizeNext(t *testing.T) {
	cases := map[string]string{
		"/file/abc":           "/file/abc",
		"/":                   "/",
		"":                    "/",
		"//evil.com":          "/",
		"http://evil.com":     "/",
		"javascript:alert(1)": "/",
	}
	for in, want := range cases {
		if got := sanitizeNext(in); got != want {
			t.Errorf("sanitizeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestChallengeSolve(t *testing.T) {
	r := reqWithIP(http.MethodGet, "/x", "1.1.1.1")
	exp := time.Now().Add(challengeMaxAge).Unix()
	token := strconv.FormatInt(exp, 10) + "." + challengeMAC(clientIP(r), 7, exp) // 3 + 4

	if !challengeSolved(r, token, "7") {
		t.Error("correct answer should solve")
	}
	if challengeSolved(r, token, "8") {
		t.Error("wrong answer must not solve")
	}
	if challengeSolved(reqWithIP(http.MethodGet, "/x", "2.2.2.2"), token, "7") {
		t.Error("token is IP-bound; another IP must not solve it")
	}
	expired := time.Now().Add(-time.Minute).Unix()
	expiredTok := strconv.FormatInt(expired, 10) + "." + challengeMAC(clientIP(r), 7, expired)
	if challengeSolved(r, expiredTok, "7") {
		t.Error("expired token must not solve")
	}
	if challengeSolved(r, strconv.FormatInt(exp, 10)+".tampered", "7") {
		t.Error("bad signature must not solve")
	}
}

func TestPassCookieRoundTrip(t *testing.T) {
	w := httptest.NewRecorder()
	issuePass(w, reqWithIP(http.MethodGet, "/x", "9.9.9.9"))
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != passCookieName {
		t.Fatalf("expected one %s cookie, got %v", passCookieName, cookies)
	}

	same := reqWithIP(http.MethodGet, "/y", "9.9.9.9")
	same.AddCookie(cookies[0])
	if !hasValidPass(same) {
		t.Error("freshly issued pass should be valid for the same IP")
	}

	other := reqWithIP(http.MethodGet, "/y", "8.8.8.8")
	other.AddCookie(cookies[0])
	if hasValidPass(other) {
		t.Error("pass is IP-bound; a different IP must be rejected")
	}
}

func TestChallengeBypassEndToEnd(t *testing.T) {
	rl := newRateLimiter(1, time.Minute)
	h := rl.limit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	browser := func(cookie *http.Cookie) *httptest.ResponseRecorder {
		r := reqWithIP(http.MethodGet, "/file/x", "5.5.5.5")
		r.Header.Set("Accept", "text/html")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	if w := browser(nil); w.Code != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", w.Code)
	}
	// Over-limit browser navigation gets the solvable challenge page.
	w := browser(nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit browser: got %d, want 429", w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "/_/challenge") || !strings.Contains(body, "robot.jpg") {
		t.Error("challenge page should contain the form action and robot image")
	}

	// A valid pass cookie bypasses the limiter even while over the rate.
	pw := httptest.NewRecorder()
	issuePass(pw, reqWithIP(http.MethodGet, "/x", "5.5.5.5"))
	if w := browser(pw.Result().Cookies()[0]); w.Code != http.StatusOK {
		t.Fatalf("with a valid pass, an over-limit request should pass: got %d", w.Code)
	}
}

func TestNonBrowserGetsPlain429(t *testing.T) {
	rl := newRateLimiter(1, time.Minute)
	h := rl.limit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	call := func() *httptest.ResponseRecorder {
		// No Accept: text/html — a scripted / download-bot client.
		r := reqWithIP(http.MethodGet, "/file/x.dl", "7.7.7.7")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	call() // consume the single token
	w := call()
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", w.Code)
	}
	if strings.Contains(w.Body.String(), "/_/challenge") {
		t.Error("non-browser client should get a bare 429, not the challenge page")
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("plain 429 should carry Retry-After")
	}
}
