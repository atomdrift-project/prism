package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/atomdrift-project/hopper"
)

const shaRouteTestSHA = "dd46efaa38534ef67370ac3ebc6151e4cf475fdb4bb68f8e2003b432d11d92c2"

func TestAnswerFor(t *testing.T) {
	ptr := func(s string) *string { return &s }
	level := func(n int) *int { return &n }
	analyzed := func(fires *int) *hopper.LookupRecord {
		return &hopper.LookupRecord{
			SHA256:        ptr(shaRouteTestSHA),
			PURL:          ptr("pkg:npm/left-pad@1.3.0"),
			FiresAt:       fires,
			EngineVersion: ptr("2.8.0"),
			AnalyzedAt:    ptr("2026-08-01T00:00:00Z"),
			State:         hopper.StateAnalyzed,
			Findings:      []hopper.LookupFinding{{ID: "objectives/execution/shell/bash", Crit: 5}},
		}
	}
	tests := []struct {
		name     string
		rec      *hopper.LookupRecord
		err      error
		budget   int
		status   string
		severity string
		cause    string
	}{
		{"nothing known", nil, hopper.ErrNotFound, 25, "unanalyzed", "unknown", ""},
		{"store unreachable", nil, errors.New("dial tcp: refused"), 25, "unavailable", "unknown", "unreachable"},
		{"held but not judged", &hopper.LookupRecord{SHA256: ptr(shaRouteTestSHA), State: hopper.StatePending, Findings: []hopper.LookupFinding{}}, nil, 25, "unanalyzed", "unknown", ""},
		{"no level applies", analyzed(nil), nil, 25, "unanalyzed", "unknown", ""},
		{"never fires", analyzed(level(-1)), nil, 25, "analyzed", "benign", ""},
		{"within budget", analyzed(level(10)), nil, 25, "analyzed", "hostile", ""},
		{"at budget", analyzed(level(25)), nil, 25, "analyzed", "hostile", ""},
		{"past a strict budget", analyzed(level(10)), nil, 5, "analyzed", "suspicious", ""},
		{"at the suspicious ceiling", analyzed(level(2500)), nil, 25, "analyzed", "suspicious", ""},
		// Where scan places a verdict a benign read cleared from L0: just past
		// its band, so it must read benign here too, not suspicious.
		{"just past the suspicious ceiling", analyzed(level(2501)), nil, 25, "analyzed", "benign", ""},
		{"the old fixed ceiling", analyzed(level(3000)), nil, 25, "analyzed", "benign", ""},
		{"past the suspicious ceiling", analyzed(level(5000)), nil, 25, "analyzed", "benign", ""},
		// The ceiling scales with the budget, as scan's does with -l.
		{"past a strict budget's ceiling", analyzed(level(1001)), nil, 10, "analyzed", "benign", ""},
		{"within a loose budget's ceiling", analyzed(level(5000)), nil, 100, "analyzed", "suspicious", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := answerFor(shaRouteTestSHA, tt.rec, tt.err, tt.budget)
			if a.Status != tt.status || a.Severity != tt.severity || a.Cause != tt.cause {
				t.Errorf("got status=%q severity=%q cause=%q, want %q %q %q", a.Status, a.Severity, a.Cause, tt.status, tt.severity, tt.cause)
			}
			if a.SHA256 != shaRouteTestSHA {
				t.Errorf("sha256 = %q, want %q", a.SHA256, shaRouteTestSHA)
			}
			if a.Findings == nil {
				t.Error("findings is nil; the contract is an empty array")
			}
			if a.Status != "analyzed" && (a.FiresAt != nil || a.EngineVersion != "" || len(a.Findings) != 0) {
				t.Errorf("a %s answer carries a verdict: %+v", a.Status, a)
			}
		})
	}
}

func TestParseBudget(t *testing.T) {
	for _, tt := range []struct {
		raw  string
		want int
		ok   bool
	}{
		{"", 25, true},
		{"0", 0, true},
		{"250", 250, true},
		{"3000", 3000, true},
		{"3001", 0, false},
		{"-1", 0, false},
		{"2.5", 0, false},
		{"lots", 0, false},
	} {
		got, ok := parseBudget(tt.raw)
		if got != tt.want || ok != tt.ok {
			t.Errorf("parseBudget(%q) = %d, %v; want %d, %v", tt.raw, got, ok, tt.want, tt.ok)
		}
	}
}

// With no hopper connected, a non-browser is told "unavailable" in a 200,
// never an HTML error page it cannot read.
func TestSHARouteAnswersScriptsWithJSON(t *testing.T) {
	mux := newMux()
	for _, path := range []string{"/" + shaRouteTestSHA, "/" + strings.ToUpper(shaRouteTestSHA)} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		req.Header.Set("Accept", "*/*")
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rr.Code)
		}
		if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		if v := rr.Header().Get("Vary"); v != "Accept" {
			t.Errorf("Vary = %q, want Accept", v)
		}
		var got map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("body is not JSON: %v: %s", err, rr.Body)
		}
		if got["status"] != "unavailable" || got["sha256"] != shaRouteTestSHA || got["severity"] != "unknown" {
			t.Errorf("body = %s", rr.Body)
		}
		if findings, ok := got["findings"].([]any); !ok || len(findings) != 0 {
			t.Errorf("findings = %v, want []", got["findings"])
		}
	}
}

func TestSHARouteRefusesABadBudget(t *testing.T) {
	rr := httptest.NewRecorder()
	newMux().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/"+shaRouteTestSHA+"?false_positive_budget=9999", http.NoBody))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"code":"invalid_false_positive_budget"`) {
		t.Errorf("body = %s", rr.Body)
	}
}

// A browser at /{sha256} gets the same HTML the detail page serves; with no
// hopper connected that is the error page, not JSON.
func TestSHARouteServesBrowsersHTML(t *testing.T) {
	errorTemplate = parseForTest(t, "error.html")
	t.Cleanup(func() { errorTemplate = nil })
	prev := cache
	cache = openNullCache[storedResult]("result cache")
	t.Cleanup(func() { cache = prev })

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+shaRouteTestSHA, http.NoBody)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	newMux().ServeHTTP(rr, req)
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

// A single segment that is not a digest is still an ecosystem.
func TestSHARouteLeavesEcosystemsAlone(t *testing.T) {
	rr := httptest.NewRecorder()
	newMux().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/npm", http.NoBody))
	if rr.Code != http.StatusMovedPermanently || rr.Header().Get("Location") != "/npm/" {
		t.Errorf("GET /npm = %d %q, want 301 /npm/", rr.Code, rr.Header().Get("Location"))
	}
}

// Old /file/{sha256} page links land on /{sha256}, query intact.
func TestLegacyFileRouteRedirects(t *testing.T) {
	tests := []struct{ path, want string }{
		{"/file/" + shaRouteTestSHA, "/" + shaRouteTestSHA},
		{"/file/" + strings.ToUpper(shaRouteTestSHA) + "?refresh=1", "/" + shaRouteTestSHA + "?refresh=1"},
	}
	for _, tt := range tests {
		rr := httptest.NewRecorder()
		newMux().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, tt.path, http.NoBody))
		if rr.Code != http.StatusMovedPermanently || rr.Header().Get("Location") != tt.want {
			t.Errorf("GET %s = %d %q, want 301 %q", tt.path, rr.Code, rr.Header().Get("Location"), tt.want)
		}
	}
}

// suspiciousCeiling is scan's suspicious_ceiling: 100x the hostile cutoff,
// never under L500, never past the grid. The table is scan's own
// (model/tests.rs suspicious_ceiling_scales_with_the_hostile_level).
func TestSuspiciousCeilingMatchesScan(t *testing.T) {
	for _, tt := range []struct{ budget, want int }{
		{0, 500},
		{1, 500},
		{5, 500},
		{10, 1000},
		{25, 2500},
		{70, 7000},
		{100, 10000},
		{250, 25000},
		{1000, 25000},
	} {
		if got := suspiciousCeiling(tt.budget); got != tt.want {
			t.Errorf("suspiciousCeiling(%d) = %d, want %d", tt.budget, got, tt.want)
		}
	}
}
